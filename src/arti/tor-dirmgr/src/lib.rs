//! Code to fetch, store, and update directory information.
//!
//! In its current design, Tor requires a set of up-to-date
//! authenticated directory documents in order to build multi-hop
//! anonymized circuits through the network.
//!
//! This directory manager crate is responsible for figuring out which
//! directory information we lack, downloading what we're missing, and
//! keeping a cache of it on disk.

// Code mostly copied from Arti.

#![deny(missing_docs)]
#![deny(clippy::await_holding_lock)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::rc_buffer)]

pub mod authority;
mod bootstrap;
mod config;
mod docid;
mod docmeta;
mod err;
mod retry;
mod shared_ref;
mod state;

use crate::docid::CacheUsage;
use crate::shared_ref::SharedMutArc;
use tor_netdir::NetDir;

use anyhow::{Context, Result};
use async_trait::async_trait;
use log::{info, warn};

use std::sync::Arc;
use std::time::SystemTime;

pub use authority::Authority;
pub use config::{DownloadScheduleConfig, NetDirConfig, NetDirConfigBuilder, NetworkConfig};
pub use docid::DocId;
pub use err::Error;

/// A directory manager to download, fetch, and cache a Tor directory.
///
/// A DirMgr can operate in three modes:
///   * In **offline** mode, it only reads from the cache, and can
///     only read once.
///   * In **read-only** mode, it reads from the cache, but checks
///     whether it can acquire an associated lock file.  If it can, then
///     it enters read-write mode.  If not, it checks the cache
///     periodically for new information.
///   * In **read-write** mode, it knows that no other process will be
///     writing to the cache, and it takes responsibility for fetching
///     data from the network and updating the directory with new
///     directory information.
///
/// # Limitations
///
/// Because of portability issues in [`fslock::LockFile`], you might
/// get weird results if you run two of these in the same process with
/// the same underlying cache.
pub struct DirMgr {
    /// Configuration information: where to find directories, how to
    /// validate them, and so on.
    config: NetDirConfig,

    /// Our latest sufficiently bootstrapped directory, if we have one.
    ///
    /// We use the RwLock so that we can give this out to a bunch of other
    /// users, and replace it once a new directory is bootstrapped.
    netdir: SharedMutArc<NetDir>,

}

impl DirMgr {
    /// Try to load the directory from disk, without launching any
    /// kind of update process.
    ///
    /// This function runs in **offline** mode: it will give an error
    /// if the result is not up-to-date, or not fully downloaded.
    ///
    /// In general, you shouldn't use this function in a long-running
    /// program; it's only suitable for command-line or batch tools.
    // TODO: I wish this function didn't have to be async or take a runtime.
    pub async fn load_once(config: NetDirConfig, docdir: &str) -> Result<Arc<NetDir>> {
        let dirmgr = Arc::new(Self::from_config(config)?); //, runtime, None)?);

        // TODO: add some way to return a directory that isn't up-to-date
        let _success = dirmgr.load_directory(&docdir).await?;

        dirmgr
            .opt_netdir()
            .ok_or_else(|| Error::DirectoryNotPresent.into())
    }

    /// Return a current netdir, either loading it or bootstrapping it
    /// as needed.
    ///
    /// Like load_once, but will try to bootstrap (or wait for another
    /// process to bootstrap) if we don't have an up-to-date
    /// bootstrapped directory.
    ///
    /// In general, you shouldn't use this function in a long-running
    /// program; it's only suitable for command-line or batch tools.
    pub async fn load_or_bootstrap_once(
        config: NetDirConfig,
        docdir: &str,
    ) -> Result<Arc<NetDir>> {
        let dirmgr = DirMgr::bootstrap_from_config(config, &docdir).await?; //, runtime, circmgr).await?;
        Ok(dirmgr.netdir())
    }

    /// Return a new directory manager from a given configuration,
    /// bootstrapping from the network as necessary.
    ///
    /// This function will to return until the directory is
    /// bootstrapped enough to build circuits.  It will also launch a
    /// background task that fetches any missing information, and that
    /// replaces the directory when a new one is available.
    pub async fn bootstrap_from_config(
        config: NetDirConfig,
        docdir: &str,
    ) -> Result<Arc<Self>> {
        let dirmgr = Arc::new(DirMgr::from_config(config)?); //, runtime.clone(), Some(circmgr))?);

        // Try to load from the cache.
        dirmgr
            .load_directory(&docdir)
            .await
            .context("Error loading cached directory")?;

        info!("We have enough information to build circuits.");

        Ok(dirmgr)
    }

    /// Construct a DirMgr from a NetDirConfig.
    fn from_config(
        config: NetDirConfig,
    ) -> Result<Self> {
        let netdir = SharedMutArc::new();
        Ok(DirMgr {
            config,
            netdir,
        })
    }

    /// Load the latest non-pending non-expired directory from the
    /// cache, if it is newer than the one we have.
    ///
    /// Return false if there is no such consensus.
    async fn load_directory(self: &Arc<Self>, docdir: &str) -> Result<bool> {
        let state = state::GetConsensusState::new(Arc::downgrade(self), CacheUsage::CacheOnly)?;
        let _ = bootstrap::load(Box::new(state), &docdir).await?;

        Ok(self.netdir.get().is_some())
    }

    /// Return an Arc handle to our latest directory, if we have one.
    ///
    /// This is a private method, since by the time anybody else has a
    /// handle to a DirMgr, the NetDir should definitely be
    /// bootstrapped.
    fn opt_netdir(&self) -> Option<Arc<NetDir>> {
        self.netdir.get()
    }

    /// Return an Arc handle to our latest directory, if we have one.
    // TODO: Add variants of this that make sure that it's up-to-date?
    pub fn netdir(&self) -> Arc<NetDir> {
        self.opt_netdir().expect("DirMgr was not bootstrapped!")
    }
}

/// A "state" object used to represent our progress in downloading a
/// directory.
///
/// These state objects are not meant to know about the network, or
/// how to fetch documents at all.  Instead, they keep track of what
/// information they are missing, and what to do when they get that
/// information.
///
/// Every state object has two possible transitions: "resetting", and
/// "advancing".  Advancing happens when a state has no more work to
/// do, and needs to transform into a different kind of object.
/// Resetting happens when this state needs to go back to an initial
/// state in order to start over -- either because of an error or
/// because the information it has downloaded is no longer timely.
#[async_trait]
trait DirState: Send {
    /// Return a human-readable description of this state.
    fn describe(&self) -> String;
    /// Return a list of the documents we're missing.
    ///
    /// If every document on this list were to be loaded or downloaded, then
    /// the state should either become "ready to advance", or "complete."
    ///
    /// This list should never _grow_ on a given state; only advancing
    /// or resetting the state should add new DocIds that weren't
    /// there before.
    fn missing_docs(&self) -> Vec<DocId>;
    /// Return true if this state can advance to another state via its
    /// `advance` method.
    fn can_advance(&self) -> bool;
    /// Add one or more documents from our cache; returns 'true' if there
    /// was any change in this state.
    fn add_from_cache(&mut self, docdir: &str) -> Result<bool>;

    /// If possible, advance to the next state.
    fn advance(self: Box<Self>) -> Result<Box<dyn DirState>>;
    /// Return a time (if any) when downloaders should stop attempting to
    /// advance this state, and should instead reset it and start over.
    fn reset_time(&self) -> Option<SystemTime>;
    /// Reset this state and start over.
    fn reset(self: Box<Self>) -> Result<Box<dyn DirState>>;
}
