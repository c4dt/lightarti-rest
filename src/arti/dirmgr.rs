//! Code to fetch, store, and update directory information.
//!
//! In its current design, Tor requires a set of up-to-date
//! authenticated directory documents in order to build multi-hop
//! anonymized circuits through the network.
//!
//! This directory manager crate is responsible for figuring out which
//! directory information we lack, downloading what we're missing, and
//! keeping a cache of it on disk.

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

use tor_dirmgr::docid::{CacheUsage};
use tor_dirmgr::shared_ref::SharedMutArc;
use tor_circmgr::CircMgr;
use tor_dirmgr::NetDirConfig;
use tor_dirmgr::Error;
use tor_netdir::NetDir;
use tor_rtcompat::Runtime;
use tor_dirmgr::{
    docmeta::ConsensusMeta, DocId, Readiness,
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use log::{info, warn};

use std::sync::Arc;
use std::sync::Weak;
use std::{fmt::Debug, time::SystemTime};

use chrono::{DateTime, Utc};
use rand::Rng;
use std::fs;
use std::collections::HashSet;
use std::time::Duration;
use tor_netdir::{MdReceiver, PartialNetDir};
use tor_netdoc::doc::netstatus::Lifetime;

use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::doc::{
    microdesc::{MdDigest, Microdesc},
    netstatus::MdConsensus,
};
use tor_netdoc::{
    doc::{
        authcert::{AuthCert, AuthCertKeyIds},
        microdesc::MicrodescReader,
        netstatus::{ConsensusFlavor, UnvalidatedMdConsensus},
    },
    AllowAnnotations,
};


///
static OUR_CERTIFICATES: [&str; 9] = include!("certificates.in");


/// An object where we can put a usable netdir.
///
/// Note that there's only one implementation for this trait: DirMgr.
/// We make this a trait anyway to make sure that the different states
/// in this module can _only_ interact with the DirMgr through
/// modifying the NetDir and looking at the configuration.
pub(crate) trait WriteNetDir: 'static + Sync + Send {
    /// Return a NetDirConfig to use when asked how to retry downloads,
    /// or when we need to find a list of descriptors.
    fn config(&self) -> &NetDirConfig;

    /// Return a reference where we can write or modify a NetDir.
    fn netdir(&self) -> &SharedMutArc<NetDir>;
}

impl<R: Runtime> WriteNetDir for DirMgr<R> {
    fn config(&self) -> &NetDirConfig {
        &self.config
    }
    fn netdir(&self) -> &SharedMutArc<NetDir> {
        &self.netdir
    }
}

/// Initial state: fetching or loading a consensus directory.
#[derive(Clone, Debug)]
pub(crate) struct GetConsensusState<DM: WriteNetDir> {
    /// How should we get the consensus from the cache, if at all?
    cache_usage: CacheUsage,

    /// If present, our next state.
    ///
    /// (This is present once we have a consensus.)
    next: Option<GetCertsState<DM>>,

    /// A list of RsaIdentity for the authorities that we believe in.
    ///
    /// No consensus can be valid unless it purports to be signed by
    /// more than half of these authorities.
    authority_ids: Vec<RsaIdentity>,

    /// A weak reference to the directory manager that wants us to
    /// fetch this information.  When this references goes away, we exit.
    writedir: Weak<DM>,
}

impl<DM: WriteNetDir> GetConsensusState<DM> {
    /// Create a new GetConsensusState from a weak reference to a
    /// directory manager and a `cache_usage` flag.
    pub(crate) fn new(writedir: Weak<DM>, cache_usage: CacheUsage) -> Result<Self> {
        let authority_ids: Vec<_> = if let Some(writedir) = Weak::upgrade(&writedir) {
            writedir
                .config()
                .authorities()
                .iter()
                .map(|auth| *auth.v3ident())
                .collect()
        } else {
            return Err(Error::ManagerDropped.into());
        };
        Ok(GetConsensusState {
            cache_usage,
            next: None,
            authority_ids,
            writedir,
        })
    }
}

#[async_trait]
impl<DM: WriteNetDir> DirState for GetConsensusState<DM> {
    fn describe(&self) -> String {
        if self.next.is_some() {
            "About to fetch certificates."
        } else {
            match self.cache_usage {
                CacheUsage::CacheOnly => "Looking for a cached consensus.",
                CacheUsage::CacheOkay => "Looking for a consensus.",
                CacheUsage::MustDownload => "Downloading a consensus.",
            }
        }
        .to_string()
    }
    fn missing_docs(&self) -> Vec<DocId> {
        if self.can_advance() {
            return Vec::new();
        }
        let flavor = ConsensusFlavor::Microdesc;
        vec![DocId::LatestConsensus {
            flavor,
            cache_usage: self.cache_usage,
        }]
    }
    fn is_ready(&self, _ready: Readiness) -> bool {
        false
    }
    fn can_advance(&self) -> bool {
        self.next.is_some()
    }
    fn add_from_cache(&mut self, docdir: &str) -> Result<bool> {
        // side-loaded data
        let consensus_path = format!("{}/consensus.txt", docdir);
        let consensus = fs::read_to_string(consensus_path)
            .expect("Failed to read the consensus.");
        self.add_consensus_text(true, consensus.as_str())
            .map(|meta| meta.is_some())
    }
    fn advance(self: Box<Self>) -> Result<Box<dyn DirState>> {
        Ok(match self.next {
            Some(next) => Box::new(next),
            None => self,
        })
    }
    fn reset_time(&self) -> Option<SystemTime> {
        None
    }
    fn reset(self: Box<Self>) -> Result<Box<dyn DirState>> {
        Ok(self)
    }
}

impl<DM: WriteNetDir> GetConsensusState<DM> {
    /// Helper: try to set the current consensus text from an input
    /// string `text`.  Refuse it if the authorities could never be
    /// correct, or if it is illformed.
    fn add_consensus_text(
        &mut self,
        from_cache: bool,
        text: &str,
    ) -> Result<Option<&ConsensusMeta>> {
        // Try to parse it and get its metadata.
        let (consensus_meta, unvalidated) = {
            let (signedval, remainder, parsed) = MdConsensus::parse(text)?;
            if let Ok(timely) = parsed.check_valid_now() {
                let meta = ConsensusMeta::from_unvalidated(signedval, remainder, &timely);
                (meta, timely)
            } else {
                return Ok(None);
            }
        };

        // Check out what authorities we believe in, and see if enough
        // of them are purported to have singed this consensus.
        let n_authorities = self.authority_ids.len() as u16;
        let unvalidated = unvalidated.set_n_authorities(n_authorities);

        let id_refs: Vec<_> = self.authority_ids.iter().collect();
        if !unvalidated.authorities_are_correct(&id_refs[..]) {
            return Err(Error::UnrecognizedAuthorities.into());
        }

        // Make a set of all the certificates we want -- the subset of
        // those listed on the consensus that we would indeed accept as
        // authoritative.
        let desired_certs = unvalidated
            .signing_cert_ids()
            .filter(|m| self.recognizes_authority(&m.id_fingerprint))
            .collect();

        self.next = Some(GetCertsState {
            cache_usage: self.cache_usage,
            from_cache,
            unvalidated,
            consensus_meta,
            missing_certs: desired_certs,
            certs: Vec::new(),
            writedir: Weak::clone(&self.writedir),
        });

        Ok(Some(&self.next.as_ref().unwrap().consensus_meta))
    }

    /// Return true if `id` is an authority identity we recognize
    fn recognizes_authority(&self, id: &RsaIdentity) -> bool {
        self.authority_ids.iter().any(|auth| auth == id)
    }
}

/// Second state: fetching or loading authority certificates.
///
/// TODO: we should probably do what C tor does, and try to use the
/// same directory that gave us the consensus.
///
/// TODO SECURITY: This needs better handling for the DOS attack where
/// we are given a bad consensus signed with fictional certificates
/// that we can never find.
#[derive(Clone, Debug)]
struct GetCertsState<DM: WriteNetDir> {
    /// The cache usage we had in mind when we began.  Used to reset.
    cache_usage: CacheUsage,
    /// True iff we loaded the consensus from our cache.
    from_cache: bool,
    /// The consensus that we are trying to validate.
    unvalidated: UnvalidatedMdConsensus,
    /// Metadata for the consensus.
    consensus_meta: ConsensusMeta,
    /// A set of the certificate keypairs for the certificates we don't
    /// have yet.
    missing_certs: HashSet<AuthCertKeyIds>,
    /// A list of the certificates we've been able to load or download.
    certs: Vec<AuthCert>,
    /// Reference to our directory manager.
    writedir: Weak<DM>,
}

#[async_trait]
impl<DM: WriteNetDir> DirState for GetCertsState<DM> {
    fn describe(&self) -> String {
        let total = self.certs.len() + self.missing_certs.len();
        format!(
            "Downloading certificates for consensus (we are missing {}/{}).",
            self.missing_certs.len(),
            total
        )
    }
    fn missing_docs(&self) -> Vec<DocId> {
        self.missing_certs
            .iter()
            .map(|id| DocId::AuthCert(*id))
            .collect()
    }
    fn is_ready(&self, _ready: Readiness) -> bool {
        false
    }
    fn can_advance(&self) -> bool {
        self.unvalidated.key_is_correct(&self.certs[..]).is_ok()
    }
    fn add_from_cache(&mut self, docdir: &str) -> Result<bool> {
        let mut changed = false;
        // static data for certificates
        for static_cert in OUR_CERTIFICATES.iter() {
            let parsed = AuthCert::parse(static_cert)?.check_signature()?;
            if let Ok(cert) = parsed.check_valid_now() {
                self.missing_certs.remove(cert.key_ids());
                self.certs.push(cert);
                changed = true;
            }
        }
        Ok(changed)
    }

    fn advance(self: Box<Self>) -> Result<Box<dyn DirState>> {
        if self.can_advance() {
            let validated = self.unvalidated.check_signature(&self.certs[..])?;
            Ok(Box::new(GetMicrodescsState::new(
                validated,
                self.consensus_meta,
                self.writedir,
            )?))
        } else {
            Ok(self)
        }
    }
    fn reset_time(&self) -> Option<SystemTime> {
        Some(self.consensus_meta.lifetime().valid_until())
    }
    fn reset(self: Box<Self>) -> Result<Box<dyn DirState>> {
        Ok(Box::new(GetConsensusState::new(
            self.writedir,
            self.cache_usage,
        )?))
    }
}

/// Final state: we're fetching or loading microdescriptors
#[derive(Debug, Clone)]
struct GetMicrodescsState<DM: WriteNetDir> {
    /// The digests of the microdesscriptors we are missing.
    missing: HashSet<MdDigest>,
    /// The dirmgr to inform about a usable directory.
    writedir: Weak<DM>,
    /// A NetDir that we are currently building, but which doesn't
    /// have enough microdescs yet.
    partial: Option<PartialNetDir>,
    /// Metadata for the current consensus.
    meta: ConsensusMeta,
    /// A pending list of microdescriptor digests whose
    /// "last-listed-at" times we should update.
    newly_listed: Vec<MdDigest>,
    /// A time after which we should try to replace this directory and
    /// find a new one.  Since this is randomized, we only compute it
    /// once.
    reset_time: SystemTime,
}

impl<DM: WriteNetDir> GetMicrodescsState<DM> {
    /// Create a new [`GetMicroDescsState`] from a provided
    /// microdescriptor consensus.
    fn new(consensus: MdConsensus, meta: ConsensusMeta, writedir: Weak<DM>) -> Result<Self> {
        let reset_time = consensus.lifetime().valid_until();

        let partial_dir = match Weak::upgrade(&writedir) {
            Some(wd) => {
                let params = wd.config().override_net_params();
                let mut dir = PartialNetDir::new(consensus, Some(params));
                if let Some(old_dir) = wd.netdir().get() {
                    dir.fill_from_previous_netdir(&old_dir);
                }
                dir
            }
            None => return Err(Error::ManagerDropped.into()),
        };

        let missing = partial_dir.missing_microdescs().map(Clone::clone).collect();
        let mut result = GetMicrodescsState {
            missing,
            writedir,
            partial: Some(partial_dir),
            meta,
            newly_listed: Vec::new(),
            reset_time,
        };

        result.consider_upgrade();
        Ok(result)
    }

    /// Add a bunch of microdescriptors to the in-progress netdir.
    ///
    /// Return true if the netdir has just become usable.
    fn register_microdescs<I>(&mut self, mds: I) -> bool
    where
        I: IntoIterator<Item = Microdesc>,
    {
        if let Some(p) = &mut self.partial {
            for md in mds {
                self.newly_listed.push(*md.digest());
                p.add_microdesc(md);
            }
            return self.consider_upgrade();
        } else if let Some(wd) = Weak::upgrade(&self.writedir) {
            let _ = wd.netdir().mutate(|nd| {
                for md in mds {
                    nd.add_microdesc(md);
                }
                Ok(())
            });
        }
        false
    }

    /// Check whether this netdir we're building has _just_ become
    /// usable when it was not previously usable.  If so, tell the
    /// dirmgr about it and return true; otherwise return false.
    fn consider_upgrade(&mut self) -> bool {
        if let Some(p) = self.partial.take() {
            match p.unwrap_if_sufficient() {
                Ok(netdir) => {
                    self.reset_time = pick_download_time(netdir.lifetime());
                    if let Some(wd) = Weak::upgrade(&self.writedir) {
                        wd.netdir().replace(netdir);
                        return true;
                    }
                }
                Err(partial) => self.partial = Some(partial),
            }
        }
        false
    }
}

#[async_trait]
impl<DM: WriteNetDir> DirState for GetMicrodescsState<DM> {
    fn describe(&self) -> String {
        format!(
            "Downloading microdescriptors (we are missing {}).",
            self.missing.len()
        )
    }
    fn missing_docs(&self) -> Vec<DocId> {
        self.missing.iter().map(|d| DocId::Microdesc(*d)).collect()
    }
    fn is_ready(&self, ready: Readiness) -> bool {
        match ready {
            Readiness::Complete => self.missing.is_empty(),
            Readiness::Usable => self.partial.is_none(),
        }
    }
    fn can_advance(&self) -> bool {
        false
    }
    fn add_from_cache(&mut self, docdir: &str) -> Result<bool> {
        // side-loaded data
        let microdescriptors_path = format!("{}/microdescriptors.txt", docdir);
        let microdescriptors = fs::read_to_string(microdescriptors_path)
            .expect("Failed to read microdescriptors.");

        let mut new_mds = Vec::new();
        for anno in MicrodescReader::new(microdescriptors.as_str(), AllowAnnotations::AnnotationsNotAllowed).flatten() {
            let md = anno.into_microdesc();
            self.missing.remove(md.digest());
            new_mds.push(md);
        }

        self.newly_listed.clear();
        self.register_microdescs(new_mds);

        Ok(true)
    }
    fn advance(self: Box<Self>) -> Result<Box<dyn DirState>> {
        Ok(self)
    }
    fn reset_time(&self) -> Option<SystemTime> {
        Some(self.reset_time)
    }
    fn reset(self: Box<Self>) -> Result<Box<dyn DirState>> {
        Ok(Box::new(GetConsensusState::new(
            self.writedir,
            CacheUsage::MustDownload,
        )?))
    }
}

/// Choose a random download time to replace a consensus whose lifetime
/// is `lifetime`.
fn pick_download_time(lifetime: &Lifetime) -> SystemTime {
    let (lowbound, uncertainty) = client_download_range(lifetime);
    let zero = Duration::new(0, 0);
    let t = lowbound + rand::thread_rng().gen_range(zero..uncertainty);
    info!("The current consensus is fresh until {}, and valid until {}. I've picked {} as the earliest time to replace it.",
          DateTime::<Utc>::from(lifetime.fresh_until()),
          DateTime::<Utc>::from(lifetime.valid_until()),
          DateTime::<Utc>::from(t));
    t
}

/// Based on the lifetime for a consensus, return the time range during which
/// clients should fetch the next one.
fn client_download_range(lt: &Lifetime) -> (SystemTime, Duration) {
    let valid_after = lt.valid_after();
    let fresh_until = lt.fresh_until();
    let valid_until = lt.valid_until();
    let voting_interval = fresh_until
        .duration_since(valid_after)
        .expect("valid-after must precede fresh-until");
    let whole_lifetime = valid_until
        .duration_since(valid_after)
        .expect("valid-after must precede valid-until");

    // From dir-spec:
    // "This time is chosen uniformly at random from the interval
    // between the time 3/4 into the first interval after the
    // consensus is no longer fresh, and 7/8 of the time remaining
    // after that before the consensus is invalid."
    let lowbound = voting_interval + (voting_interval * 3) / 4;
    let remainder = whole_lifetime - lowbound;
    let uncertainty = (remainder * 7) / 8;

    (valid_after + lowbound, uncertainty)
}

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
pub struct DirMgr<R: Runtime> {
    /// Configuration information: where to find directories, how to
    /// validate them, and so on.
    config: NetDirConfig,
    /// Our latest sufficiently bootstrapped directory, if we have one.
    ///
    /// We use the RwLock so that we can give this out to a bunch of other
    /// users, and replace it once a new directory is bootstrapped.
    netdir: SharedMutArc<NetDir>,

    /// A circuit manager, if this DirMgr supports downloading.
    circmgr: Option<Arc<CircMgr<R>>>,

    /// Our asynchronous runtime.
    runtime: R,
}

impl<R: Runtime> DirMgr<R> {
    /// Try to load the directory from disk, without launching any
    /// kind of update process.
    ///
    /// This function runs in **offline** mode: it will give an error
    /// if the result is not up-to-date, or not fully downloaded.
    ///
    /// In general, you shouldn't use this function in a long-running
    /// program; it's only suitable for command-line or batch tools.
    // TODO: I wish this function didn't have to be async or take a runtime.
    pub async fn load_once(runtime: R, config: NetDirConfig, docdir: &str) -> Result<Arc<NetDir>> {
        let dirmgr = Arc::new(Self::from_config(config, runtime, None)?);

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
        runtime: R,
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<NetDir>> {
        let dirmgr = DirMgr::bootstrap_from_config(config, &docdir, runtime, circmgr).await?;
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
        runtime: R,
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<Self>> {
        let dirmgr = Arc::new(DirMgr::from_config(config, runtime.clone(), Some(circmgr))?);

        // Try to load from the cache.
        dirmgr
            .load_directory(&docdir)
            .await
            .context("Error loading cached directory")?;

        info!("We have enough information to build circuits.");

        Ok(dirmgr)
    }

    /// Get a reference to the circuit manager, if we have one.
    fn circmgr(&self) -> Result<Arc<CircMgr<R>>> {
        self.circmgr
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| Error::NoDownloadSupport.into())
    }

    /// Construct a DirMgr from a NetDirConfig.
    fn from_config(
        config: NetDirConfig,
        runtime: R,
        circmgr: Option<Arc<CircMgr<R>>>,
    ) -> Result<Self> {
        let netdir = SharedMutArc::new();
        Ok(DirMgr {
            config,
            netdir,
            circmgr,
            runtime,
        })
    }

    /// Load the latest non-pending non-expired directory from the
    /// cache, if it is newer than the one we have.
    ///
    /// Return false if there is no such consensus.
    async fn load_directory(self: &Arc<Self>, docdir: &str) -> Result<bool> {
        //let store = &self.store;

        let state = GetConsensusState::new(Arc::downgrade(self), CacheUsage::CacheOnly)?;
        let _ = load(Arc::clone(self), Box::new(state), &docdir).await?;

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


/// Try tp update `state` by loading cached information from `dirmgr`.
/// Return true if anything changed.
async fn load_once<R: Runtime>(
    dirmgr: &Arc<DirMgr<R>>,
    state: &mut Box<dyn DirState>,
    docdir: &str
) -> Result<bool> {
    let missing = state.missing_docs();
    if missing.is_empty() {
        Ok(false)
    } else {
        state.add_from_cache(&docdir)
    }
}

/// Try to load as much state as possible for a provided `state` from the
/// cache in `dirmgr`, advancing the state to the extent possible.
///
/// No downloads are performed; the provided state will not be reset.
pub(crate) async fn load<R: Runtime>(
    dirmgr: Arc<DirMgr<R>>,
    mut state: Box<dyn DirState>,
    docdir: &str
) -> Result<Box<dyn DirState>> {
    let mut safety_counter = 0_usize;
    loop {
        let changed = load_once(&dirmgr, &mut state, &docdir).await?;

        if state.can_advance() {
            state = state.advance()?;
            safety_counter = 0;
        } else {
            if !changed {
                break;
            }
            safety_counter += 1;
            if safety_counter == 100 {
                panic!("Spent 100 iterations in the same state: this is a bug");
            }
        }
    }

    Ok(state)
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
    /// Describe whether this state has reached `ready` status.
    fn is_ready(&self, ready: Readiness) -> bool;
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

/// Try to upgrade a weak reference to a DirMgr, and give an error on
/// failure.
fn upgrade_weak_ref<T>(weak: &Weak<T>) -> Result<Arc<T>> {
    Weak::upgrade(weak).ok_or_else(|| Error::ManagerDropped.into())
}
