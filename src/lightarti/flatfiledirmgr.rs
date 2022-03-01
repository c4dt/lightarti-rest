//! Simple flat-file implementation of the DirProvider trait.
//! Used for 'lightarti'.

use arti_client::builder::DirProviderBuilder;
use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
use tor_circmgr::CircMgr;
use tor_dirmgr::config::DirMgrConfig;
use tor_dirmgr::err::Error;
use tor_dirmgr::event::DirEvent;
use tor_dirmgr::shared_ref::SharedMutArc;
use tor_dirmgr::{DirBootstrapStatus, DirProvider, Result};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdir::MdReceiver;
use tor_netdir::{NetDir, PartialNetDir};
use tor_netdoc::doc::authcert::AuthCert;
use tor_netdoc::doc::microdesc::{Microdesc, MicrodescReader};
use tor_netdoc::doc::netstatus::{
    MdConsensus, MdConsensusRouterStatus, RouterStatus, UnvalidatedConsensus,
};
use tor_netdoc::AllowAnnotations;
use tor_rtcompat::Runtime;

use async_trait::async_trait;
use futures::stream::BoxStream;
use postage::{broadcast, sink::Sink, watch};
use tracing::{debug, info, warn};

use rand::seq::SliceRandom;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// 1/CHURN_FRACTION is the threshold of the consensus relays that we can remove with the churn
const CHURN_FRACTION: usize = 6;

/// A directory manager that loads the directory information from flat files read from the cache
/// directory.
pub struct FlatFileDirMgr<R: Runtime> {
    /// Configuration information: where to find directories, how to
    /// validate them, and so on.
    config: tor_config::MutCfg<DirMgrConfig>,

    /// The directory as read from the files in the cache directory.
    netdir: SharedMutArc<NetDir>,

    /// A sender handle that we notify whenever the consensus changes.
    tx_events: broadcast::Sender<DirEvent>,

    /// A receiver handle that gets notified whenever our bootstrapping status changes.
    ///
    /// Unused for now.
    bootstrap_rx_events: watch::Receiver<DirBootstrapStatus>,

    /// A circuit manager.
    circmgr: Option<Arc<CircMgr<R>>>,
}

impl<R: Runtime> FlatFileDirMgr<R> {
    /// Create a new FlatFileDirMgr from a given configuration.
    pub fn from_config(config: DirMgrConfig, circmgr: Arc<CircMgr<R>>) -> Result<Arc<Self>> {
        let netdir = SharedMutArc::new();
        let (tx_events, _) = broadcast::channel(1);
        let (_, bootstrap_rx_events) = watch::channel();
        let circmgr = Some(circmgr);

        Ok(Arc::new(FlatFileDirMgr {
            config: config.into(),
            netdir,
            tx_events,
            bootstrap_rx_events,
            circmgr,
        }))
    }

    /// Try to load the directory from flat files.
    ///
    /// This is strongly inspired by the add_from_cache() methods from the various states in
    /// DirMgr, combined and simplified to directly use the data from the loaded files.
    pub async fn load_directory(&self) -> Result<bool> {
        let config = self.config.get();
        let cache_path = config.cache_path();

        // Consensus
        let unvalidated = self.load_consensus(cache_path)?;

        let authority_ids: Vec<RsaIdentity> = config
            .authorities()
            .iter()
            .map(|auth| *auth.v3ident())
            .collect();

        // Check out what authorities we believe in, and see if enough
        // of them are purported to have signed this consensus.
        let n_authorities = authority_ids.len() as u16;
        let unvalidated = unvalidated.set_n_authorities(n_authorities);

        let id_refs: Vec<_> = authority_ids.iter().collect();
        if !unvalidated.authorities_are_correct(&id_refs[..]) {
            return Err(Error::UnrecognizedAuthorities);
        }

        // Certificate
        let certificate = self.load_certificate(cache_path)?;
        let consensus = unvalidated
            .check_signature(&[certificate])
            .map_err(|_| Error::CacheCorruption("Failed to validate consensus signature"))?;

        // Microdescriptors
        let udesc = self.load_microdesc(cache_path)?;

        // Build directory
        let params = config.override_net_params();
        let mut partial = PartialNetDir::new(consensus, Some(params));

        for md in udesc {
            partial.add_microdesc(md);
        }

        if let Ok(netdir) = partial.unwrap_if_sufficient() {
            if match &self.circmgr {
                Some(circmgr) => circmgr.netdir_is_sufficient(&netdir),
                None => true,
            } {
                self.netdir.replace(netdir);
            } else {
                warn!("circmgr says netdir is not sufficient");
            }
        }

        Ok(match self.netdir.get() {
            Some(_) => {
                let mut tx = self.tx_events.clone();

                tx.send(DirEvent::NewConsensus)
                    .await
                    .map_err(|_| Error::DirectoryNotPresent)?;
                tx.send(DirEvent::NewDescriptors)
                    .await
                    .map_err(|_| Error::DirectoryNotPresent)?;

                true
            }
            None => false,
        })
    }

    /// Load the consensus from a flat file.
    fn load_consensus(
        &self,
        cache_path: &Path,
    ) -> Result<UnvalidatedConsensus<MdConsensusRouterStatus>> {
        let path = cache_path.join("consensus.txt");
        let consensus_text = fs::read_to_string(path)?;
        debug!("consensus.txt loaded");

        let path = cache_path.join("churn.txt");
        let churn_text = fs::read_to_string(path).unwrap_or_else(|_| "".to_string());
        debug!("churn.txt loaded");

        let (_, _, parsed) = MdConsensus::parse(&consensus_text)
            .map_err(|_| Error::CacheCorruption("Failed to parse consensus"))?;
        let mut unvalidated = parsed
            .check_valid_now()
            .map_err(|_| Error::BadNetworkConfig("The consensus file is no longer valid"))?;

        let churn = parse_churn(&churn_text)?;

        // If the churn is above a threshold, we only consider a random subset
        // of the churned routers.
        let churn_threshold = unvalidated.n_relays() / CHURN_FRACTION;
        let churn_set: HashSet<&RsaIdentity> = if churn.len() > churn_threshold {
            warn!("Churn larger than threshold limit!");
            let number_to_remove = churn.len() - churn_threshold;

            churn
                .choose_multiple(&mut rand::thread_rng(), churn.len() - number_to_remove)
                .collect()
        } else {
            churn.iter().collect()
        };

        // We remove the churned routers from the consensus.
        if churn_set.is_empty() {
            debug!("All router(s) in custom consensus are still valid.");
        } else {
            debug!(
                "Removing {} router(s) from custom consensus as their info is no longer valid.",
                churn_set.len()
            );
            unvalidated
                .modify_relays(|relays| relays.retain(|r| !churn_set.contains(r.rsa_identity())));
        }

        Ok(unvalidated)
    }

    /// Load the certificate from a flat file.
    fn load_certificate(&self, cache_path: &Path) -> Result<AuthCert> {
        let path = cache_path.join("certificate.txt");
        let certificate = fs::read_to_string(path)?;
        debug!("certificate.txt loaded");

        let parsed = AuthCert::parse(certificate.as_str())
            .map_err(|_| Error::CacheCorruption("Failed to parse certificate"))?
            .check_signature()?;
        let cert = parsed
            .check_valid_now()
            .map_err(|_| Error::BadNetworkConfig("The certificate file is no longer valid"))?;

        Ok(cert)
    }

    /// Load the list of microdescriptors from a flat file.
    fn load_microdesc(&self, cache_path: &Path) -> Result<Vec<Microdesc>> {
        let path = cache_path.join("microdescriptors.txt");
        let udesc_text = fs::read_to_string(path)?;
        debug!("microdescriptors.txt loaded");

        let udesc = MicrodescReader::new(
            udesc_text.as_str(),
            &AllowAnnotations::AnnotationsNotAllowed,
        )
        .flatten()
        .map(|anno| anno.into_microdesc())
        .collect::<Vec<Microdesc>>();

        Ok(udesc)
    }

    /// Return an Arc handle to our latest directory, if we have one.
    fn opt_netdir(&self) -> Option<Arc<NetDir>> {
        self.netdir.get()
    }

    /// Return a stream of [`DirBootstrapStatus`] events to tell us about changes in the latest
    /// directory's bootstrap status.
    fn bootstrap_events(&self) -> watch::Receiver<DirBootstrapStatus> {
        self.bootstrap_rx_events.clone()
    }
}

/// Parse churned routers info.
fn parse_churn(text: &str) -> Result<Vec<RsaIdentity>> {
    let churn: Vec<RsaIdentity> = text
        .lines()
        .collect::<Vec<&str>>()
        .iter()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let bytes = hex::decode(line).map_err(Error::BadHexInCache)?;
            RsaIdentity::from_bytes(&bytes).ok_or(Error::CacheCorruption("invalid RSA identity"))
        })
        .collect::<Result<_>>()?;
    Ok(churn)
}

#[async_trait]
impl<R: Runtime> DirProvider for FlatFileDirMgr<R> {
    fn latest_netdir(&self) -> Option<Arc<NetDir>> {
        self.opt_netdir()
    }

    fn events(&self) -> BoxStream<'static, DirEvent> {
        Box::pin(self.tx_events.subscribe())
    }

    fn reconfigure(
        &self,
        _new_config: &DirMgrConfig,
        _how: tor_config::Reconfigure,
    ) -> std::result::Result<(), tor_config::ReconfigureError> {
        // Not implemented
        Err(tor_config::ReconfigureError::CannotChange {
            field: "all".to_string(),
        })
    }

    async fn bootstrap(&self) -> Result<()> {
        let loaded = self.load_directory().await?;
        info!("Valid directory loaded from files: {}", loaded);
        Ok(())
    }

    fn bootstrap_events(&self) -> BoxStream<'static, DirBootstrapStatus> {
        Box::pin(self.bootstrap_events())
    }
}

pub struct FlatFileDirMgrBuilder {}

impl<R: Runtime> DirProviderBuilder<R> for FlatFileDirMgrBuilder {
    fn build(
        &self,
        _runtime: R,
        circmgr: Arc<tor_circmgr::CircMgr<R>>,
        config: DirMgrConfig,
    ) -> arti_client::Result<Arc<dyn tor_dirmgr::DirProvider + Send + Sync + 'static>> {
        let dm =
            FlatFileDirMgr::from_config(config, circmgr).map_err(arti_client::ErrorDetail::from)?;
        Ok(dm)
    }
}
