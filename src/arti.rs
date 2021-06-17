use std::sync::Arc;

use crate::DirectoryCache;
/// This is a simple wrapper around arti to offer a synchronous
/// REST interface to mobile libraries.
use anyhow::{anyhow, Result};
use tracing::{debug, info, trace};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{rustls::ClientConfig, webpki::DNSNameRef, TlsConnector};
use tor_client::TorClient;
use tor_config::CfgPath;
use tor_dirmgr::{DownloadScheduleConfig, NetDirConfig, NetworkConfig};
use tor_rtcompat::{Runtime, SpawnBlocking};

mod conv;

/// Some structures that were defined in the arti main source and that I took over
/// without thinking...

const ARTI_DEFAULTS: &str = concat!(
include_str!("./arti_defaults.toml"),
include_str!("./authorities.toml"),
);

/// This connection sends a generic request over TLS to the host.
/// It returns the result from the request, or an error.
pub fn tls_send(host: &str, request: &str, dir_cache: &DirectoryCache) -> Result<String> {
    info!("Starting TorClient");
    let dflt_config = tor_config::default_config_file();
    let mut cfg = config::Config::new();
    cfg.merge(config::File::from_str(
        ARTI_DEFAULTS,
        config::FileFormat::Toml,
    ))?;

    debug!("Load config");
    let empty: Vec<String> = vec![];
    tor_config::load(&mut cfg, dflt_config, &empty, &empty)?;
    let config: ArtiConfig = cfg.try_into()?;

    let runtime = tor_rtcompat::create_runtime()?;
    runtime.block_on(
        async {
            debug!("Getting tor connection");
            let cc = dir_cache.tmp_dir.as_ref().map(|s| &**s);
            let tor = get_tor(runtime.clone(), config, cc).await?;

            debug!("Setting up tls connection and sending GET");
            get_result(tor, host, request).await
        })
}

/// Sends a GET request over a TLS connection and returns the result.
async fn get_result(tor: TorClient<impl Runtime>, host: &str, request: &str) -> Result<String> {
    // Configure a TLS client to connect to endpoint
    let mut config = ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let config = TlsConnector::from(Arc::new(config));
    let dnsname = DNSNameRef::try_from_ascii_str(host).unwrap();

    debug!("Connecting to the tls stream");
    for t in 0..2u32 {
        debug!("Trying to connect: {}", t);
        let stream: conv::TorStream = tor.connect(host, 443, None).await?.into();
        let mut tls_stream = config.connect(dnsname, stream).await?;
        tls_stream
            .write_all(request.as_ref())
            .await
            .unwrap();
        let mut res = vec![];

        if let Ok(_) = tls_stream.read_to_end(&mut res).await {
            let result = String::from_utf8_lossy(&res).to_string();

            debug!("Received {} bytes from stream", result.len());
            trace!("Received stream: {}", result);
            return Ok(result);
        }
        info!("Trying again");
    }

    Err(anyhow!("Couldn't get response"))
}

// On iOS, the get_dir_config works as supposed, so no need to do special treatment.
#[cfg(not(target_os = "android"))]
async fn get_tor<T: Runtime>(runtime: T, config: ArtiConfig, _cache_dir: Option<&str>) -> Result<TorClient<T>> {
    let dircfg = config.get_dir_config()?;
    TorClient::bootstrap(runtime.clone(), dircfg).await
}

// For Android, the cache path needs to be set, so the whole config needs to be initialized.
// This could of course be cleaned up...
#[cfg(target_os = "android")]
async fn get_tor<T: Runtime>(runtime: T, config: ArtiConfig, cache_dir: Option<&str>) -> Result<TorClient<T>> {
    use std::path::Path;

    debug!("New dircfg");
    let mut dircfg = tor_dirmgr::NetDirConfigBuilder::new();

    debug!("Clone network config");
    let network_clone = config.network.clone();

    debug!("Set network config");
    dircfg.set_network_config(network_clone);

    debug!("Set timing config");
    dircfg.set_timing_config(config.download_schedule.clone());

    debug!("Retrieve cache path");
    let cache_path = Path::new(cache_dir.unwrap());

    debug!("Set cache path");
    dircfg.set_cache_path(&cache_path);

    let netdircfg = dircfg.finalize().expect("Failed to build netdircfg.");

    debug!("Connect to tor");
    TorClient::bootstrap(runtime, netdircfg).await
}

/// Configuration for where information should be stored on disk.
///
/// This section is for read/write storage
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Location on disk for cached directory information
    cache_dir: CfgPath,
    /// Location on disk for less-sensitive persistent state information.
    #[allow(unused)]
    state_dir: CfgPath,
}


/// Structure to hold our configuration options, whether from a
/// configuration file or the command line.
///
/// NOTE: These are NOT the final options or their final layout.
/// Expect NO stability here.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ArtiConfig {
    /// Port to listen on (at localhost) for incoming SOCKS
    /// connections.
    socks_port: Option<u16>,
    /// Whether to log at trace level.
    trace: bool,

    /// Information about the Tor network we want to connect to.
    network: NetworkConfig,

    /// Directories for storing information on disk
    storage: StorageConfig,

    /// Information about when and how often to download directory information
    download_schedule: DownloadScheduleConfig,
}

impl ArtiConfig {
    fn get_dir_config(&self) -> Result<NetDirConfig> {
        let mut dircfg = tor_dirmgr::NetDirConfigBuilder::new();
        dircfg.set_network_config(self.network.clone());
        dircfg.set_timing_config(self.download_schedule.clone());
        dircfg.set_cache_path(&self.storage.cache_dir.path()?);
        dircfg.finalize()
    }
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;

    use crate::tests;

    use super::*;

    #[test]
    fn clearnet_and_tor_gives_the_same_page() {
        tests::setup_tracing();

        let tempdir = TempDir::new("tor-cache").expect("create temp dir");

        tls_send(
            "www.c4dt.org",
            "GET /index.html HTTP/1.0\nHost: www.c4dt.org\n\n",
            &DirectoryCache {
                tmp_dir: tempdir.path().to_str().map(String::from),
                nodes: None,
                relays: None,
            },
        )
        .expect("get page via tor");
    }
}
