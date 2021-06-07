use std::sync::Arc;

/// This is a simple wrapper around arti to offer a synchronous
/// REST interface to mobile libraries.
/// In the current version, only a GET to the root of a domain is supported.

use anyhow::Result;
use log::{debug, info, LevelFilter, trace};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{rustls::ClientConfig, TlsConnector, webpki::DNSNameRef};
use tor_client::TorClient;
use tor_config::CfgPath;
use tor_dirmgr::{DownloadScheduleConfig, NetDirConfig, NetworkConfig};
use tor_rtcompat::{Runtime, SpawnBlocking};

/// This is a simple wrapper around arti to offer a synchronous
/// REST interface to mobile libraries.
/// In the current version, only a GET to the root of a domain is supported.

/// Just do nothing for the moment

mod conv;

/// Some structures that were defined in the arti main source and that I took over
/// without thinking...

const ARTI_DEFAULTS: &str = concat!(
include_str!("./arti_defaults.toml"),
include_str!("./authorities.toml"),
);

/// This connection sends a GET request over TLS to the domain.
/// It returns the result from the request, or an error.
pub fn tls_get(domain: &str, cache_dir: Option<&str>) -> Result<String> {
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
            let tor = get_tor(runtime.clone(), config, cache_dir).await?;

            debug!("Setting up tls connection and sending GET");
            get_result(tor, domain).await
        })
}

/// Sends a GET request over a TLS connection and returns the result.
async fn get_result(tor: TorClient<impl Runtime>, domain: &str) -> Result<String> {
    let stream: conv::TorStream = tor.connect(domain, 443, None).await?.into();

    // Configure a TLS client to connect to endpoint
    let mut config = ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let config = TlsConnector::from(Arc::new(config));
    let dnsname = DNSNameRef::try_from_ascii_str(domain).unwrap();

    debug!("Connecting to the tls stream");
    let mut tls_stream = config.connect(dnsname, stream).await?;
    tls_stream
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .await
        .unwrap();
    let mut res = vec![];
    tls_stream.read_to_end(&mut res).await.unwrap();
    let result = String::from_utf8_lossy(&res).to_string();

    debug!("Received {} bytes from stream", result.len());
    trace!("Received stream: {}", result);
    Ok(result)
}

// On iOS, the get_dir_config works as supposed, so no need to do special treatment.
#[cfg(not(target_os = "ios"))]
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

    //debug!("Getting dircfg");
    //let dircfg = config.get_dir_config()?;

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

#[tokio::test]
async fn clearnet_and_tor_gives_the_same_page() {
    tls_get("c4dt.org", Some("/tmp/tor-cache"))
        .expect("get page via tor");
}
