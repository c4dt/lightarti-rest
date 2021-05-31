#[cfg(target_os = "ios")]
mod ffi_ios;
#[cfg(target_os = "android")]
mod ffi_android;

// Core functionality goes here (or any other Rust file).
// This demo is only about FFI, so empty.
// Possible structures:
// - For simple calculations or services: functions.
// - For more complex scenarios: e.g. function that bootstraps a dependency graph,
//   stored in a static variable. the FFI/JNI functions call the dependency graph's functions.
use std::{path::Path};

use serde::Deserialize;
use log::{info};
use anyhow::{Result};

use tor_client::TorClient;
use tor_config::CfgPath;
use tor_dirmgr::{DownloadScheduleConfig, NetDirConfig, NetworkConfig};
use tor_rtcompat::SpawnBlocking;
use tokio_rustls::{ TlsConnector, rustls::ClientConfig };
use tokio_rustls::webpki::DNSNameRef;
use std::sync::Arc;

mod conv;

/// Use the tor_rtcompat tokio runtime to access the block_on method.
fn blocking_google_ch(cache_dir: &str) -> Result<String>{
    tor_rtcompat::create_runtime()?.block_on(
        connect_google_ch(cache_dir)
    )
}

/// Some structures that were defined in the arti main source and that I took over
/// without thinking...

const ARTI_DEFAULTS: &str = concat!(
    include_str!("./arti_defaults.toml"),
    include_str!("./authorities.toml"),
);

/// This is the clobbered together main function, mainly from
///   arti/arti/src/main.rs
///   arti/tor-client/src/client.rs
/// It connects to google.ch over port 80 to test that it can get back some text.
async fn connect_google_ch(cache_dir: &str) -> Result<String> {
    info!("Starting TorClient");

    info!("Default tor config");
    let dflt_config = tor_config::default_config_file();

    let mut cfg = config::Config::new();

    info!("Merge config");
    cfg.merge(config::File::from_str(
        ARTI_DEFAULTS,
        config::FileFormat::Toml,
    ))?;


    let args = Args{ rc: vec![], cfg: vec![] };

    info!("Load config");
    tor_config::load(&mut cfg, dflt_config, &args.rc, &args.cfg)?;


    info!("Attempt try_into config");
    let config: ArtiConfig = cfg.try_into()?;

    info!("New dircfg");
    let mut dircfg = tor_dirmgr::NetDirConfigBuilder::new();

    info!("Clone network config");
    let network_clone = config.network.clone();

    info!("Set network config");
    dircfg.set_network_config(network_clone);

    info!("Set timing config");
    dircfg.set_timing_config(config.download_schedule.clone());

    info!("Retrieve cache path");
    let cache_path = Path::new(cache_dir);

    info!("Set cache path");
    dircfg.set_cache_path(&cache_path);

    let netdircfg = dircfg.finalize().expect("Failed to build netdircfg.");

    //info!("Getting dircfg");
    //let dircfg = config.get_dir_config()?;

    info!("Create runtime");
    let runtime = tor_rtcompat::create_runtime()?;

    info!("Connect to tor, getting google.ch");
    let tor = TorClient::bootstrap(runtime.clone(), netdircfg).await?;

    // let stream = tor.connect("rainmaker.wunderground.com", 23, None).await?;
    info!("Connect to google.ch");
    let stream = tor.connect("google.ch", 443, None).await?;

    if false {
        use futures::{AsyncReadExt, AsyncWriteExt};

        info!("Splitting and sending");
        let (mut r, mut w) = stream.split();

        w.write_all(&"Get /\n\n".as_bytes()).await?;
        w.flush().await?;

        let mut inbuf = [0_u8; 128];
        let read = r
            .read(&mut inbuf[..])
            .await?;
        info!("Read {} chars:", read);
        let ret = std::str::from_utf8(&inbuf)?;
        info!("{}", ret);

        Ok(ret.to_string())
    } else {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let stream: conv::TorStream = stream.into();

        let mut config = ClientConfig::new();
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let config = TlsConnector::from(Arc::new(config));
        let dnsname = DNSNameRef::try_from_ascii_str("google.ch").unwrap();

        let mut tls_stream = config.connect(dnsname, stream).await?;

        tls_stream
            .write_all(b"GET / HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let mut res = vec![];
        tls_stream.read_to_end(&mut res).await.unwrap();
        // println!("{}", String::from_utf8_lossy(&res));
        Ok(String::from_utf8_lossy(&res).to_string())
    }
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


#[derive(Debug, Clone)]
/// Make a connection to the Tor network, open a SOCKS port, and proxy
/// traffic.
///
/// This is a demo; you get no stability guarantee.
struct Args {
    /// override the default location(s) for the configuration file
    rc: Vec<String>,
    /// override a configuration option (uses toml syntax)
    cfg: Vec<String>,
}

#[tokio::test]
async fn clearnet_and_tor_gives_the_same_page() {
    connect_google_ch("/tmp/tor-cache")
        .await
        .expect("get page via tor");
}
