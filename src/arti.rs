use std::{path::Path, sync::Arc};

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{rustls::ClientConfig, webpki::DNSNameRef, TlsConnector};
use tor_rtcompat::{Runtime, SpawnBlocking};
use tracing::{debug, info, trace};

use crate::arti::client::TorClient;

mod client;
mod conv;

/// Some structures that were defined in the arti main source and that I took over
/// without thinking...

const ARTI_DEFAULTS: &str = concat!(
    include_str!("./arti_defaults.toml"),
    include_str!("./authorities.toml"),
);

/// This connection sends a generic request over TLS to the host.
/// It returns the result from the request, or an error.
pub fn tls_send(host: &str, request: &str, cache: &Path) -> Result<String> {
    info!("Starting TorClient");
    let dflt_config = tor_config::default_config_file();
    let mut cfg = config::Config::new();
    cfg.merge(config::File::from_str(
        ARTI_DEFAULTS,
        config::FileFormat::Toml,
    ))
    .context("merge config")?;

    debug!("Load config");
    let empty: Vec<String> = vec![];
    tor_config::load(&mut cfg, dflt_config, &empty, &empty).context("load config")?;

    let runtime = tor_rtcompat::create_runtime().context("create tor runtime")?;
    runtime.block_on(async {
        let mut dircfg = tor_dirmgr::NetDirConfigBuilder::new();
        dircfg.set_cache_path(cache);

        let tor_client = TorClient::bootstrap(
            runtime.clone(),
            dircfg.finalize().context("netdir finalize")?,
            cache.to_str().context("cache as string")?,
        )
        .await
        .context("bootstrap tor client")?;

        send_request(tor_client, host, request).await
    })
}

/// Sends a GET request over a TLS connection and returns the result.
async fn send_request(tor: TorClient<impl Runtime>, host: &str, request: &str) -> Result<String> {
    // Configure a TLS client to connect to endpoint
    let mut config = ClientConfig::new();
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let config = TlsConnector::from(Arc::new(config));
    let dnsname = DNSNameRef::try_from_ascii_str(host).context("read host as valid DNS")?;

    debug!("Connecting to the tls stream");
    for t in 0..2u32 {
        debug!("Trying to connect: {}", t);
        let stream: conv::TorStream = tor
            .connect(host, 443, None)
            .await
            .context("tor connect")?
            .into();
        let mut tls_stream = config
            .connect(dnsname, stream)
            .await
            .context("tls connect")?;
        tls_stream
            .write_all(request.as_ref())
            .await
            .context("write request")?;
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

#[cfg(test)]
mod tests {
    use crate::tests;

    use super::*;

    #[test]
    fn clearnet_and_tor_gives_the_same_page() {
        tests::setup_tracing();
        let docdir = tests::setup_cache();

        tls_send(
            "www.c4dt.org",
            "GET /index.html HTTP/1.0\nHost: www.c4dt.org\n\n",
            docdir.path(),
        )
        .expect("get page via tor");
    }
}
