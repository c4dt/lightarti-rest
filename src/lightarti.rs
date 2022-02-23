use std::{fs, path::Path};

use anyhow::{anyhow, Context, Result};
use arti_client::{DPConstructor, TorClient, TorClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_native_tls::{native_tls, TlsConnector};
use tor_config::CfgPath;
use tor_rtcompat::{BlockOn, Runtime};
use tracing::{debug, trace};

mod flatfiledirmgr;

fn build_config(cache_path: &Path) -> Result<TorClientConfig> {
    let mut cfg_builder = TorClientConfig::builder();
    cfg_builder
        .storage()
        .cache_dir(CfgPath::from_path(cache_path));

    let auth_path = cache_path.join("authority.json");
    let auth_raw = fs::read_to_string(auth_path).context("Failed to read authority")?;
    let auth = serde_json::from_str(auth_raw.as_str())?;

    cfg_builder.tor_network().authorities(vec![auth]);
    // Overriding authorities requires also overriding fallback caches
    cfg_builder.tor_network().fallback_caches(Vec::new());

    cfg_builder.build().map_err(anyhow::Error::new)
}

/// This connection sends a generic request over TLS to the host.
/// It returns the result from the request, or an error.
pub fn tls_send(host: &str, request: &str, cache: &Path) -> Result<String> {
    let cfg = build_config(cache).context("load config")?;
    let runtime = tor_rtcompat::tokio::PreferredRuntime::create().context("create runtime")?;

    runtime.clone().block_on(async {
        let tor_client = TorClient::builder(runtime)
            .config(cfg)
            .dp_constructor(&DPConstructor(&|cfg, _runtime, circmgr| {
                let dm = flatfiledirmgr::FlatFileDirMgr::from_config(cfg, circmgr)?;
                Ok(dm)
            }))
            .create_bootstrapped()
            .await?;
        send_request(&tor_client, host, request).await
    })
}

/// Tries several times to send a request; if still unsuccessful, returns an error
async fn send_request(tor: &TorClient<impl Runtime>, host: &str, request: &str) -> Result<String> {
    debug!(host, "send request");

    for retry in 0..5u32 {
        debug!("Connection-try {}", retry);
        match send_request_attempt(tor, host, request).await {
            Err(error) => debug!("Error: {}", error),
            v => return v,
        }
    }

    Err(anyhow!("Couldn't get response"))
}

/// Sends a request over a TLS connection and returns the result.
async fn send_request_attempt(
    tor: &TorClient<impl Runtime>,
    host: &str,
    request: &str,
) -> Result<String> {
    let stream = tor.connect((host, 443)).await.context("tor connect")?;

    let mut tls_stream =
        TlsConnector::from(native_tls::TlsConnector::new().context("create tls connector")?)
            .connect(host, stream)
            .await
            .context("tls connect")?;

    tls_stream
        .write_all(request.as_ref())
        .await
        .context("write request")?;
    tls_stream.flush().await.context("stream flush")?;

    let mut res = Vec::default();
    tls_stream
        .read_to_end(&mut res)
        .await
        .context("read response")?;

    let result = String::from_utf8_lossy(&res).to_string();

    debug!("Received {} bytes from stream", result.len());
    trace!("Received stream: {}", result);

    Ok(result)
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
            "www.example.com",
            "GET /index.html HTTP/1.0\nHost: www.example.com\n\n",
            docdir.path(),
        )
        .expect("get page via tor");
    }
}
