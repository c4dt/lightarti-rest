use std::{fs, path::Path};

use anyhow::{Context, Result};
use arti_client::{TorClient, TorClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_native_tls::{native_tls, TlsConnector};
use tor_config::CfgPath;
use tor_rtcompat::Runtime;
use tracing::trace;

pub(super) mod flatfiledirmgr;

pub(super) fn build_config(cache_path: &Path) -> Result<TorClientConfig> {
    let mut cfg_builder = TorClientConfig::builder();
    cfg_builder
        .storage()
        .cache_dir(CfgPath::from_path(cache_path))
        .state_dir(CfgPath::from_path(cache_path));

    let auth_path = cache_path.join("authority.json");
    let auth_raw = fs::read_to_string(auth_path).context("Failed to read authority")?;
    let auth = serde_json::from_str(auth_raw.as_str())?;

    cfg_builder.tor_network().authorities(vec![auth]);
    // Overriding authorities requires also overriding fallback caches
    cfg_builder.tor_network().fallback_caches(Vec::new());

    cfg_builder.build().map_err(anyhow::Error::new)
}

/// Sends a request over a TLS connection and returns the result.
pub(super) async fn send_request(
    tor: &TorClient<impl Runtime>,
    host: &str,
    request: &[u8],
) -> Result<Vec<u8>> {
    let stream = tor.connect((host, 443)).await.context("tor connect")?;

    let mut tls_stream =
        TlsConnector::from(native_tls::TlsConnector::new().context("create tls connector")?)
            .connect(host, stream)
            .await
            .context("tls connect")?;

    tls_stream
        .write_all(request)
        .await
        .context("write request")?;
    tls_stream.flush().await.context("stream flush")?;

    let mut response = Vec::new();
    tls_stream
        .read_to_end(&mut response)
        .await
        .context("read response")?;

    trace!(?response, "received stream");

    Ok(response)
}
