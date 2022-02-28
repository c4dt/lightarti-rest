use anyhow::{Context, Result};
use arti_client::TorClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_native_tls::{native_tls, TlsConnector};
use tor_rtcompat::Runtime;
use tracing::trace;

pub(super) mod flatfiledirmgr;

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
