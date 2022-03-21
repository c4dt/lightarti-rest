use std::{convert::TryFrom, fs, path::Path, sync::Arc};

use anyhow::{bail, Context, Result};
use arti_client::{TorClient, TorClientConfig};
use http::{Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{rustls, TlsConnector};
use tor_config::CfgPath;
use tor_rtcompat::tokio::TokioRustlsRuntime as Runtime;
use tracing::trace;

use crate::{
    flatfiledirmgr::FlatFileDirMgrBuilder,
    http::{raw_to_response, request_to_raw},
};

pub struct Client(TorClient<Runtime>);

impl Client {
    pub async fn new(cache: &Path) -> Result<Self> {
        let runtime = Runtime::current().context("get runtime")?;

        let tor_client = TorClient::with_runtime(runtime)
            .config(Self::tor_config(cache).context("load config")?)
            .dirmgr_builder::<FlatFileDirMgrBuilder>(Arc::new(FlatFileDirMgrBuilder {}))
            .create_bootstrapped()
            .await
            .context("create tor client")?;

        Ok(Self(tor_client))
    }

    fn tor_config(cache_path: &Path) -> Result<TorClientConfig> {
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

        cfg_builder.build().context("build config")
    }

    /// Sends the request to the given URL. It returns the response.
    pub async fn send(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>> {
        trace!("request: {:?}", req);

        if req.version() != http::Version::HTTP_10 {
            bail!("only supports HTTP version 1.0")
        }

        let uri = req.uri().clone();
        let host = uri.host().context("no host found")?;

        let raw_req = request_to_raw(req).context("serialize request")?;
        let raw_resp = self.send_raw(host, &raw_req).await.context("tls send")?;
        let resp = raw_to_response(raw_resp);

        trace!("response: {:?}", resp);

        resp
    }

    /// Sends a request over a TLS connection and returns the result.
    // TODO use Request directly
    async fn send_raw(&self, host: &str, request: &[u8]) -> Result<Vec<u8>> {
        let stream = self.0.connect((host, 443)).await.context("tor connect")?;

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut tls_stream = TlsConnector::from(Arc::new(tls_config))
            .connect(
                rustls::ServerName::try_from(host).context("invalid host")?,
                stream,
            )
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
}
