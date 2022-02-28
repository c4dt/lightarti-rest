use std::{path::Path, sync::Arc};

use anyhow::{bail, Context, Result};
use arti_client::TorClient;
use http::{Request, Response};
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tracing::trace;

use crate::{
    http::{raw_to_response, request_to_raw},
    lightarti::{build_config, flatfiledirmgr::FlatFileDirMgrBuilder, send_request},
};

type Runtime = TokioNativeTlsRuntime;

pub struct Client(TorClient<Runtime>);

impl Client {
    pub async fn new(cache: &Path) -> Result<Self> {
        let runtime = TokioNativeTlsRuntime::current().context("get runtime")?;

        let tor_client = TorClient::with_runtime(runtime)
            .config(build_config(cache).context("load config")?)
            .dirmgr_builder::<FlatFileDirMgrBuilder>(Arc::new(FlatFileDirMgrBuilder {}))
            .create_bootstrapped()
            .await
            .context("create tor client")?;

        Ok(Self(tor_client))
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
        let raw_resp = send_request(&self.0, host, &raw_req)
            .await
            .context("tls send")?;
        let resp = raw_to_response(raw_resp);

        trace!("response: {:?}", resp);

        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests;

    #[tokio::test]
    async fn test_get() {
        crate::tests::setup_tracing();
        let cache = tests::setup_cache();

        let resp = Client::new(cache.path())
            .await
            .expect("create client")
            .send(
                Request::get("https://www.example.com")
                    .header("Host", "www.example.com")
                    .version(http::Version::HTTP_10)
                    .body(vec![])
                    .expect("create get request"),
            )
            .await
            .expect("send request");

        assert_eq!(resp.status(), 200);
    }
}
