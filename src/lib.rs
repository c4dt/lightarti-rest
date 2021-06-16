use anyhow::{Result, bail};
use log::info;
use std::collections::HashMap;
use url::Url;

use crate::arti::tls_send;

mod arti;
mod ffi;

/// Request for the different REST methods. Here we don't differentiate between
/// the url and the parameters passed to the remote end.
/// Only http and https URLs are supported for the moment.
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

impl Request {
    /// Sends the request to the given URL. It returns the response.
    pub fn send(&self, dir_cache: &DirectoryCache) -> Result<Response> {
        let request = &self.to_str()?;
        info!("Contacting path {}", request);
        let resp = tls_send(&self.host()?, request, dir_cache)?;
        Ok(Response {
            code: 100,
            body: Some(resp),
        })
    }

    /// Returns the string to be sent to the host.
    fn to_str(&self) -> Result<String> {
        info!("Sending GET request to {}", self.url);
        let url = Url::parse(&self.url)?;
        if url.scheme() != "https" {
            bail!("Currently only supports https");
        }
        let host = &url.domain().unwrap();
        // TODO: add other headers
        // TODO: add body
        // Needs to follow https://www.rfc-editor.org/rfc/rfc7230.html#page-19
        Ok(format!("{} {} HTTP/1.0\r\nHost: {}\r\n\r\n",
                   self.method, url.path(), host))
    }

    /// Returns the host, or an error if it's not defined.
    fn host(&self) -> Result<String> {
        let url = Url::parse(&self.url)?;
        Ok(url.domain().unwrap().into())
    }
}

/// The DirectoryCache allows arti to avoid having to download all the nodes and
/// relays when starting up. This improves the request-time a lot, as arti now only
/// needs to set up the circuit, and not download the information of all the nodes.
/// Even if some nodes are not available anymore, this is not a problem.
///
/// If tmp_dir is set, it is used to store temporary files during the setup. This is only
/// needed in Android.
pub struct DirectoryCache {
    pub tmp_dir: Option<String>,
    pub nodes: Option<String>,
    pub relays: Option<String>,
}


/// Response from the REST call. If an error happened during the call,
/// no Response will be sent.
/// The 'code' is parsed from the response.
#[derive(Debug)]
pub struct Response {
    pub code: i32,
    pub body: Option<String>,
}

#[test]
fn test_get() {
    use log::LevelFilter;

    simple_logging::log_to_stderr(LevelFilter::Debug);

    let req = Request {
        method: "GET".into(),
        url: "https://www.c4dt.org/index.html".into(),
        headers: HashMap::new(),
        body: None,
    };
    match req.send(&DirectoryCache {
        tmp_dir: None,
        nodes: None,
        relays: None,
    }) {
        Ok(resp) => {
            info!("Sent GET to c4dt.org and got code {}", resp.code);
            if let Some(body) = resp.body {
                info!("Body is: {}", body);
            }
        }
        Err(e) => {
            panic!("Encountered error: {}", e);
        }
    }
}