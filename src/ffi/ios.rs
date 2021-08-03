use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::path::PathBuf;
use std::panic;

use anyhow::{anyhow, Context, Result};
use core_foundation::{
    base::TCFType,
    string::{CFString, CFStringRef},
};
use http::header::HeaderName;
use http::{HeaderValue, Method, Request};
use libc::c_char;
use serde::{Deserialize, Serialize};
use tracing::debug;
use url::Url;

use crate::client::Client;

#[derive(Debug, Serialize, Deserialize)]
struct ArtiRequest {
    method: String,
    url: String,
    headers: HashMap<String, Vec<String>>,
    body: Vec<u8>,
    cache_dir: String,
}

impl TryFrom<ArtiRequest> for http::Request<Vec<u8>> {
    type Error = anyhow::Error;

    fn try_from(request: ArtiRequest) -> Result<Self, Self::Error> {
        let host_url = Url::parse(&request.url).context("parse url")?;
        let host = host_url.host_str().context("no host in request")?;

        let mut req = Request::builder()
            .method(Method::from_bytes(request.method.as_bytes()).context("invalid method")?)
            .header("Host", host)
            .version(http::Version::HTTP_10)
            .uri(&request.url)
            .body(request.body)
            .context("invalid request")?;

        let hm = req.headers_mut();
        for (key, values) in request.headers {
            for value in values {
                hm.append(
                    &HeaderName::from_bytes(&key.as_bytes())?,
                    HeaderValue::from_bytes(value.as_bytes())?,
                );
            }
        }

        Ok(req)
    }
}

#[no_mangle]
pub unsafe extern "C" fn call_arti(request_json: *const c_char) -> CFStringRef {
    setup_logger();

    let ret = _call_arti(cstring_to_str(&request_json))
        .map(|resp| ReturnStruct {
            response: Some(resp),
            error: None,
        })
        .unwrap_or_else(|e| ReturnStruct {
            error: Some(JSONError {
                error_string: e.to_string(),
                error_context: None,
            }),
            response: None,
        });

    // FIXME doesn't yield valid response on JSON error
    to_cf_str(serde_json::to_string(&ret).unwrap_or("JSON error".into()))
}

fn _call_arti(request_json: &str) -> Result<Response> {
    panic::catch_unwind(|| {
        let request: ArtiRequest =
            serde_json::from_str(request_json).context("parse request as JSON")?;
        debug!("JSON-Request is: {:?}", request);

        // TODO avoid binding field to struct to avoid copying around
        let cache_dir = PathBuf::from(request.cache_dir.clone());

        let req = request
            .try_into()
            .context("convert request to http::Request")?;
        debug!("Parsed request is: {:?}", req);

        let resp = Client::new(cache_dir).send(req).context("send request")?;
        resp.try_into()
            .context("convert http::Response to response")
    })
        .unwrap_or_else(|e| Err(anyhow!("caught panic: {:?}", e)))
}

#[derive(Serialize, Deserialize, Debug)]
struct ReturnStruct {
    error: Option<JSONError>,
    response: Option<Response>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    status: u16,
    headers: HashMap<String, Vec<String>>,
    body: Vec<u8>,
}

impl TryFrom<http::response::Response<Vec<u8>>> for Response {
    type Error = anyhow::Error;

    fn try_from(resp: http::response::Response<Vec<u8>>) -> Result<Self, Self::Error> {
        let mut headers = HashMap::new();
        for (k, v) in resp.headers() {
            headers.insert(k.to_string(), vec![v.to_str()?.to_string()]);
        }

        Ok(Response {
            status: resp.status().as_u16(),
            headers,
            body: resp.body().clone(),
        })
    }
}

// TODO rename as it isn't only a JSON only error
#[derive(Serialize, Deserialize, Debug)]
struct JSONError {
    error_string: String,
    // TODO remove, it is not possible to extract context with `anyhow`
    error_context: Option<String>,
}

fn to_cf_str(str: String) -> CFStringRef {
    let cf_string = CFString::new(&str);
    let cf_string_ref = cf_string.as_concrete_TypeRef();
    ::std::mem::forget(cf_string); // FIXME seems really weird to be needing this
    cf_string_ref
}

// Convert C string to Rust string slice
unsafe fn cstring_to_str<'a>(cstring: &'a *const c_char) -> &str {
    if cstring.is_null() {
        // TODO Of course in a real project you'd return Result instead
        panic!("cstring is null")
    }

    let raw = ::std::ffi::CStr::from_ptr(*cstring);
    // TODO panic not handled
    raw.to_str().expect("Couldn't convert c string to slice")
}

fn setup_logger() {
    let subscriber = tracing_fmt::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("to be the only logger");
}
