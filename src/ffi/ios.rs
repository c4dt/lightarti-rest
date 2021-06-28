use core_foundation::{
    base::TCFType,
    string::{CFString, CFStringRef},
};
use http::{Request, HeaderValue, Method};
use libc::c_char;
use tracing::info;
use url::Url;
use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};
use http::header::HeaderName;
use std::collections::HashMap;

use crate::client::Client;
use std::convert::{TryFrom, TryInto};

#[derive(Debug, Serialize, Deserialize)]
pub struct ArtiRequest {
    method: String,
    url: String,
    headers: HashMap<String, Vec<String>>,
    body: Vec<u8>,
    dict_dir: String,
}

#[no_mangle]
pub unsafe extern "C" fn call_arti(
    request_json: *const c_char) -> CFStringRef {
    setup_logger();

    let ret = _call_arti(cstring_to_str(&request_json))
        .unwrap_or_else(|e| ReturnStruct {
            error: Some(JSONError {
                error_string: e.to_string(),
                error_context: None,
            }),
            response: None,
        });

    let json_str = serde_json::to_string(&ret).unwrap_or("JSON error".into());
    return to_cf_str(json_str.to_string());
}

pub fn _call_arti(request_json: &str) -> Result<ReturnStruct> {
    let request: ArtiRequest = serde_json::from_str(request_json)?;
    info!("JSON-Request is: {:?}", request);

    let host_url = Url::parse(&request.url)
        .context("parse url")?;
    let host = host_url.host_str()
        .context("no host in request")?;

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
            hm.append(&HeaderName::from_bytes(&key.as_bytes())?,
                      HeaderValue::from_bytes(value.as_bytes())?);
        }
    }

    info!("Parsed request is: {:?}", req);

    Client::new(request.dict_dir.into()).send(req).try_into()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReturnStruct {
    error: Option<JSONError>,
    response: Option<Response>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    status: u16,
    headers: HashMap<String, Vec<String>>,
    body: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JSONError {
    error_string: String,
    error_context: Option<String>,
}

impl TryFrom<Result<http::response::Response<Vec<u8>>>> for ReturnStruct {
    type Error = anyhow::Error;

    fn try_from(resp_result: Result<http::response::Response<Vec<u8>>>) -> Result<Self, anyhow::Error> {
        match resp_result {
            Ok(resp) => {
                let mut headers = HashMap::new();
                for (k, v) in resp.headers() {
                    headers.insert(k.to_string(), vec![v.to_str()?.to_string()]);
                }
                Ok(Self {
                    error: None,
                    response: Some(Response {
                        status: resp.status().as_u16(),
                        headers,
                        body: resp.body().clone(),
                    }),
                })
            }
            Err(e) => Err(e),
        }
    }
}

fn to_cf_str(str: String) -> CFStringRef {
    let cf_string = CFString::new(&str);
    let cf_string_ref = cf_string.as_concrete_TypeRef();
    ::std::mem::forget(cf_string);
    cf_string_ref
}

// Convert C string to Rust string slice
unsafe fn cstring_to_str<'a>(cstring: &'a *const c_char) -> &str {
    if cstring.is_null() {
        // Of course in a real project you'd return Result instead
        panic!("cstring is null")
    }

    let raw = ::std::ffi::CStr::from_ptr(*cstring);
    raw.to_str().expect("Couldn't convert c string to slice")
}

fn setup_logger() {
    let subscriber = tracing_fmt::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("to be the only logger");
}
