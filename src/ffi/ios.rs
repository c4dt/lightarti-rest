use std::path::Path;

use core_foundation::{
    base::TCFType,
    string::{CFString, CFStringRef},
};
use http::{Request, HeaderValue, HeaderMap, StatusCode};
use libc::c_char;
use tracing::info;
use url::Url;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use http::header::HeaderName;
use std::collections::HashMap;

use crate::client::Client;

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

    let ret = match _call_arti(cstring_to_str(&request_json)) {
        Ok(ret) => ret,
        Err(e) => ReturnStruct::err(e.to_string()),
    };
    return to_cf_str(ret.to_json().to_string());
}

pub fn _call_arti(request_json: &str) -> Result<ReturnStruct> {
    let request: ArtiRequest = serde_json::from_str(request_json)?;
    info!("Request is: {:?}", request);

    let host = Url::parse(&request.url)?.host_str().unwrap().to_string();
    let mut req = match request.method.as_str() {
        "GET" => Request::get(request.url),
        "POST" => Request::post(request.url),
        "PUT" => Request::put(request.url),
        "DELETE" => Request::delete(request.url),
        // TODO: add other verbs of REST
        // TODO: correctly return error here
        _ => Request::get(request.url),
    }
        .header("Host", host)
        .version(http::Version::HTTP_10)
        .body(vec![])?;

    let hm = req.headers_mut();
    for (key, values) in request.headers {
        for value in values {
            hm.append(&HeaderName::from_bytes(&key.as_bytes())?,
                      HeaderValue::from_bytes(value.as_bytes())?);
        }
    }

    info!("Request is: {:?}", req);

    let resp = Client::new(DirectoryCache {
        tmp_dir: Some(request.dict_dir),
        nodes: None,
        relays: None,
    })
        .send(req)?;

    ReturnStruct::new(resp.status(), resp.headers(), resp.body())
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

impl ReturnStruct {
    pub fn new(status: StatusCode, headers_map: &HeaderMap<HeaderValue>, body_vec: &Vec<u8>) -> Result<Self> {
        let mut headers = HashMap::new();
        for (k, v) in headers_map {
            headers.insert(k.to_string(), vec![v.to_str()?.to_string()]);
        }
        Ok(Self {
            error: None,
            response: Some(Response {
                status: status.into(),
                headers,
                body: body_vec.clone(),
            }),
        })
    }

    pub fn err(error: String) -> ReturnStruct {
        ReturnStruct {
            error: Some(JSONError {
                error_string: error.to_string(),
                error_context: None,
            }),
            response: None,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or("JSON error".into())
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
