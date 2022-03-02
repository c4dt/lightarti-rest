use std::{
    borrow::Cow,
    collections::HashMap,
    convert::TryFrom,
    mem::{self, ManuallyDrop},
};

use anyhow::Context;
use core_foundation::{
    array::CFArray,
    base::{FromVoid, TCFType},
    data::{CFData, CFDataRef},
    dictionary::{CFDictionary, CFDictionaryRef},
    string::{CFString, CFStringRef},
    url::{CFURLRef, CFURL},
};
use http::{
    header::{HeaderName, HeaderValue},
    Uri,
};

#[repr(C)]
pub enum Method {
    // TODO more methods!
    Get,
}

impl From<Method> for http::Method {
    fn from(method: Method) -> Self {
        match method {
            Method::Get => http::Method::GET,
        }
    }
}

#[repr(C)]
pub struct Request {
    method: Method,
    url: CFURLRef,
    /// CFDictionary<CFString, CFArray<CFData>>,
    headers: CFDictionaryRef,
    body: CFDataRef,
}

impl TryFrom<Request> for super::Request {
    type Error = anyhow::Error;

    fn try_from(request: Request) -> anyhow::Result<Self> {
        let url_ios = unsafe { CFURL::wrap_under_get_rule(request.url) };
        let url_raw = url_ios.get_string();
        let url_raw: Cow<_> = (&url_raw).into();
        let url: Uri = url_raw.parse().context("parse url")?;

        let headers_ios = unsafe {
            CFDictionary::<CFString, CFArray<CFData>>::wrap_under_get_rule(request.headers)
        };
        let body_ios = unsafe { CFData::wrap_under_get_rule(request.body) };

        let mut ret = http::Request::builder()
            .method::<http::Method>(request.method.into())
            .header("Host", url.host().context("no host in request")?)
            .version(http::Version::HTTP_10)
            .uri(url)
            .body(body_ios.bytes().to_vec())
            .context("invalid request")?;

        let (headers_keys, headers_values) = headers_ios.get_keys_and_values();
        let hm = ret.headers_mut();
        for (key, values) in headers_keys
            .into_iter()
            .map(|k| unsafe { CFString::from_void(k) })
            .zip(
                headers_values
                    .into_iter()
                    .map(|v| unsafe { CFArray::<CFData>::from_void(v) }),
            )
        {
            let key_raw: Cow<_> = (&(*key)).into();
            let key = HeaderName::try_from(key_raw.as_ref()).context("invalid header name")?;

            for value in values.iter() {
                let value = HeaderValue::try_from(value.bytes()).context("invalid header value")?;
                hm.append(&key, value);
            }
        }

        Ok(super::Request(ret))
    }
}

#[repr(C)]
pub struct Response {
    status: u16,
    /// CFDictionary<CFString, CFArray<CFData>>,
    headers: CFDictionaryRef,
    body: CFDataRef,
}

impl TryFrom<super::Response> for Response {
    type Error = anyhow::Error;

    fn try_from(resp: super::Response) -> anyhow::Result<Self> {
        let (parts, body) = resp.0.into_parts();

        let mut headers_with_vec = HashMap::with_capacity(parts.headers.keys_len());
        let mut last_header_name = None;
        for (k, v) in parts.headers {
            let k = k
                .map(|k| k.as_str().to_owned())
                .or(last_header_name)
                .context("no header name")?;
            last_header_name = Some(k.clone());

            headers_with_vec.entry(k).or_insert_with(Vec::new).push(v);
        }

        // TODO avoid copies
        let headers = CFDictionary::from_CFType_pairs(
            &headers_with_vec
                .into_iter()
                .map(|(k, vs)| {
                    (
                        CFString::new(&k),
                        CFArray::from_CFTypes(
                            &vs.into_iter()
                                .map(|v| CFData::from_buffer(v.as_bytes()))
                                .collect::<Vec<_>>(),
                        ),
                    )
                })
                .collect::<Vec<_>>(),
        );

        let body = CFData::from_buffer(&body);

        let ret = Self {
            status: parts.status.as_u16(),
            headers: headers.as_concrete_TypeRef(),
            body: body.as_concrete_TypeRef(),
        };

        // ownership for the caller
        mem::forget(headers);
        mem::forget(body);

        Ok(ret)
    }
}

#[repr(C)]
pub union ResultUnion<T> {
    ok: ManuallyDrop<T>,
    err: CFStringRef,
}

#[repr(C)]
pub struct Result<T> {
    is_ok: bool,
    value: ResultUnion<T>,
}

impl<T> From<anyhow::Result<T>> for Result<T> {
    fn from(res: anyhow::Result<T>) -> Self {
        let is_ok = res.is_ok();

        let value = match res {
            Ok(ok) => ResultUnion {
                ok: ManuallyDrop::new(ok),
            },
            Err(err) => ResultUnion {
                err: ManuallyDrop::new(CFString::new(&format!("{:#}", err))).as_concrete_TypeRef(),
            },
        };

        Self { is_ok, value }
    }
}
