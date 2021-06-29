use std::path::PathBuf;

use anyhow::{Context, Result};
use http::{Request, Uri, Version};
use jni::objects::{JClass, JList, JMap, JObject, JString, JValue};
use jni::sys::{jbyteArray, jint, jobject};
use jni::JNIEnv;
use tracing::{info, log::Level, trace};

use crate::client::Client;

const ANDROID_LOG_TAG: &str = "ArtiLib";
const TOR_LIB_EXCEPTION: &str = "org/c4dt/artiwrapper/TorLibException";

/// Minimal entry point used for testing purposes
#[no_mangle]
pub unsafe extern "system" fn Java_org_c4dt_artiwrapper_TorLibApi_hello(
    env: JNIEnv,
    _: JClass,
    who: JString,
) -> jobject {
    || -> Result<JObject> {
        let str: String = env
            .get_string(who)
            .context("create rust string for `who`")?
            .into();

        env.new_string(format!("Hello {}!", str))
            .context("create java string")
            .map(Into::into)
    }()
    .unwrap_or_else(|e| {
        let _ = env.throw((TOR_LIB_EXCEPTION, format!("process hello: {:?}", e)));
        JObject::null()
    })
    .into_inner()
}

/// Entry point to initialize the logger so that Rust logs show up in logcat
#[no_mangle]
pub unsafe extern "system" fn Java_org_c4dt_artiwrapper_TorLibApi_initLogger(_: JNIEnv, _: JClass) {
    // Important: Logcat doesn't contain stdout / stderr so we need a custom logger.
    // An alternative solution to android_logger, is to register a callback
    // (Using the same functionality as registerCallback) to send the logs.
    // This allows to process the messages arbitrarily in the app.
    android_logger::init_once(
        android_logger::Config::default()
            .with_min_level(Level::Trace)
            .with_tag(ANDROID_LOG_TAG),
    );
    // Log panics rather than printing them.
    // Without this, Logcat doesn't show panic message.
    log_panics::init();
    info!("init log system - done");
}

/// Get the cache dir from the input arguments
fn get_cache_dir(env: JNIEnv, cache_dir_j: JString) -> Result<String> {
    env.get_string(cache_dir_j)
        .context("create rust string for `cache_dir_j`")
        .map(Into::into)
}

/// Build an http::Request from the input arguments
fn make_request(
    env: JNIEnv,
    method_j: JString,
    url_j: JString,
    headers_j: JObject,
    body_j: jbyteArray,
) -> Result<http::Request<Vec<u8>>> {
    let method: String = env
        .get_string(method_j)
        .context("create rust string for `method_j`")?
        .into();

    let url: String = env
        .get_string(url_j)
        .context("create rust string for `url_j`")?
        .into();

    let body: Vec<u8> = env
        .convert_byte_array(body_j)
        .context("create byte array")?;

    let uri = url.parse::<Uri>().context("parse URL")?;
    let host = uri.host().unwrap_or("");

    let mut req_builder = Request::builder()
        .method(method.as_bytes())
        .header("Host", host)
        .uri(uri)
        .version(Version::HTTP_10);

    let headers_jmap: JMap = env.get_map(headers_j).context("create JMap")?;

    for (key, value_list) in headers_jmap.iter().context("create JMap iterator")? {
        let header_name: String = env
            .get_string(JString::from(key))
            .context("create rust string for header name")?
            .into();
        trace!("Request header_name: {:?}", header_name);

        let header_value_list: JList = env.get_list(value_list).context("create JList")?;

        for value in header_value_list.iter().context("create JList iterator")? {
            let header_value: String = env
                .get_string(JString::from(value))
                .context("create rust string for header value")?
                .into();
            trace!("    Request header_value: {:?}", header_value);

            req_builder = req_builder.header(header_name.as_str(), header_value);
        }
    }

    let request = req_builder.body(body).context("create request")?;

    Ok(request)
}

/// Format an http::Response into a Java HttpResponse object
fn format_response(env: JNIEnv, response: http::Response<Vec<u8>>) -> Result<JObject> {
    let status: jint = response.status().as_u16().into();

    let version = env
        .new_string(match response.version() {
            http::Version::HTTP_09 => "HTTP/0.9",
            http::Version::HTTP_10 => "HTTP/1.0",
            http::Version::HTTP_11 => "HTTP/1.1",
            http::Version::HTTP_2 => "HTTP/2",
            http::Version::HTTP_3 => "HTTP/3",
            _ => "Unknown",
        })
        .context("build http string version")?;

    let headers = env
        .new_object(
            env.find_class("java/util/HashMap")
                .context("find java.util.HashMap")?,
            "()V",
            &[],
        )
        .context("create HashMap")?;

    for (key, value) in response.headers() {
        trace!("Response header: {:?} → {:?}", key, value);

        let mut entry = env
            .new_object(
                env.find_class("java/util/ArrayList")
                    .context("find java.util.ArrayList")?,
                "()V",
                &[],
            )
            .context("create ArrayList")?;

        match env
            .call_method(
                headers,
                "putIfAbsent",
                "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
                &[
                    env.new_string(key.as_str())
                        .context("create JString for key")?
                        .into(),
                    entry.into(),
                ],
            )
            .context("call HashMap.put()")?
        {
            JValue::Object(o) => {
                if o.into_inner() != std::ptr::null_mut() {
                    trace!("Entry already existed -- appending");
                    entry = o;
                }
            }
            _ => (),
        }

        env.call_method(
            entry,
            "add",
            "(Ljava/lang/Object;)Z",
            &[env
                .new_string(value.to_str().context("convert header value to string")?)
                .context("create JString for value")?
                .into()],
        )
        .context("call List.add()")?;
    }

    let body = env
        .byte_array_from_slice(response.body())
        .context("create byte array")?;

    Ok(env
        .new_object(
            env.find_class("org/c4dt/artiwrapper/HttpResponse")
                .context("find HttpResult class")?,
            "(ILjava/lang/String;Ljava/util/Map;[B)V",
            &[status.into(), version.into(), headers.into(), body.into()],
        )
        .context("create HttpResult")?)
}

/// Entry point to process an HTTP request via Arti
#[no_mangle]
pub unsafe extern "system" fn Java_org_c4dt_artiwrapper_TorLibApi_torRequest(
    env: JNIEnv,
    _: JClass,
    cache_dir_j: JString,
    method_j: JString,
    url_j: JString,
    headers_j: JObject,
    body_j: jbyteArray,
) -> jobject {
    || -> Result<JObject> {
        let request =
            make_request(env, method_j, url_j, headers_j, body_j).context("make request")?;
        trace!("Request: {:?}", request);

        let cache_dir = get_cache_dir(env, cache_dir_j).context("get cache dir")?;
        let client = Client::new(PathBuf::from(cache_dir));

        let response = client.send(request).context("send request")?;
        trace!("Response: {:?}", response);

        format_response(env, response).context("format response")
    }()
    .unwrap_or_else(|e| {
        let _ = env.throw((TOR_LIB_EXCEPTION, format!("{:?}", e)));
        JObject::null()
    })
    .into_inner()
}
