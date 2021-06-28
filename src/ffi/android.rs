use http::{Request, Version};
use jni::objects::{JClass, JString, JObject, JList, JMap, JValue};
use jni::sys::{jstring, jbyteArray, jint, jobject};
use jni::JNIEnv;
use tracing::{info, trace, log::Level};
use anyhow::{bail, Context, Result};

use crate::{client::Client, DirectoryCache};

const ANDROID_LOG_TAG: &str = "ArtiLib";

#[no_mangle]
pub unsafe extern "system" fn Java_org_c4dt_artiwrapper_TorLibApi_hello(
    env: JNIEnv,
    _: JClass,
    who: JString,
) -> jstring {
    let str: String = env
        .get_string(who)
        .expect("Couldn't create rust string")
        .into();

    let output = env
        .new_string(format!("Hello {}!", str))
        .expect("Couldn't create java string");

    output.into_inner()
}

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

fn make_request(
    env: JNIEnv,
    cache_dir_j: JString,
    method_j: JString,
    url_j: JString,
    headers_j: JObject,
    body_j: jbyteArray,
) -> Result<(String, http::Request<Vec<u8>>)> {
    let cache_dir: String = env
        .get_string(cache_dir_j)
        .context("create rust string for `cache_dir_j`")?
        .into();

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

    let mut req_builder = match method.as_str() {
        "POST" => Request::post(format!("{}", url)),
        "GET" => Request::get(format!("{}", url)),
         _ => bail!("HTTP method not supported: {:?}", method)
    }.version(Version::HTTP_10);

    let headers_jmap: JMap = env
        .get_map(headers_j)
        .context("create JMap")?;

    for (key, value_list) in headers_jmap
        .iter()
        .context("create JMap iterator")? {
        let header_name: String = env
            .get_string(JString::from(key))
            .context("create rust string for header name")?
            .into();
        trace!("Request header_name: {:?}", header_name);

        let header_value_list: JList = env
            .get_list(value_list)
            .context("create JList")?;

        for value in header_value_list
            .iter()
            .context("create JList iterator")? {
            let header_value: String = env
                .get_string(JString::from(value))
                .context("create rust string for header value")?
                .into();
            trace!("    Request header_value: {:?}", header_value);

            req_builder = req_builder.header(header_name.as_str(), header_value);
        }
    }

    let request = req_builder.body(body).context("create request")?;

    Ok((cache_dir, request))
}

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

    let headers = env.new_object(
        env
            .find_class("java/util/HashMap")
            .context("find java.util.HashMap")?,
        "()V",
        &[],
        ).context("create HashMap")?;

    for (key, value) in response.headers() {
        trace!("Response header: {:?} → {:?}", key, value);

        let mut entry = env.new_object(
            env
            .find_class("java/util/ArrayList")
            .context("find java.util.ArrayList")?,
            "()V",
            &[],
            ).context("create ArrayList")?;

        match env.call_method(
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
            .context("call HashMap.put()")? {
                JValue::Object(o) => {
                    if o.into_inner() != std::ptr::null_mut() {
                        trace!("Entry already existed -- appending");
                        entry = o;
                    }
                },
                _ => (),
            }

        env.call_method(
            entry,
            "add",
            "(Ljava/lang/Object;)Z",
            &[
                env.new_string(
                    value.to_str()
                    .context("convert header value to string")?
                    )
                .context("create JString for value")?.into()
            ]
            )
            .context("call List.add()")?;
    }

    let body = env
        .byte_array_from_slice(response.body())
        .context("create byte array")?;

    Ok(env.new_object(
        env
            .find_class("org/c4dt/artiwrapper/HttpResponse")
            .context("find HttpResult class")?,
        "(ILjava/lang/String;Ljava/util/Map;[B)V",
        &[
            status.into(),
            version.into(),
            headers.into(),
            body.into(),
        ]
        )
        .context("create HttpResult")?)
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_c4dt_artiwrapper_TorLibApi_torRequest(
    env: JNIEnv,
    _: JClass,
    cache_dir_j: JString,
    method_j: JString,
    url_j: JString,
    headers_j: JObject,
    body_j: jbyteArray
) -> jobject {
    let (cache_dir, request) = match make_request(env, cache_dir_j, method_j, url_j, headers_j, body_j) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw(("org/c4dt/artiwrapper/TorLibException",
                               format!("make request: {:?}", e)));
            return JObject::null().into_inner();
        }
    };
    trace!("Request: {:?}", request);

    let client = Client::new(DirectoryCache {
        tmp_dir: Some(cache_dir),
        nodes: None,
        relays: None,
    });

    let response = match client.send(request) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw(("org/c4dt/artiwrapper/TorLibException",
                               format!("send request: {:?}", e)));
            return JObject::null().into_inner();
        },
    };
    trace!("Response: {:?}", response);

    let fmt_response = match format_response(env, response) {
        Ok(v) => v,
        Err(e) => {
            let _ = env.throw(("org/c4dt/artiwrapper/TorLibException",
                               format!("format response: {:?}", e)));
            return JObject::null().into_inner();
        },
    };

    fmt_response.into_inner()
}
