use std::{mem::ManuallyDrop, ops::Deref, path::Path, ptr};

use anyhow::{Context, Result};
use jni::{
    objects::{JClass, JObject, JString},
    sys::{jbyteArray, jlong, jobject},
    JNIEnv,
};
use tracing::{info, log::Level};

use super::{Request, Response, RuntimeAndClient};

mod conv;

const ANDROID_LOG_TAG: &str = "ArtiLib";
const TOR_LIB_EXCEPTION: &str = "org/c4dt/artiwrapper/TorLibException";

/// Minimal entry point used for testing purposes
#[no_mangle]
pub unsafe extern "system" fn Java_org_c4dt_artiwrapper_TorLibApi_hello(
    env: JNIEnv,
    _: JClass,
    who: JString,
) -> jobject {
    throw_on_err(env, ptr::null_mut(), || {
        let str: String = env
            .get_string(who)
            .context("create rust string for `who`")?
            .into();

        env.new_string(format!("Hello {}!", str))
            .context("create java string")
            .map(Into::into)
            .map(JObject::into_inner)
    })
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

/// Create a Client
#[no_mangle]
pub unsafe extern "system" fn Java_org_c4dt_artiwrapper_Client_create(
    env: JNIEnv,
    _: JClass,
    cache_dir_j: JString,
) -> jlong {
    throw_on_err(env, 0, || {
        // TODO avoid UTF-8 conversion?
        let cache_dir_javastr = env
            .get_string(cache_dir_j)
            .context("create rust string for `cache_dir_j`")?;
        let cache_dir = cache_dir_javastr
            .deref()
            .to_str()
            .context("rust string from java")
            .map(Path::new)?;

        RuntimeAndClient::new(cache_dir)
            .context("create runtime and client")
            .map(Into::into)
    })
}

/// Send a request with the given Client
#[no_mangle]
pub unsafe extern "system" fn Java_org_c4dt_artiwrapper_Client_send(
    env: JNIEnv,
    _: JClass,
    java_client: jlong,
    method_j: JString,
    url_j: JString,
    headers_j: JObject,
    body_j: jbyteArray,
) -> jobject {
    throw_on_err(env, ptr::null_mut(), || {
        let rt_and_client = RuntimeAndClient::from(java_client);
        let request = Request::from_java(env, method_j, url_j, headers_j, body_j)
            .context("request from java")?;

        let response = rt_and_client
            .runtime()
            .block_on(async { rt_and_client.client().send(request.0).await })
            .context("send request")
            .map(Response)?;

        response
            .into_java(env)
            .context("response to java")
            .map(JObject::into_inner)
    })
}

/// Free the given Client
#[no_mangle]
pub unsafe extern "system" fn Java_org_c4dt_artiwrapper_Client_free(
    _: JNIEnv,
    _: JClass,
    java_client: jlong,
) {
    ManuallyDrop::into_inner(RuntimeAndClient::from(java_client).0);
}

fn throw_on_err<T>(env: JNIEnv, default: T, act: impl FnOnce() -> Result<T>) -> T {
    act().unwrap_or_else(|e| {
        let _ = env.throw((TOR_LIB_EXCEPTION, format!("{:#}", e)));
        default
    })
}
