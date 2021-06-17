use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use log::info;

use crate::{client::Client, DirectoryCache};
use http::Request;

const ANDROID_LOG_TAG: &str = "ArtiLib";

#[no_mangle]
pub unsafe extern "system" fn Java_org_c4dt_artiwrapper_JniApi_hello(
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
pub unsafe extern "system" fn Java_org_c4dt_artiwrapper_JniApi_initLogger(_: JNIEnv, _: JClass) {
    // Important: Logcat doesn't contain stdout / stderr so we need a custom logger.
    // An alternative solution to android_logger, is to register a callback
    // (Using the same functionality as registerCallback) to send the logs.
    // This allows to process the messages arbitrarily in the app.
    android_logger::init_once(
        android_logger::Config::default()
            .with_min_level(log::Level::Debug)
            .with_tag(ANDROID_LOG_TAG),
    );
    // Log panics rather than printing them.
    // Without this, Logcat doesn't show panic message.
    log_panics::init();
    info!("init log system - done");
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_c4dt_artiwrapper_JniApi_tlsGet(
    env: JNIEnv,
    _: JClass,
    cache_dir_j: JString,
    domain_j: JString,
) -> jstring {
    let cache_dir: String = env
        .get_string(cache_dir_j)
        .expect("Couldn't create rust string")
        .into();
    let domain: String = env
        .get_string(domain_j)
        .expect("Couldn't create rust string")
        .into();

    let req = Request::get(format!("https://{}", domain))
        .header("Host", domain)
        .body(vec![])
        .expect("create request");

    let client = Client::new(DirectoryCache {
        tmp_dir: Some(cache_dir),
        nodes: None,
        relays: None,
    });

    let output = match client.send(req) {
        Ok(s) => format!(
            "Result is: {:?}",
            s.map(|raw| String::from_utf8(raw).expect("decode body as utf8"))
        ),
        Err(e) => format!("Error while getting result: {}", e),
    };

    env.new_string(output)
        .expect("Failed to build java string")
        .into_inner()
}
