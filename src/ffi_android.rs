use mpsc::Receiver;
use std::{
    sync::mpsc::{self, Sender},
    thread,
};

use jni::JavaVM;
use jni::JNIEnv;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jint, jobject, jstring};
use log::info;

use crate::{tls_get};


#[no_mangle]
pub unsafe extern "system" fn Java_com_schuetz_rustandroidios_JniApi_initLogger(
    _: JNIEnv,
    _: JClass,
) {
    // Important: Logcat doesn't contain stdout / stderr so we need a custom logger.
    // An alternative solution to android_logger, is to register a callback
    // (Using the same functionality as registerCallback) to send the logs.
    // This allows to process the messages arbitrarily in the app.
    android_logger::init_once(
        android_logger::Config::default()
            .with_min_level(log::Level::Debug)
            .with_tag("Hello"),
    );
    // Log panics rather than printing them.
    // Without this, Logcat doesn't show panic message.
    log_panics::init();
    info!("init log system - done");
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_schuetz_rustandroidios_JniApi_TLS_get(
    env: JNIEnv,
    _: JClass,
    cache_dir_j: JString,
    domain_j: JString,
) -> jstring {
    let cache_dir: String = env.get_string(cache_dir_j).expect("Couldn't create rust string").into();
    let domain: String = env.get_string(domain_j).expect("Couldn't create rust string").into();
    let output = match tls_get(&domain, Some(&cache_dir)) {
        Ok(s) => format!("Result is: {}", s),
        Err(e) => format!("Error while getting result: {}", e),
    };
    env.new_string(output).expect("Failed to build java string").into_inner()
}
