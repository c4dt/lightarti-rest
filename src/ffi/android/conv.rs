use std::mem::ManuallyDrop;

use anyhow::{Context, Result};
use http::{Uri, Version};
use jni::{
    objects::{JList, JMap, JObject, JString, JValue},
    sys::{jbyteArray, jint, jlong},
    JNIEnv,
};
use tokio::runtime::Runtime;
use tracing::trace;

use super::{Request, Response, RuntimeAndClient};
use crate::Client;

impl From<jlong> for RuntimeAndClient {
    fn from(java_ptr: jlong) -> Self {
        Self(ManuallyDrop::new(unsafe {
            Box::from_raw(java_ptr as *mut (Runtime, Client))
        }))
    }
}

impl From<RuntimeAndClient> for jlong {
    fn from(rt_and_client: RuntimeAndClient) -> Self {
        Box::into_raw(ManuallyDrop::into_inner(rt_and_client.0)) as jlong
    }
}

impl Request {
    pub fn from_java(
        env: JNIEnv,
        method_j: JString,
        url_j: JString,
        headers_j: JObject,
        body_j: jbyteArray,
    ) -> Result<Self> {
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

        let mut req_builder = http::Request::builder()
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

        req_builder
            .body(body)
            .context("create request")
            .map(Request)
    }
}

impl Response {
    pub fn into_java(self, env: JNIEnv) -> Result<JObject> {
        let status: jint = self.0.status().as_u16().into();

        let version = env
            .new_string(format!("{:?}", self.0.version()))
            .context("build http string version")?;

        let headers = env
            .new_object(
                env.find_class("java/util/HashMap")
                    .context("find java.util.HashMap")?,
                "()V",
                &[],
            )
            .context("create HashMap")?;

        for (key, value) in self.0.headers() {
            trace!("Response header: {:?} → {:?}", key, value);

            let mut entry = env
                .new_object(
                    env.find_class("java/util/ArrayList")
                        .context("find java.util.ArrayList")?,
                    "()V",
                    &[],
                )
                .context("create ArrayList")?;

            if let JValue::Object(o) = env
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
                if !o.into_inner().is_null() {
                    trace!("Entry already existed -- appending");
                    entry = o;
                }
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
            .byte_array_from_slice(self.0.body())
            .context("create byte array")?;

        env.new_object(
            env.find_class("org/c4dt/artiwrapper/HttpResponse")
                .context("find HttpResult class")?,
            "(ILjava/lang/String;Ljava/util/Map;[B)V",
            &[status.into(), version.into(), headers.into(), body.into()],
        )
        .context("create HttpResult")
    }
}
