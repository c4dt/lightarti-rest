use std::{borrow::Cow, convert::TryInto, mem::ManuallyDrop, path::Path};

use anyhow::{Context, Result};
use core_foundation::{
    base::TCFType,
    string::{CFString, CFStringRef},
};

mod conv;
mod structs;

use super::{Request, Response, RuntimeAndClient};

#[no_mangle]
pub unsafe extern "C" fn logger_init() {
    let subscriber = tracing_fmt::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("to be the only logger");
}

#[no_mangle]
pub unsafe extern "C" fn client_new(cache_dir_ref: CFStringRef) -> structs::Result<isize> {
    {
        let cache_dir_ios = CFString::wrap_under_get_rule(cache_dir_ref);
        let cache_dir_raw: Cow<_> = (&cache_dir_ios).into();
        let cache_dir = Path::new(cache_dir_raw.as_ref());

        RuntimeAndClient::new(cache_dir)
            .context("create runtime and client")
            .map(Into::into)
    }
    .into()
}

#[no_mangle]
pub unsafe extern "C" fn client_send(
    ios_client: isize,
    request: structs::Request,
) -> structs::Result<structs::Response> {
    (|| -> Result<structs::Response> {
        let rt_and_client = RuntimeAndClient::from(ios_client);

        let req: Request = request.try_into().context("iOS request to Rust")?;

        let resp = rt_and_client
            .runtime()
            .block_on(async { rt_and_client.client().send(req.0).await })
            .context("send request")
            .map(Response)?;

        let ret = resp.try_into().context("Rust response to iOS")?;

        Ok(ret)
    })()
    .into()
}

#[no_mangle]
pub unsafe extern "C" fn client_free(ios_client: isize) {
    ManuallyDrop::into_inner(RuntimeAndClient::from(ios_client).0);
}
