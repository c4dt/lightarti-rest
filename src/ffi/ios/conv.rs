use std::mem::ManuallyDrop;

use tokio::runtime::Runtime;

use super::RuntimeAndClient;
use crate::Client;

impl From<RuntimeAndClient> for isize {
    fn from(rt_and_client: RuntimeAndClient) -> Self {
        Box::into_raw(ManuallyDrop::into_inner(rt_and_client.0)) as isize
    }
}

impl From<isize> for RuntimeAndClient {
    fn from(rt_and_client: isize) -> Self {
        Self(ManuallyDrop::new(unsafe {
            Box::from_raw(rt_and_client as *mut (Runtime, Client))
        }))
    }
}
