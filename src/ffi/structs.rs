use std::{mem::ManuallyDrop, path::Path};

use anyhow::{Context, Result};
use tokio::runtime::Runtime;

use crate::Client;

pub(super) struct RuntimeAndClient(pub ManuallyDrop<Box<(Runtime, Client)>>);

impl RuntimeAndClient {
    pub fn new(cache_dir: &Path) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build tokio runtime")?;

        let client = rt
            .block_on(async { Client::new(cache_dir).await })
            .context("create client")?;

        Ok(Self(ManuallyDrop::new(Box::new((rt, client)))))
    }

    pub fn runtime(&self) -> &Runtime {
        &self.0 .0
    }

    pub fn client(&self) -> &Client {
        &self.0 .1
    }
}

pub(super) struct Request(pub http::Request<Vec<u8>>);
pub(super) struct Response(pub http::Response<Vec<u8>>);
