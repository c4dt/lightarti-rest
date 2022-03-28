//! FFI structs

use std::{mem::ManuallyDrop, path::Path};

use anyhow::{Context, Result};
use tokio::runtime::Runtime;

use crate::Client;

/// Wrap a [`Runtime`] and a [`Client`], useful for crossing FFI bondaries
pub(super) struct RuntimeAndClient(pub ManuallyDrop<Box<(Runtime, Client)>>);

impl RuntimeAndClient {
    /// Create a new [`RuntimeAndClient`] using the given cache directory
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

    /// Return the constructed [`Runtime`]
    pub fn runtime(&self) -> &Runtime {
        &self.0 .0
    }

    /// Return the wrapped [`Client`]
    pub fn client(&self) -> &Client {
        &self.0 .1
    }
}

/// Deserializable HTTP Request
pub(super) struct Request(pub http::Request<Vec<u8>>);
/// Serializable HTTP Response
pub(super) struct Response(pub http::Response<Vec<u8>>);
