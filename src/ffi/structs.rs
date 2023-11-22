//! FFI structs

use std::{mem::ManuallyDrop, path::Path};

use anyhow::{Context, Result};
use tokio::runtime::Runtime;

use crate::client::{DIRECTORY_CACHE_C4DT, DIRECTORY_CHURN_C4DT};
use crate::Client;

/// Wrap a [`Runtime`] and a [`Client`], useful for crossing FFI boundaries
pub(super) struct RuntimeAndClient(pub ManuallyDrop<Box<(Runtime, Client)>>);

impl RuntimeAndClient {
    /// Create a new [`RuntimeAndClient`] using the given cache directory
    pub fn new(cache_dir: &Path) -> Result<Self> {
        Self::new_with_url(cache_dir, DIRECTORY_CACHE_C4DT, DIRECTORY_CHURN_C4DT)
    }

    /// Create a new [`RuntimeAndClient`] by giving another URL for the cache files.
    pub fn new_with_url(
        cache_dir: &Path,
        directory_cache: &str,
        churn_cache: &str,
    ) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build tokio runtime")?;

        let client = rt
            .block_on(async { Client::new_with_url(cache_dir, directory_cache, churn_cache).await })
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
