//! Tor client made simpler

#![deny(missing_docs)]

mod client;
mod ffi;
mod flatfiledirmgr;
mod http;

pub use client::Client;
