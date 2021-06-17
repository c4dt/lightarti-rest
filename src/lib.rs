pub mod client;

mod arti;
mod ffi;

#[cfg(test)]
mod tests;

/// The DirectoryCache allows arti to avoid having to download all the nodes and
/// relays when starting up. This improves the request-time a lot, as arti now only
/// needs to set up the circuit, and not download the information of all the nodes.
/// Even if some nodes are not available anymore, this is not a problem.
///
/// If tmp_dir is set, it is used to store temporary files during the setup. This is only
/// needed in Android.
pub struct DirectoryCache {
    pub tmp_dir: Option<String>,
    pub nodes: Option<String>,
    pub relays: Option<String>,
}
