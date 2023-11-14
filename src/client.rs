use std::fs::File;
use std::io::Write;
use std::time::SystemTime;
use std::{convert::TryFrom, fs, io, path::Path, sync::Arc};

use anyhow::{bail, Context, Result};
use arti_client::{DataStream, TorClient, TorClientConfig};
use http::{Request, Response};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    client::TlsStream,
    rustls::{self, ServerName},
    TlsConnector,
};
use tor_config::CfgPath;
use tor_dirmgr::Error;
use tor_rtcompat::tokio::TokioRustlsRuntime as Runtime;
use tracing::{debug, trace, warn};

use crate::flatfiledirmgr::check_directory;
use crate::{
    flatfiledirmgr::FlatFileDirMgrBuilder,
    http::{raw_to_response, request_to_raw},
    CHURN_FILENAME, MICRODESCRIPTORS_FILENAME,
};

/// Client using the Tor network
pub struct Client(TorClient<Runtime>);

/// AUTHORITY_FILENAME is the name of the file containing the authorities.
pub const AUTHORITY_FILENAME: &str = "authority.json";

#[derive(PartialEq)]
enum UpdateNeeded {
    None,
    Churn,
    All,
}

/// Default directory cache download URL, provided by C4DT.
pub const DIRECTORY_CACHE_C4DT: &str =
    "https://github.com/c4dt/lightarti-directory/releases/latest/download/directory-cache.tgz";
/// Default directory churn download URL, provided by C4DT.
pub const DIRECTORY_CHURN_C4DT: &str =
    "https://github.com/c4dt/lightarti-directory/releases/latest/download/churn.txt";

impl Client {
    /// Create a new client with the given cache directory and the default URLs for the tor caches.
    pub async fn new(cache_path: &Path) -> Result<Self> {
        Self::new_with_url(cache_path, DIRECTORY_CACHE_C4DT, DIRECTORY_CHURN_C4DT).await
    }

    /// Create a new client with the given cache directory and URLs for the tor caches.
    pub async fn new_with_url(
        cache_path: &Path,
        directory_cache: &str,
        churn_cache: &str,
    ) -> Result<Self> {
        Self::update_cache(cache_path, directory_cache, churn_cache).await?;

        let runtime = Runtime::current().context("get runtime")?;

        let tor_client = TorClient::with_runtime(runtime)
            .config(Self::tor_config(cache_path).context("load config")?)
            .dirmgr_builder::<FlatFileDirMgrBuilder>(Arc::new(FlatFileDirMgrBuilder {}))
            .create_bootstrapped()
            .await
            .context("create tor client")?;

        Ok(Self(tor_client))
    }

    /// Checks whether the AUTHORITY_FILENAME is present, which is needed to verify the
    /// signatures of the other files.
    fn check_directory(cache_path: &Path) -> Result<()> {
        if !cache_path.is_dir() {
            return Err(Error::CacheCorruption("directory cache does not exist").into());
        }
        if !cache_path.join(AUTHORITY_FILENAME).exists() {
            debug!("required file missing: {}", AUTHORITY_FILENAME);
            return Err(Error::CacheCorruption("required file(s) missing in cache").into());
        }
        Ok(())
    }

    /// Returns which cache files need to be updated.
    async fn update_cache(
        cache_path: &Path,
        directory_cache: &str,
        churn_cache: &str,
    ) -> Result<()> {
        match Self::get_cache_state(cache_path)? {
            UpdateNeeded::None => Ok(()),
            UpdateNeeded::Churn => Self::download_churn_file(cache_path, churn_cache).await,
            UpdateNeeded::All => {
                Self::download_churn_file(cache_path, churn_cache).await?;
                Self::download_full_cache(cache_path, directory_cache)
            }
        }
    }

    /// Downloads the churn file from the given URL.
    async fn download_churn_file(cache_path: &Path, churn_cache: &str) -> Result<()> {
        let churn = reqwest::get(churn_cache).await?.bytes().await?;
        let mut f = File::create(cache_path.join(CHURN_FILENAME))?;
        Ok(f.write_all(churn.as_ref())?)
    }

    /// Downloads and extracts the cache files from the given URL, which should point to the
    /// .tgz file.
    fn download_full_cache(cache_path: &Path, directory_cache: &str) -> Result<()> {
        Ok(arkiv::Archive::download(directory_cache)?.unpack(cache_path)?)
    }

    /// Returns the OffsetDateTime
    fn get_offset_date_time(cache_path: &Path, file_name: &str) -> Result<OffsetDateTime> {
        let sec = fs::metadata(cache_path.join(file_name))?
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?;
        Ok(OffsetDateTime::from_unix_timestamp(sec.as_secs() as i64)?)
    }

    // Returns which files need to be updated by checking the dates of the files against
    // the current date.
    // This will probably fail for the first minutes of the day, when the churn is not yet
    // available in the new version.
    fn get_cache_state(cache_path: &Path) -> Result<UpdateNeeded> {
        if check_directory(cache_path).is_err() {
            return Ok(UpdateNeeded::All);
        }

        let now = OffsetDateTime::now_utc();
        if Self::get_offset_date_time(cache_path, MICRODESCRIPTORS_FILENAME)?.monday_based_week()
            != now.monday_based_week()
        {
            return Ok(UpdateNeeded::All);
        }

        let churn = Self::get_offset_date_time(cache_path, CHURN_FILENAME)?;
        Ok(
            if churn.monday_based_week() == now.monday_based_week()
                && churn.weekday() == now.weekday()
            {
                UpdateNeeded::None
            } else {
                UpdateNeeded::Churn
            },
        )
    }

    fn tor_config(cache_path: &Path) -> Result<TorClientConfig> {
        let mut cfg_builder = TorClientConfig::builder();
        Self::check_directory(cache_path)?;
        cfg_builder
            .storage()
            .cache_dir(CfgPath::new_literal(cache_path))
            .state_dir(CfgPath::new_literal(cache_path));

        let auth_path = cache_path.join(AUTHORITY_FILENAME);
        let auth_raw = fs::read_to_string(auth_path.clone())
            .context(format!("Failed to read {}", auth_path.to_string_lossy()))?;
        let auth = serde_json::from_str(auth_raw.as_str())?;

        cfg_builder.tor_network().set_authorities(vec![auth]);
        // Overriding authorities requires also overriding fallback caches
        cfg_builder.tor_network().set_fallback_caches(Vec::new());

        cfg_builder.build().context("build config")
    }

    /// Send the request over Tor
    pub async fn send(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>> {
        trace!(?request, "request");

        // TODO drop check
        if request.version() != http::Version::HTTP_10 {
            bail!("only supports HTTP version 1.0")
        }

        let raw_host = request.uri().host().context("no host found")?;
        let tls_host = rustls::ServerName::try_from(raw_host).context("invalid host")?;

        let tor_stream = self
            .0
            .connect((raw_host, request.uri().port_u16().unwrap_or(443)))
            .await
            .context("tor connect")?;

        let mut tls_stream = Self::with_tls_stream(tls_host, tor_stream)
            .await
            .context("wrap in TLS")?;

        let raw_request = request_to_raw(request).context("serialize request")?;

        tls_stream
            .write_all(&raw_request)
            .await
            .context("write request")?;
        tls_stream.flush().await.context("flush")?;

        let mut raw_response = Vec::new();
        let read_response = tls_stream.read_to_end(&mut raw_response).await;

        if let Err(ref err) = read_response {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                // see rustls/rustls#b84721ef0d72e7f2747105f6b76a6bcbb8aa0ea4
                warn!("server didn't close TLS stream")
            } else {
                read_response.context("read response")?;
            }
        }
        let response = raw_to_response(raw_response)?;

        trace!(?response, "response");

        Ok(response)
    }

    async fn with_tls_stream(
        host: ServerName,
        tor_stream: DataStream,
    ) -> Result<TlsStream<DataStream>> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        TlsConnector::from(Arc::new(tls_config))
            .connect(host, tor_stream)
            .await
            .context("tls connect")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_tracing() {
        // dropping error as many tests can setup_tracing

        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt::Subscriber::builder()
                .with_max_level(tracing::Level::DEBUG)
                .finish(),
        );

        let _ = tracing_log::LogTracer::init();
    }

    #[test]
    fn test_empty() {
        let tmp = tempfile::tempdir().expect("Creating tempdir");
        assert!(check_directory(tmp.path()).is_err());
    }

    #[tokio::test]
    async fn test_download() -> Result<()> {
        setup_tracing();

        let tmp = tempfile::tempdir().expect("Creating tempdir");
        assert!(Client::get_cache_state(tmp.path())? == UpdateNeeded::All);
        Client::update_cache(tmp.path(), DIRECTORY_CACHE_C4DT, DIRECTORY_CHURN_C4DT).await?;
        assert!(Client::get_cache_state(tmp.path())? == UpdateNeeded::None);
        Ok(())
    }
}
