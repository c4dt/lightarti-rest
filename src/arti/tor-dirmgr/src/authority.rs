//! Information about directory authorities
//!
//! From a client's point of view, an authority's role is to to sign the
//! consensus directory.

// Code mostly copied from Arti.

use std::str::FromStr;
use anyhow::{bail, Context, Result, Error};
use serde::Deserialize;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::doc::authcert::{AuthCert, AuthCertKeyIds};

/// A single authority that signs a consensus directory.
//
// Note that we do *not* set serde(deny_unknown_fields)] on this structure:
// we want our authorities format to be future-proof against adding new info
// about each authority.
#[derive(Deserialize, Debug, Clone)]
pub struct Authority {
    /// A memorable nickname for this authority.
    name: String,
    /// A SHA1 digest of the DER-encoded long-term v3 RSA identity key for
    /// this authority.
    // TODO: It would be lovely to use a better hash for these identities.
    v3ident: RsaIdentity,
}

impl Authority {
    /// Construct information about a new authority.
    pub fn new(name: String, v3ident: RsaIdentity) -> Self {
        Authority { name, v3ident }
    }
    /// Return the v3 identity key of this certificate.
    pub fn v3ident(&self) -> &RsaIdentity {
        &self.v3ident
    }
    /// Return true if this authority matches a given certificate.
    pub fn matches_cert(&self, cert: &AuthCert) -> bool {
        &self.v3ident == cert.id_fingerprint()
    }

    /// Return true if this authority matches a given key ID.
    pub fn matches_keyid(&self, id: &AuthCertKeyIds) -> bool {
        self.v3ident == id.id_fingerprint
    }
}

impl FromStr for Authority {
    type Err = Error;

    /// Parse Authority from a string.
    fn from_str(authority_raw: &str) -> Result<Self, Self::Err> {
        // name, v3ident_raw
        let authority: Vec<&str> = authority_raw.split_whitespace().collect();

        if authority.len() != 2 {
            bail!("Invalid format for authority.");
        }

        let name = authority[0];
        let v3ident_raw = authority[1];

        let v3ident = hex::decode(v3ident_raw).context("Built-in authority identity had bad hex!?")?;
        let v3ident = RsaIdentity::from_bytes(&v3ident)
            .context("Built-in authority identity had wrong length!?")?;

        Ok(Authority { name: name.to_string(), v3ident })
    }
}

/// Return a vector of the default directory authorities.
pub(crate) fn default_authorities() -> Vec<Authority> {
    /// Build an authority; panic if input is bad.
    fn auth(name: &str, key: &str) -> Authority {
        let name = name.to_string();
        let v3ident = hex::decode(key).expect("Built-in authority identity had bad hex!?");
        let v3ident = RsaIdentity::from_bytes(&v3ident)
            .expect("Built-in authority identity had wrong length!?");
        Authority { name, v3ident }
    }

    vec![
        auth("spring", "A1B62E1027298A07181BFEA6801360C21DDEDE51"),
    ]
}
