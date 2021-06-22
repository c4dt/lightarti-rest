//! Information about directory authorities
//!
//! From a client's point of view, an authority's role is to to sign the
//! consensus directory.

// Code mostly copied from Arti.

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

    // (List generated August 2020.)
    vec![
        auth("spring", "B03DFE2050B667BFB96AA0D5B5C31922D8F5B6DE"),
    ]
}
