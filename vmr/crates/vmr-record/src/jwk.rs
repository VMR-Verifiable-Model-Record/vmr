//! JWK public keys and the record's key ids: RFC 7638 thumbprints in
//! RFC 9278 URN form.
// ============================================================================
//  jwk.rs — key binding (QA P3-07)
//
//  A record names its signing key twice: `issuer.public_key` (a JWK) and
//  the key id carried by `issuer.key_id`, `signature.signing_key_id` and the
//  COSE protected header's `kid`. The key id is the RFC 7638 JWK SHA-256
//  thumbprint of that JWK, written as the RFC 9278 URN
//
//      urn:ietf:params:oauth:jwk-thumbprint:sha-256:<base64url thumbprint>
//
//  RFC 7638 §3.2: the thumbprint input is the JWK's REQUIRED members only
//  (for EC: crv, kty, x, y), lexicographically ordered, no whitespace:
//
//      {"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}
//
//  which is exactly the JCS form of that four-member object. x and y are the
//  32-byte big-endian affine coordinates, unpadded base64url (RFC 7518 §6.2.1),
//  so every P-256 key has exactly one JWK and one key id.
//
//  Binding proves consistency, not trust: the key id identifies a key, not
//  an issuer. Mapping a key id to a trusted issuer is the Phase 4 trust store.
// ============================================================================

use crate::canonical::jcs;
use crate::encoding::{b64url_decode, b64url_encode};
use crate::error::Error;
use crate::hash::sha256;
use crate::record::JwkPublicKey;
use p256::ecdsa::VerifyingKey;
use p256::elliptic_curve::sec1::EncodedPoint;

/// The RFC 9278 URN prefix of a SHA-256 JWK thumbprint.
pub const KEY_ID_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";

/// Byte length of a P-256 affine coordinate.
const COORD_LEN: usize = 32;

impl JwkPublicKey {
    /// The JWK of a P-256 verifying key: `kty` `EC`, `crv` `P-256`, and the
    /// 32-byte big-endian affine coordinates as unpadded base64url.
    // Cannot panic (plan §5.8): see the `unreachable!` arm below.
    #[allow(clippy::unreachable)]
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        let point = key.to_encoded_point(false);
        let (x, y) = match (point.x(), point.y()) {
            (Some(x), Some(y)) => (x, y),
            // An uncompressed encoding of a VerifyingKey (never the identity)
            // always has both coordinates.
            _ => unreachable!("uncompressed P-256 point without coordinates"),
        };
        JwkPublicKey {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: b64url_encode(x),
            y: b64url_encode(y),
        }
    }

    /// Parse this JWK back into a verifying key. Fails unless it is an EC
    /// P-256 key whose coordinates are exactly 32 bytes each (canonical
    /// base64url) and name a point on the curve.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, Error> {
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(Error::InvalidInput(format!(
                "JWK must be kty EC / crv P-256, got {} / {}",
                self.kty, self.crv
            )));
        }
        let coord = |name: &str, text: &str| -> Result<Vec<u8>, Error> {
            let bytes = b64url_decode(text)?;
            if bytes.len() != COORD_LEN {
                return Err(Error::InvalidInput(format!(
                    "JWK {name} must be {COORD_LEN} bytes, got {}",
                    bytes.len()
                )));
            }
            Ok(bytes)
        };
        let (x, y) = (coord("x", &self.x)?, coord("y", &self.y)?);
        let point = EncodedPoint::<p256::NistP256>::from_affine_coordinates(
            x.as_slice().into(),
            y.as_slice().into(),
            false,
        );
        VerifyingKey::from_encoded_point(&point)
            .map_err(|_| Error::InvalidInput("JWK x/y is not a point on P-256".into()))
    }

    /// The RFC 7638 SHA-256 thumbprint (unpadded base64url, 43 characters)
    /// of this JWK's required members, taken as they stand.
    pub fn thumbprint(&self) -> String {
        let members = serde_json::json!({
            "crv": self.crv,
            "kty": self.kty,
            "x": self.x,
            "y": self.y,
        });
        b64url_encode(&sha256(jcs(&members).as_bytes()))
    }

    /// This JWK's key id: [`KEY_ID_PREFIX`] followed by its thumbprint.
    pub fn key_id(&self) -> String {
        format!("{KEY_ID_PREFIX}{}", self.thumbprint())
    }
}

/// The key id of a verifying key (the key id of its JWK).
pub fn key_id(key: &VerifyingKey) -> String {
    JwkPublicKey::from_verifying_key(key).key_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(label: &[u8]) -> p256::ecdsa::SigningKey {
        crate::sign::signing_key_from_secret(&sha256(label)).unwrap()
    }

    // Known answers computed independently with Python `cryptography` +
    // hashlib (the RFC 7638 construction written by hand, no project code).
    const VECTOR_X: &str = "yRw99YmqYhAQER8UMKILOv-OFDLjl9n5E-SckLlV318";
    const VECTOR_Y: &str = "BCdTbjkziAfvOeGj-1v8vO2OqdV0_zX1ZWJLA43GxOY";
    const VECTOR_KID: &str =
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:HyoPYysSFOQ5d6x64H8_pHddcHp7E91G5SZbdiaeWJg";

    #[test]
    fn jwk_and_key_id_known_answers() {
        let k = key(b"khalm v0.1 test-vector signing key");
        let jwk = JwkPublicKey::from_verifying_key(k.verifying_key());
        assert_eq!((jwk.kty.as_str(), jwk.crv.as_str()), ("EC", "P-256"));
        assert_eq!((jwk.x.as_str(), jwk.y.as_str()), (VECTOR_X, VECTOR_Y));
        assert_eq!(jwk.key_id(), VECTOR_KID);
        assert_eq!(key_id(k.verifying_key()), VECTOR_KID);
        assert_eq!(jwk.thumbprint().len(), 43);
    }

    #[test]
    fn jwk_round_trips_to_the_same_key() {
        for label in [&b"a"[..], b"b", b"c"] {
            let k = key(label);
            let jwk = JwkPublicKey::from_verifying_key(k.verifying_key());
            assert_eq!(&jwk.to_verifying_key().unwrap(), k.verifying_key());
        }
    }

    #[test]
    fn distinct_keys_have_distinct_ids() {
        assert_ne!(key_id(key(b"a").verifying_key()), key_id(key(b"b").verifying_key()));
    }

    #[test]
    fn malformed_jwks_are_rejected() {
        let good = JwkPublicKey::from_verifying_key(key(b"a").verifying_key());
        let mut cases = Vec::new();
        let mut j = good.clone();
        j.kty = "RSA".into();
        cases.push(j);
        let mut j = good.clone();
        j.crv = "P-384".into();
        cases.push(j);
        let mut j = good.clone();
        j.x = b64url_encode(&[1u8; 31]); // short coordinate
        cases.push(j);
        let mut j = good.clone();
        j.y = format!("{}=", good.y); // padding is not canonical base64url
        cases.push(j);
        let mut j = good.clone();
        j.y = good.x.clone(); // (x, x) is not on the curve
        cases.push(j);
        for j in cases {
            assert!(j.to_verifying_key().is_err(), "{j:?}");
        }
    }
}
