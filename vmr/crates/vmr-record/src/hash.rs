//! SHA-256 helpers and the `sha256:<hex>` hash-string form.
// ============================================================================
//  hash.rs — SHA-256 wrapper (TASKS 3.1)
//
//  Audited primitive (sha2 crate). Every hash string in the record uses
//  the `sha256:<lowercase hex>` form defined here.
// ============================================================================

use sha2::{Digest, Sha256};

/// Length of a SHA-256 digest in bytes.
pub const DIGEST_LEN: usize = 32;

/// Compute the SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut buf = [0u8; DIGEST_LEN];
    buf.copy_from_slice(&out);
    buf
}

/// The record's hash string form: `sha256:<lowercase hex>`.
pub fn format_hash(digest: &[u8]) -> String {
    format!("sha256:{}", hex::encode(digest))
}

/// Parse a `sha256:<hex>` string back into a digest.
pub fn parse_hash(text: &str) -> Result<[u8; DIGEST_LEN], crate::error::Error> {
    let hex_part = text
        .strip_prefix("sha256:")
        .ok_or_else(|| crate::error::Error::InvalidInput(format!("not a sha256: hash: {text}")))?;
    let bytes = hex::decode(hex_part)
        .map_err(|e| crate::error::Error::InvalidInput(format!("bad hex: {e}")))?;
    let mut buf = [0u8; DIGEST_LEN];
    if bytes.len() != DIGEST_LEN {
        return Err(crate::error::Error::InvalidInput(format!(
            "sha256 hash must be {DIGEST_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    buf.copy_from_slice(&bytes);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST SHA-256 known-answer vectors.
    #[test]
    fn nist_vectors() {
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn format_parse_round_trip() {
        let h = sha256(b"khalm-tlm");
        let s = format_hash(&h);
        assert!(s.starts_with("sha256:"));
        assert_eq!(parse_hash(&s).unwrap(), h);
        assert!(parse_hash("md5:abcd").is_err());
        assert!(parse_hash("sha256:abcd").is_err());
    }
}
