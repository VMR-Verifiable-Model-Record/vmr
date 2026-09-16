//! Base64url (RFC 4648 §5, unpadded) encoding helpers.
// ============================================================================
//  encoding.rs — base64url (RFC 4648 §5, no padding)
//
//  Serialization aid, not a cryptographic primitive. Used for the
//  "base64url:..." strings in the signature section and for test vectors.
// ============================================================================

use crate::error::Error;

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode `data` as unpadded base64url.
// Cannot panic (plan §5.8): `chunks(3)` never yields an empty chunk, and every
// ALPHABET index is masked to 0..=63 of a 64-byte table.
#[allow(clippy::indexing_slicing)]
pub fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

fn value_of(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decode unpadded base64url text.
pub fn b64url_decode(text: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in text.as_bytes() {
        let v = value_of(c)
            .ok_or_else(|| Error::Base64Url(format!("invalid character {c:#x}")))?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u32 << bits).wrapping_sub(1);
        }
    }
    if bits >= 6 || (acc & ((1u32 << bits).wrapping_sub(1))) != 0 {
        return Err(Error::Base64Url("trailing bits".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for data in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0u8, 1, 2, 3, 254, 255],
        ] {
            let enc = b64url_encode(data);
            assert!(!enc.contains('='), "no padding allowed");
            assert_eq!(b64url_decode(&enc).unwrap(), data);
        }
    }

    #[test]
    fn rfc4648_vectors() {
        assert_eq!(b64url_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(b64url_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(b64url_decode("Zm9vYmFy=").is_err());
        assert!(b64url_decode("Zm9v+YmFy").is_err());
        assert!(b64url_decode("Zm9").is_err());
    }
}
