//! ES256: ECDSA P-256 over SHA-256, sign and verify.
// ============================================================================
//  sign.rs — ES256: ECDSA P-256 over SHA-256 (TASKS 3.4)
//
//  Audited primitive (p256 crate, Doctrine Refusal 4). ES256 signs the
//  SHA-256 DIGEST of the payload (prehash), matching the COSE ES256
//  definition. Test keys are derived from fixed bytes — never generated
//  here at runtime, so test vectors are reproducible.
// ============================================================================

use crate::hash::sha256;
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// A fixed-byte signing key (deterministic tests/vectors only).
pub fn signing_key_from_secret(bytes: &[u8; 32]) -> Result<SigningKey, p256::ecdsa::Error> {
    SigningKey::from_bytes(bytes.into())
}

/// Sign `data` with ES256 (ECDSA P-256 over the SHA-256 digest).
///
/// The result is always low-s (`s <= n/2`, the BIP 62 normalization): ECDSA
/// accepts both `(r, s)` and `(r, n - s)`, so without a canonical choice
/// anyone could turn one signed record into a second, byte-different one
/// that verifies equally (QA P3-04). Normalizing keeps RFC 6979 determinism.
pub fn sign(key: &SigningKey, data: &[u8]) -> Result<Signature, p256::ecdsa::Error> {
    let sig: Signature = key.sign_prehash(&sha256(data))?;
    Ok(sig.normalize_s().unwrap_or(sig))
}

/// Verify an ES256 signature over `data`. A high-s signature is rejected
/// even when it satisfies the ECDSA equation: only the low-s form of a
/// signature is valid, so a signed object has exactly one valid encoding.
pub fn verify(
    key: &VerifyingKey,
    data: &[u8],
    signature: &Signature,
) -> Result<(), crate::error::Error> {
    if is_high_s(signature) {
        return Err(crate::error::Error::InvalidInput(HIGH_S_MESSAGE.into()));
    }
    Ok(verify_ecdsa(key, data, signature)?)
}

/// The message [`verify`] rejects a high-s signature with.
pub(crate) const HIGH_S_MESSAGE: &str = "non-canonical ECDSA signature: s is in the upper half \
     of the group order (high-s); only the low-s form is valid";

/// Whether `signature` is high-s (`s > n/2`): the non-canonical twin of a
/// valid low-s signature, which [`verify`] rejects (QA P3-04).
pub fn is_high_s(signature: &Signature) -> bool {
    signature.normalize_s().is_some()
}

/// The ECDSA equation alone, over the SHA-256 digest of `data`. It accepts
/// the high-s twin, so it stays crate-private: every caller must reject
/// high-s first, as [`verify`] and `Record::check_integrity` do.
pub(crate) fn verify_ecdsa(
    key: &VerifyingKey,
    data: &[u8],
    signature: &Signature,
) -> Result<(), p256::ecdsa::Error> {
    key.verify_prehash(&sha256(data), signature)
}

/// Length of an ES256 signature: `r || s`, 32 bytes each, big-endian.
pub const SIGNATURE_LEN: usize = 64;

/// Encode a signature in its one wire form: the 64-byte `r || s`
/// (RFC 9052 §8.1 for COSE, RFC 7518 §3.4 for JOSE) as unpadded base64url —
/// always 86 characters. Never DER (QA P3-02).
pub fn signature_to_b64url(sig: &Signature) -> String {
    crate::encoding::b64url_encode(&sig.to_bytes())
}

/// Parse a signature from its raw `r || s` bytes; anything but exactly
/// [`SIGNATURE_LEN`] bytes (a DER encoding included) is rejected.
pub fn signature_from_bytes(bytes: &[u8]) -> Result<Signature, crate::error::Error> {
    if bytes.len() != SIGNATURE_LEN {
        return Err(crate::error::Error::InvalidInput(format!(
            "ES256 signature must be {SIGNATURE_LEN} bytes (raw r||s), got {}",
            bytes.len()
        )));
    }
    Signature::from_slice(bytes).map_err(Into::into)
}

/// Decode the base64url text of a signature (without the record's
/// `base64url:` prefix): exactly 64 raw bytes, see [`signature_from_bytes`].
pub fn signature_from_b64url(
    text: &str,
) -> Result<Signature, crate::error::Error> {
    signature_from_bytes(&crate::encoding::b64url_decode(text)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> SigningKey {
        signing_key_from_secret(&sha256(b"khalm-vmr test key v0.1")).unwrap()
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = fixed_key();
        let sig = sign(&key, b"passport payload").unwrap();
        verify(key.verifying_key(), b"passport payload", &sig).unwrap();
    }

    #[test]
    fn tampered_payload_fails() {
        let key = fixed_key();
        let sig = sign(&key, b"passport payload").unwrap();
        assert!(verify(key.verifying_key(), b"passport payload!", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key = fixed_key();
        let other = signing_key_from_secret(&sha256(b"a different key")).unwrap();
        let sig = sign(&key, b"data").unwrap();
        assert!(verify(other.verifying_key(), b"data", &sig).is_err());
    }

    #[test]
    fn b64url_round_trip() {
        let key = fixed_key();
        let sig = sign(&key, b"x").unwrap();
        let text = signature_to_b64url(&sig);
        let decoded = signature_from_b64url(&text).unwrap();
        assert_eq!(decoded, sig);
        assert!(signature_from_b64url("not base64!").is_err());
    }

    #[test]
    fn b64url_form_is_raw_r_s_only() {
        // QA P3-02: 64 raw bytes (86 characters), never DER.
        let key = fixed_key();
        let sig = sign(&key, b"x").unwrap();
        let text = signature_to_b64url(&sig);
        assert_eq!(text.len(), 86);
        assert_eq!(crate::encoding::b64url_decode(&text).unwrap(), sig.to_bytes().to_vec());
        let der = crate::encoding::b64url_encode(sig.to_der().as_bytes());
        assert!(signature_from_b64url(&der).is_err(), "DER is not accepted");
        // 63 and 65 bytes are rejected too.
        let raw = sig.to_bytes();
        assert!(signature_from_b64url(&crate::encoding::b64url_encode(&raw[..63])).is_err());
        let mut long = raw.to_vec();
        long.push(0);
        assert!(signature_from_b64url(&crate::encoding::b64url_encode(&long)).is_err());
    }

    /// The other valid ECDSA signature for the same message: (r, n - s).
    fn twin(sig: &Signature) -> Signature {
        Signature::from_scalars(*sig.r(), -*sig.s()).unwrap()
    }

    #[test]
    fn signing_emits_low_s() {
        // QA P3-04: RFC 6979 alone yields a high s for about half of all
        // messages; every signature this crate produces must be low-s.
        let key = fixed_key();
        for i in 0..64u32 {
            let sig = sign(&key, &i.to_le_bytes()).unwrap();
            assert!(sig.normalize_s().is_none(), "message {i}: high-s signature emitted");
        }
    }

    #[test]
    fn verify_rejects_the_high_s_twin() {
        // (r, s) and (r, n - s) both satisfy the ECDSA equation; accepting
        // both lets anyone mint a second, byte-different valid signature
        // without the key. Only the low-s form verifies.
        let key = fixed_key();
        for i in 0..8u32 {
            let msg = i.to_le_bytes();
            let sig = sign(&key, &msg).unwrap();
            let low = sig.normalize_s().unwrap_or(sig);
            let high = twin(&low);
            assert!(high.normalize_s().is_some(), "twin is high-s");
            verify(key.verifying_key(), &msg, &low).unwrap();
            let err = verify(key.verifying_key(), &msg, &high).unwrap_err();
            assert!(err.to_string().contains("high-s"), "{err}");
        }
    }

    #[test]
    fn determinism() {
        // ECDSA signature is deterministic (RFC 6979 in p256's default signer).
        let key = fixed_key();
        let s1 = signature_to_b64url(&sign(&key, b"same data").unwrap());
        let s2 = signature_to_b64url(&sign(&key, b"same data").unwrap());
        assert_eq!(s1, s2);
    }
}
