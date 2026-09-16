//! The bytes an authority signs, and checking its signature (P6-7, P6-8).
// ============================================================================
//  signing.rs — pack signature verification
//
//  A pack is signed by the authority that authors it. What is signed is the
//  DOCUMENT AS RECEIVED with its `signature` member removed, canonicalised
//  with JCS (RFC 8785) - never a re-serialisation of the Rust structs
//  (P6-8). A member this build does not model could otherwise change the
//  bytes an authority signed; and since the loader refuses unknown members
//  (P6-9), the two can only ever differ for a pack this build would not
//  accept anyway. Hashing the document keeps that property explicit instead
//  of accidental.
//
//  Everything cryptographic comes from `vmr-record` (P6-7): JCS, SHA-256,
//  the `sha256:` string form, base64url, the 64-byte `r ‖ s` encoding, the
//  low-s rule and RFC 7638 key ids. This crate implements none of it again.
//
//  How a pack signature differs from a record signature: a record signs
//  the COSE Sig_structure over its canonical payload (spec §4.1); a pack has
//  no COSE envelope in v0.1, so the signed bytes are the JCS payload itself.
//  The algorithm (ES256), the signature encoding, the `signed_payload_hash`
//  form and the key id are identical, so one key management serves both.
// ============================================================================

use crate::error::Error;
use crate::pack::{PackSignature, PolicyPack};
use crate::schema::quote;
use p256::ecdsa::VerifyingKey;
use serde_json::Value;
use vmr_record::canonical::jcs;
use vmr_record::hash::{format_hash, sha256};

/// The bytes an authority signs: the document with `/signature` removed, in
/// its JCS canonical form.
pub fn signed_payload(document: &Value) -> String {
    let mut value = document.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("signature");
    }
    jcs(&value)
}

/// `sha256:` + the hex of the SHA-256 of [`signed_payload`].
pub fn payload_hash(document: &Value) -> String {
    format_hash(&sha256(signed_payload(document).as_bytes()))
}

/// Verify a pack's signature under `key`.
///
/// In order, each with its own message:
///
/// 1. the pack carries a `signature` section;
/// 2. `algorithm` is `ES256`;
/// 3. `signing_key_id` is `key`'s RFC 7638 key id — a pack is verified
///    against the key it names, never against whichever key was handed in;
/// 4. `signed_payload_hash` is the recomputed hash of [`signed_payload`];
/// 5. the signature decodes as 64 bytes `r ‖ s`;
/// 6. it verifies under `key`, low-s only (`vmr_record::sign::verify`).
///
/// Which key an authority is allowed to use is the caller's decision, held
/// wherever it keeps its trust — this function answers only "did the holder
/// of this key sign these bytes", exactly as `Record::verify_signature`
/// answers integrity and not trust.
pub fn verify_pack_signature(
    pack: &PolicyPack,
    document: &Value,
    key: &VerifyingKey,
) -> Result<(), Error> {
    let section: &PackSignature = pack.signature.as_ref().ok_or(Error::PackUnsigned)?;
    if section.algorithm != "ES256" {
        return Err(Error::PackSignature(format!(
            "algorithm {} is not ES256",
            quote(&section.algorithm)
        )));
    }
    let expected_key_id = vmr_record::jwk::key_id(key);
    if section.signing_key_id != expected_key_id {
        return Err(Error::PackSignature(format!(
            "the pack names signing_key_id {}, not the key it is checked against ({})",
            quote(&section.signing_key_id),
            quote(&expected_key_id)
        )));
    }
    let payload = signed_payload(document);
    let recomputed = format_hash(&sha256(payload.as_bytes()));
    if section.signed_payload_hash != recomputed {
        // Its own variant and refusal id: this step needs no key
        // (docs/dev/task-6.16.md A16-22), and its message is unchanged.
        return Err(Error::PayloadHashMismatch { stated: section.signed_payload_hash.clone(), recomputed });
    }
    let text = section.signature.strip_prefix("base64url:").ok_or_else(|| {
        Error::PackSignature(format!(
            "signature {} does not start with \"base64url:\"",
            quote(&section.signature)
        ))
    })?;
    let signature = vmr_record::sign::signature_from_b64url(text)
        .map_err(|e| Error::PackSignature(format!("signature encoding: {e}")))?;
    vmr_record::sign::verify(key, payload.as_bytes(), &signature)
        .map_err(|e| Error::PackSignature(e.to_string()))
}
