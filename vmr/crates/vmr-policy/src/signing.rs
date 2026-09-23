//! The bytes an authority signs, making its signature and checking it
//! (P6-7, P6-8).
// ============================================================================
//  signing.rs — making and checking a pack signature
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
//
//  Making a signature lives here beside checking one, over the same
//  `signed_payload`: the two cannot drift apart, and the crate that defines
//  the format is the crate that can produce a pack in it. `sign_pack` holds
//  no notion of a privileged authority - any P-256 key signs any pack, and
//  whose key may speak for which authority stays a trust decision its caller
//  makes (the reference CLI's is a trust store's `policy_authorities`).
// ============================================================================

use crate::error::Error;
use crate::pack::{PackSignature, PolicyPack};
use crate::schema::quote;
use p256::ecdsa::{SigningKey, VerifyingKey};
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

/// Sign `document` as the authority that authors it, and return the
/// `signature` section to put back into it (format §4).
///
/// What is signed is [`signed_payload`]: the document with any top-level
/// `signature` removed, in its JCS form. A pack that already carries a
/// section is therefore signed over exactly the bytes an unsigned copy of it
/// would be, so replacing a signature never changes the payload hash.
///
/// Everything cryptographic is `vmr-record`'s, as the check is (P6-7): ES256
/// over the payload's bytes with RFC 6979 and the low-s rule, the
/// `base64url:` encoding of the 64-byte `r ‖ s`, and the RFC 7638 key id.
/// Because RFC 6979 makes ES256 deterministic, the same document and key
/// give the same section on every machine and every run.
///
/// The section this returns is what [`verify_pack_signature`] accepts under
/// `key`'s public half, and nothing else here decides anything: WHICH
/// authority may sign a pack, and whether this key is that authority's, is
/// the caller's trust decision, held wherever it keeps its trust. Any
/// authority's key signs any pack — the format has no privileged signer, and
/// neither has this function.
pub fn sign_pack(document: &Value, key: &SigningKey) -> Result<PackSignature, Error> {
    let payload = signed_payload(document);
    let signature = vmr_record::sign::sign(key, payload.as_bytes())
        .map_err(|e| Error::PackSignature(format!("the pack could not be signed: {e}")))?;
    Ok(PackSignature {
        algorithm: "ES256".to_string(),
        signature: format!("base64url:{}", vmr_record::sign::signature_to_b64url(&signature)),
        signed_payload_hash: format_hash(&sha256(payload.as_bytes())),
        signing_key_id: vmr_record::jwk::key_id(key.verifying_key()),
    })
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
