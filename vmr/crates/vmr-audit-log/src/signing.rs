//! The signed-document construction of the audit-log format
//! (`specs/audit-log-format-v0.1.md` §3): the checkpoint's, and any document
//! of another format that adopts that section (the enforcer's bundle and
//! export token do).
// ============================================================================
//  signing.rs — one signature construction, one check order.
//
//  What is signed is the DOCUMENT AS RECEIVED with its top-level `signature`
//  member removed, canonicalised with JCS (RFC 8785) — never a
//  re-serialisation of a typed model, as vmr-policy signs a pack. The
//  algorithm is ES256, the signature the raw 64-byte low-s `r ‖ s`, the key
//  id an RFC 7638 thumbprint. Everything cryptographic comes from
//  vmr-record (Doctrine Refusal 4): this module implements none of it again.
// ============================================================================

use p256::ecdsa::{SigningKey, VerifyingKey};
use serde_json::{json, Value};
use vmr_record::canonical::jcs;
use vmr_record::hash::{format_hash, sha256};
use vmr_record::record::SignatureSection;

/// The bytes an author signs: the document with `/signature` removed, in its
/// JCS canonical form.
pub fn signed_payload(document: &Value) -> String {
    let mut value = document.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("signature");
    }
    jcs(&value)
}

/// `sha256:` + the hex of the SHA-256 of [`signed_payload`]. Defined for every
/// document, signed or not; names the content independently of its layout.
pub fn payload_hash(document: &Value) -> String {
    format_hash(&sha256(signed_payload(document).as_bytes()))
}

/// Add a `signature` section to `document`, signing [`signed_payload`] with
/// `key` (ES256, low-s). The document must be a JSON object without a
/// `signature` member; a non-object is returned unchanged (callers build
/// objects).
pub fn sign_document(key: &SigningKey, document: &Value) -> Result<Value, p256::ecdsa::Error> {
    let payload = signed_payload(document);
    let sig = vmr_record::sign::sign(key, payload.as_bytes())?;
    let section = json!({
        "algorithm": "ES256",
        "signature": SignatureSection::signature_field(&sig),
        "signed_payload_hash": format_hash(&sha256(payload.as_bytes())),
        "signing_key_id": vmr_record::jwk::key_id(key.verifying_key()),
    });
    let mut out = document.clone();
    if let Some(object) = out.as_object_mut() {
        object.insert("signature".to_string(), section);
    }
    Ok(out)
}

/// The step of the §3 signature check that failed. A caller maps each to the
/// refusal id its document uses (`checkpoint.signature_section`,
/// `export_token.key_unknown`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigFail {
    /// There is no `signature` object.
    NoSection,
    /// `algorithm` is not `ES256`.
    Algorithm,
    /// `signed_payload_hash` is not the recomputed payload hash.
    HashMismatch,
    /// `signature` is missing, not a `base64url:` string, or not 64 bytes.
    Encoding,
    /// `signing_key_id` is not the checked key's id.
    KeyId,
    /// The signature does not verify under the key (or is high-s).
    Invalid,
}

/// The key-free part of §3's signature check: the `signature` section is
/// present, `algorithm` is `ES256`, `signed_payload_hash` is the recomputed
/// payload hash, and `signature` decodes to 64 bytes. Returns the section's
/// `signing_key_id` so the caller can find the key to verify under (the
/// token's step 5 before step 6).
pub fn section_signing_key_id(document: &Value) -> Result<String, SigFail> {
    let section = document.get("signature").and_then(Value::as_object).ok_or(SigFail::NoSection)?;
    let field = |name: &str| section.get(name).and_then(Value::as_str);
    if field("algorithm") != Some("ES256") {
        return Err(SigFail::Algorithm);
    }
    let payload = signed_payload(document);
    let recomputed = format_hash(&sha256(payload.as_bytes()));
    if field("signed_payload_hash") != Some(recomputed.as_str()) {
        return Err(SigFail::HashMismatch);
    }
    let sig_text = field("signature").ok_or(SigFail::Encoding)?;
    let sig_b64 = sig_text.strip_prefix("base64url:").ok_or(SigFail::Encoding)?;
    vmr_record::sign::signature_from_b64url(sig_b64).map_err(|_| SigFail::Encoding)?;
    field("signing_key_id").map(str::to_string).ok_or(SigFail::Encoding)
}

/// Check `document`'s signature under `key`, in the order of §3. `Ok(())` when
/// the holder of `key` signed exactly these bytes.
///
/// The first four failures (`NoSection`, `Algorithm`, `HashMismatch`,
/// `Encoding`) are a document's "signature section" refusal; `KeyId` is its
/// "wrong key" / "key unknown"; `Invalid` its "signature invalid".
pub fn check_signature(document: &Value, key: &VerifyingKey) -> Result<(), SigFail> {
    let section = document.get("signature").and_then(Value::as_object).ok_or(SigFail::NoSection)?;
    let field = |name: &str| section.get(name).and_then(Value::as_str);

    if field("algorithm") != Some("ES256") {
        return Err(SigFail::Algorithm);
    }
    let payload = signed_payload(document);
    let recomputed = format_hash(&sha256(payload.as_bytes()));
    if field("signed_payload_hash") != Some(recomputed.as_str()) {
        return Err(SigFail::HashMismatch);
    }
    let sig_text = field("signature").ok_or(SigFail::Encoding)?;
    let sig_b64 = sig_text.strip_prefix("base64url:").ok_or(SigFail::Encoding)?;
    let signature = vmr_record::sign::signature_from_b64url(sig_b64).map_err(|_| SigFail::Encoding)?;

    if field("signing_key_id") != Some(vmr_record::jwk::key_id(key).as_str()) {
        return Err(SigFail::KeyId);
    }
    vmr_record::sign::verify(key, payload.as_bytes(), &signature).map_err(|_| SigFail::Invalid)
}
