//! COSE_Sign1 envelope: encode, decode, and verify over ES256.
// ============================================================================
//  cose.rs — COSE_Sign1 envelope (TASKS 3.5)
//
//  The record's distribution format. The payload is the canonical signed
//  payload (JCS of the record without its `signature` section); the
//  protected header carries alg=ES256 and the key id. All crypto goes
//  through coset + p256 (audited libraries).
//
//  Strict decoding (Phase 4 task 4.0c, spec §4.4, decision D4 (f)): a v0.1
//  record has exactly ONE COSE form — the untagged array with the
//  protected header {1: -7, 4: kid} in deterministic encoding, the empty
//  unprotected map, the canonical signed payload and the 64-byte r||s.
//  `decode_record` rejects everything else with a typed reason, in the
//  order of the verifier's checks 3c-8c (docs/dev/phase4.md §5.2).
//  The envelope's CBOR (spec §4.4; the reviewer's decision, 2026-09-13):
//  before any decoder sees it, `check_envelope_cbor` reads the envelope
//  head by head and refuses anything but one data item of the envelope's
//  CBOR subset, at most MAX_ENVELOPE_DEPTH (16) levels deep, with nothing
//  after it. Which envelopes fail check 3c therefore follows from the spec
//  alone, not from a decoder's limits (ciborium's recursion limit is 256),
//  and ciborium only ever decodes such an item. coset rejects duplicate
//  header labels. Pinned by tests/cose_strict_tests.rs.
//
//  Which check a failure belongs to (QA P4-02, spec §6.2): 3c judges only
//  the envelope's outer shape - one CBOR item, an array [bstr, map,
//  bstr / nil, bstr], nothing after it. The envelope is therefore decoded
//  generically first, and only then is the protected bstr's content decoded
//  as a COSE header: every failure inside it is 4c (ProtectedHeader), and
//  anything inside the unprotected map is 5c (UnprotectedHeader). Letting
//  coset decode the whole COSE_Sign1 at once filed a malformed protected
//  header (a tag in place of the kid's bstr, an empty kid) under 3c.
// ============================================================================

use crate::error::Error;
use crate::hash::{format_hash, sha256};
use crate::record::{Record, SignatureSection, UnsignedRecord};
use coset::cbor::value::Value;
use coset::iana::Algorithm;
use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};

/// Why a byte string is not the COSE form of a v0.1 record. The variants
/// are in the order [`decode_record`] checks them.
#[derive(Debug)]
pub enum CoseDecodeError {
    /// The envelope starts with a CBOR tag (COSE_Sign1's own is tag 18);
    /// v0.1 envelopes are untagged (spec §4.4).
    Tagged,
    /// The bytes are not one CBOR data item of the envelope's subset, nesting
    /// at most [`MAX_ENVELOPE_DEPTH`] levels, with nothing after it (spec
    /// §4.4): truncated, followed by other data, holding an item outside the
    /// subset, or nested too deep.
    Cbor(String),
    /// The CBOR item is not an array `[protected: bstr, unprotected: map,
    /// payload: bstr / nil, signature: bstr]` - the outer shape only; what
    /// each element holds is judged by the later variants.
    NotSign1(String),
    /// The protected header is not exactly `{1: -7 (ES256), 4: kid}` in
    /// deterministic encoding with a non-empty UTF-8 `kid` (spec §4.1,
    /// §4.4) - including a protected bstr whose content is not a
    /// well-formed COSE header map at all.
    ProtectedHeader(String),
    /// The unprotected header is not the empty map (spec §4.4), whatever
    /// the map holds.
    UnprotectedHeader,
    /// The signature is not 64 bytes `r ‖ s` with `r`, `s` in `1 ..= n−1`
    /// (spec §4.2).
    SignatureEncoding(Error),
    /// The payload is nil (detached); v0.1 envelopes carry it.
    NoPayload,
    /// The payload is not a record under the JSON rules of spec §2.
    Payload(Error),
    /// The payload is a record, but not its canonical signed payload
    /// (spec §3): another encoding, or a `signature` member.
    PayloadNotCanonical,
    /// The envelope is not byte-identical to the canonical encoding of the
    /// record it carries (e.g. a non-preferred CBOR length head).
    NotCanonical,
}

const PAYLOAD_NOT_CANONICAL: &str =
    "COSE_Sign1 payload is not the canonical (JCS, signature-free) signed payload";
const NOT_CANONICAL: &str = "COSE_Sign1 envelope is not the canonical encoding of the record it \
     carries (untagged, deterministic CBOR, protected {1: -7, 4: kid}, empty unprotected map)";

impl std::fmt::Display for CoseDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoseDecodeError::Tagged => write!(
                f,
                "cose: the COSE_Sign1 envelope is tagged; v0.1 envelopes are untagged \
                 (no CBOR tag 18 or any other tag)"
            ),
            CoseDecodeError::Cbor(m) | CoseDecodeError::NotSign1(m) => write!(f, "cose: {m}"),
            CoseDecodeError::ProtectedHeader(d) => {
                write!(f, "invalid input: COSE_Sign1 protected header {d}")
            }
            CoseDecodeError::UnprotectedHeader => write!(
                f,
                "invalid input: COSE_Sign1 unprotected header must be the empty map"
            ),
            CoseDecodeError::SignatureEncoding(e) | CoseDecodeError::Payload(e) => write!(f, "{e}"),
            CoseDecodeError::NoPayload => write!(f, "invalid input: COSE_Sign1 has no payload"),
            CoseDecodeError::PayloadNotCanonical => {
                write!(f, "invalid input: {PAYLOAD_NOT_CANONICAL}")
            }
            CoseDecodeError::NotCanonical => write!(f, "invalid input: {NOT_CANONICAL}"),
        }
    }
}

impl std::error::Error for CoseDecodeError {}

impl From<CoseDecodeError> for Error {
    fn from(e: CoseDecodeError) -> Self {
        match e {
            CoseDecodeError::Cbor(m) | CoseDecodeError::NotSign1(m) => Error::Cose(m),
            CoseDecodeError::SignatureEncoding(e) | CoseDecodeError::Payload(e) => e,
            CoseDecodeError::PayloadNotCanonical => Error::InvalidInput(PAYLOAD_NOT_CANONICAL.into()),
            CoseDecodeError::NotCanonical => Error::InvalidInput(NOT_CANONICAL.into()),
            other @ CoseDecodeError::Tagged => {
                // Error::Cose adds its own "cose: " prefix.
                let text = other.to_string();
                Error::Cose(text.trim_start_matches("cose: ").to_string())
            }
            other => {
                let text = other.to_string();
                Error::InvalidInput(text.trim_start_matches("invalid input: ").to_string())
            }
        }
    }
}

/// The deterministic encoding of the only protected header a v0.1 envelope
/// may carry: `{1: -7, 4: kid}` — for a v0.1 key id, `a2 01 26 04 58 58`
/// followed by the 88 kid bytes (spec §4.1).
fn canonical_protected_header(kid: &[u8]) -> Result<Vec<u8>, coset::CoseError> {
    HeaderBuilder::new()
        .algorithm(Algorithm::ES256)
        .key_id(kid.to_vec())
        .build()
        .to_vec()
}

/// The deepest a v0.1 COSE envelope's CBOR may nest (spec §4.4): the
/// envelope's array is level 1, and an array or map is one level deeper than
/// the array or map holding it, as a key or as a value. Only arrays and maps
/// count: a tag is outside the subset, refused whatever its depth. The
/// canonical envelope nests two levels.
pub const MAX_ENVELOPE_DEPTH: usize = 16;

/// Why an item is refused by the envelope's CBOR subset (spec §4.4).
const OUTSIDE_SUBSET: &str = "outside the CBOR subset of a v0.1 envelope";

fn envelope_cbor_error(at: usize, what: std::fmt::Arguments<'_>) -> CoseDecodeError {
    CoseDecodeError::Cbor(format!("the envelope's CBOR, byte {at}: {what}"))
}

/// Check 3c's first reading of the envelope, before any CBOR decoder sees it
/// (spec §4.4): `bytes` must be exactly one CBOR data item of the envelope's
/// subset, nesting at most [`MAX_ENVELOPE_DEPTH`] levels.
///
/// The subset: unsigned and negative integers, byte strings, text strings
/// (UTF-8), arrays, maps and `null`, every argument (an integer's value, a
/// string's length, an array's or a map's count) immediate or in 1, 2 or 4
/// bytes. Outside it: every tag, every other simple value, floats, breaks,
/// indefinite lengths, 8-byte arguments and reserved additional information.
///
/// The walk reads item heads, and a text string's bytes for UTF-8, nothing
/// else. It never recurses: it keeps one count per open array or map, at
/// most `MAX_ENVELOPE_DEPTH` of them. It reads a head's argument only where
/// the input holds it and bounds every length and count by the bytes left
/// before using it, so it allocates nothing a head declares and cannot panic.
fn check_envelope_cbor(bytes: &[u8]) -> Result<(), CoseDecodeError> {
    // How many items each open array or map still holds, innermost last.
    let mut open: Vec<u64> = Vec::with_capacity(MAX_ENVELOPE_DEPTH);
    let mut pos = 0usize;
    loop {
        let at = pos;
        let Some(&initial) = bytes.get(pos) else {
            return Err(envelope_cbor_error(at, format_args!("the input ends where an item should start")));
        };
        pos += 1;
        let (major, info) = (initial >> 5, initial & 0x1f);
        if major == 6 {
            return Err(envelope_cbor_error(at, format_args!("a tag, {OUTSIDE_SUBSET}")));
        }
        if major == 7 && info != 22 {
            return Err(envelope_cbor_error(
                at,
                format_args!("a simple value, float or break other than null, {OUTSIDE_SUBSET}"),
            ));
        }
        let width = match info {
            0..=23 => 0,
            24 => 1,
            25 => 2,
            26 => 4,
            27 => return Err(envelope_cbor_error(at, format_args!("an 8-byte argument, {OUTSIDE_SUBSET}"))),
            31 => return Err(envelope_cbor_error(at, format_args!("an indefinite length, {OUTSIDE_SUBSET}"))),
            _ => {
                return Err(envelope_cbor_error(
                    at,
                    format_args!("reserved additional information {info}, not well-formed CBOR"),
                ))
            }
        };
        let Some(argument_bytes) = bytes.get(pos..).and_then(|rest| rest.get(..width)) else {
            return Err(envelope_cbor_error(at, format_args!("the input ends inside the item's head")));
        };
        pos += width;
        let argument = if width == 0 {
            u64::from(info)
        } else {
            argument_bytes.iter().fold(0u64, |value, &b| (value << 8) | u64::from(b))
        };
        let left = u64::try_from(bytes.len().saturating_sub(pos)).unwrap_or(u64::MAX);
        let items = match major {
            2 | 3 => {
                let content =
                    usize::try_from(argument).ok().and_then(|len| bytes.get(pos..).and_then(|rest| rest.get(..len)));
                let Some(content) = content else {
                    return Err(envelope_cbor_error(
                        at,
                        format_args!("a string of {argument} bytes, longer than the {left} bytes left"),
                    ));
                };
                if major == 3 && std::str::from_utf8(content).is_err() {
                    return Err(envelope_cbor_error(at, format_args!("a text string that is not UTF-8")));
                }
                pos += content.len();
                0
            }
            4 | 5 => {
                let level = open.len() + 1;
                if level > MAX_ENVELOPE_DEPTH {
                    return Err(envelope_cbor_error(
                        at,
                        format_args!("an array or map at level {level}; the envelope nests at most {MAX_ENVELOPE_DEPTH} levels"),
                    ));
                }
                // Every item takes at least one byte.
                let count = if major == 5 { argument.saturating_mul(2) } else { argument };
                if count > left {
                    return Err(envelope_cbor_error(
                        at,
                        format_args!("an array or map of {count} items, more than the {left} bytes left"),
                    ));
                }
                count
            }
            // An integer, or null.
            _ => 0,
        };
        if items > 0 {
            open.push(items);
            continue;
        }
        // The item is complete: count it in the arrays and maps it completes.
        loop {
            let Some(remaining) = open.last_mut() else {
                return if pos == bytes.len() {
                    Ok(())
                } else {
                    Err(envelope_cbor_error(pos, format_args!("data after the envelope's one item")))
                };
            };
            *remaining -= 1;
            if *remaining > 0 {
                break;
            }
            open.pop();
        }
    }
}

/// The four elements of a COSE_Sign1 array, checked for their CBOR types
/// only (check 3c).
struct Sign1Parts {
    protected: Vec<u8>,
    unprotected: Vec<(Value, Value)>,
    payload: Option<Vec<u8>>,
    signature: Vec<u8>,
}

/// Decode `bytes` as one generic CBOR item with nothing after it, and check
/// that it is an array `[bstr, map, bstr / nil, bstr]` (spec §6.2, 3c). The
/// content of each element is left to the later checks.
fn sign1_parts(bytes: &[u8]) -> Result<Sign1Parts, CoseDecodeError> {
    let mut rest = bytes;
    let item: Value = coset::cbor::de::from_reader(&mut rest)
        .map_err(|e| CoseDecodeError::Cbor(coset::CoseError::from(e).to_string()))?;
    if !rest.is_empty() {
        return Err(CoseDecodeError::Cbor(coset::CoseError::ExtraneousData.to_string()));
    }
    let not_sign1 =
        |what: &str| CoseDecodeError::NotSign1(format!("not a COSE_Sign1 array [bstr, map, bstr / nil, bstr]: {what}"));
    let Value::Array(items) = item else {
        return Err(not_sign1("not an array"));
    };
    let Ok([protected, unprotected, payload, signature]) = <[Value; 4]>::try_from(items) else {
        return Err(not_sign1("not 4 elements"));
    };
    let Value::Bytes(protected) = protected else {
        return Err(not_sign1("the protected header is not a byte string"));
    };
    let Value::Map(unprotected) = unprotected else {
        return Err(not_sign1("the unprotected header is not a map"));
    };
    let payload = match payload {
        Value::Bytes(b) => Some(b),
        Value::Null => None,
        _ => return Err(not_sign1("the payload is neither a byte string nor nil")),
    };
    let Value::Bytes(signature) = signature else {
        return Err(not_sign1("the signature is not a byte string"));
    };
    Ok(Sign1Parts { protected, unprotected, payload, signature })
}

/// Decode the COSE form of a v0.1 record, strictly (spec §4.4).
///
/// Accepts exactly the envelope [`Record::to_cose`] produces and rejects
/// anything else with the first failing reason, in this order: a tagged
/// envelope; bytes that are not one CBOR data item of the envelope's subset
/// within [`MAX_ENVELOPE_DEPTH`] levels (spec §4.4), or not an array
/// `[bstr, map, bstr / nil, bstr]`; a protected header whose content is not
/// `{1: -7, 4: kid}` in deterministic encoding with a non-empty UTF-8 kid
/// (whatever is wrong inside the protected bstr); a non-empty unprotected
/// header; a signature that is not 64 bytes `r ‖ s` in range; a missing
/// payload; a payload that is not a record, or not its canonical signed
/// payload; and finally an envelope that is not byte-identical to the
/// record's canonical encoding (which catches every other encoding choice,
/// e.g. non-preferred length heads).
///
/// Decoding checks the envelope, not the signature: the returned record
/// still has to be verified against a trusted key.
pub fn decode_record(bytes: &[u8]) -> Result<Record, CoseDecodeError> {
    // CBOR major type 6 (a tag) in the first byte: COSE_Sign1's tag 18 is
    // 0xd2. ciborium would otherwise skip tags when decoding structures.
    if bytes.first().is_some_and(|b| b >> 5 == 6) {
        return Err(CoseDecodeError::Tagged);
    }
    // 3c: the envelope's CBOR, read head by head before any decoder sees it
    // (the subset and the depth of spec §4.4); then the outer shape, decoded
    // generically.
    check_envelope_cbor(bytes)?;
    let parts = sign1_parts(bytes)?;

    // 4c: the protected bstr's content - a COSE header map, exactly
    // {1: -7, 4: kid}, deterministically encoded. Every failure to decode it
    // (not CBOR, not a map, a duplicate label, a tag or an empty bstr where
    // the kid belongs, ...) is a protected-header failure.
    let protected = coset::ProtectedHeader::from_cbor_bstr(Value::Bytes(parts.protected))
        .map_err(|e| CoseDecodeError::ProtectedHeader(format!("is not a well-formed COSE header map: {e}")))?;
    let header = &protected.header;
    if header.alg != Some(coset::RegisteredLabelWithPrivate::Assigned(Algorithm::ES256)) {
        return Err(CoseDecodeError::ProtectedHeader("alg is not ES256 (-7)".into()));
    }
    let only_alg_and_kid = header.crit.is_empty()
        && header.content_type.is_none()
        && header.iv.is_empty()
        && header.partial_iv.is_empty()
        && header.counter_signatures.is_empty()
        && header.rest.is_empty();
    if !only_alg_and_kid {
        return Err(CoseDecodeError::ProtectedHeader(
            "carries parameters other than alg (1) and kid (4)".into(),
        ));
    }
    if header.key_id.is_empty() {
        return Err(CoseDecodeError::ProtectedHeader("has no kid (4)".into()));
    }
    let expected = canonical_protected_header(&header.key_id)
        .map_err(|e| CoseDecodeError::ProtectedHeader(format!("cannot be re-encoded: {e}")))?;
    if protected.original_data.as_deref() != Some(expected.as_slice()) {
        return Err(CoseDecodeError::ProtectedHeader(
            "is not the deterministic encoding of {1: -7, 4: kid}".into(),
        ));
    }
    let kid = String::from_utf8(header.key_id.clone())
        .map_err(|_| CoseDecodeError::ProtectedHeader("kid is not valid UTF-8".into()))?;

    // 5c: the empty map. Its content is not decoded as a header at all: a
    // map holding anything - a malformed kid, a duplicate label - is 5c.
    if !parts.unprotected.is_empty() {
        return Err(CoseDecodeError::UnprotectedHeader);
    }

    let sig = crate::sign::signature_from_bytes(&parts.signature)
        .map_err(CoseDecodeError::SignatureEncoding)?;

    let payload = parts.payload.as_ref().ok_or(CoseDecodeError::NoPayload)?;
    // 7c: a record under the JSON form's rules, read strictly: an object
    // written as the array of its values is not a record (QA QT-01).
    let UnsignedRecord {
        record_version,
        record_id,
        issued_at,
        issuer,
        model_identity,
        learning_provenance,
        deployment_context,
        policy_compliance,
        lineage,
        data_governance,
        human_oversight,
        signature,
    } = crate::strict_json::from_slice(payload).map_err(|e| CoseDecodeError::Payload(e.into()))?;
    if signature.is_some() {
        return Err(CoseDecodeError::PayloadNotCanonical);
    }
    let record = Record {
        record_version,
        record_id,
        issued_at,
        issuer,
        model_identity,
        learning_provenance,
        deployment_context,
        policy_compliance,
        lineage,
        data_governance,
        human_oversight,
        // The JSON form's signature section, recovered from the envelope
        // (spec §4.4): alg, the signature bytes, the payload's hash, the kid.
        signature: SignatureSection {
            algorithm: "ES256".into(),
            signature: SignatureSection::signature_field(&sig),
            signed_payload_hash: format_hash(&sha256(payload)),
            signing_key_id: kid,
        },
    };
    if record.signed_payload().map_err(CoseDecodeError::Payload)? != *payload {
        return Err(CoseDecodeError::PayloadNotCanonical);
    }
    // One envelope per record: any other encoding of the same parts (a
    // non-preferred length head, an indefinite-length item, ...) differs
    // from the canonical re-encoding. (to_cose cannot fail here — every part
    // it re-encodes was just checked — and a failure would mean "not
    // canonical" anyway.)
    match record.to_cose() {
        Ok(canonical) if canonical == bytes => Ok(record),
        _ => Err(CoseDecodeError::NotCanonical),
    }
}

/// Encode a signed COSE_Sign1 envelope.
///
/// `payload` are the bytes the signature covers; `key_id` lands in the
/// protected header (UTF-8). The signature is computed over the payload via
/// ES256; the external AAD is empty. The signature slot holds the raw
/// 64-byte `r || s` that RFC 9052 §8.1 requires for ECDSA — coset stores
/// whatever bytes it is given, so the encoding is this crate's job
/// (QA P3-02: it used to be DER, which no conformant COSE verifier accepts).
pub fn encode_sign1(
    key: &p256::ecdsa::SigningKey,
    key_id: &str,
    payload: &[u8],
) -> Result<Vec<u8>, crate::error::Error> {
    let protected = HeaderBuilder::new()
        .algorithm(Algorithm::ES256)
        .key_id(key_id.as_bytes().to_vec())
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .try_create_signature(&[], |tbs| {
            let sig = crate::sign::sign(key, tbs)?;
            Ok::<Vec<u8>, p256::ecdsa::Error>(sig.to_bytes().to_vec())
        })?
        .build();
    Ok(sign1.to_vec()?)
}

/// Decode a COSE_Sign1 envelope.
pub fn decode_sign1(bytes: &[u8]) -> Result<CoseSign1, coset::CoseError> {
    CoseSign1::from_slice(bytes)
}

/// Verify a COSE_Sign1 envelope's signature over its own payload. The
/// signature must be the raw 64-byte `r || s` (RFC 9052 §8.1).
pub fn verify_sign1(
    sign1: &CoseSign1,
    key: &p256::ecdsa::VerifyingKey,
) -> Result<(), crate::error::Error> {
    sign1.verify_signature(&[], |sig_bytes, tbs| {
        let sig = crate::sign::signature_from_bytes(sig_bytes)?;
        crate::sign::verify(key, tbs, &sig)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;

    fn fixed_key() -> p256::ecdsa::SigningKey {
        crate::sign::signing_key_from_secret(&sha256(b"khalm-vmr cose test key")).unwrap()
    }

    #[test]
    fn encode_decode_round_trip() {
        let key = fixed_key();
        let payload = b"{\"a\":1}";
        let bytes = encode_sign1(&key, "key-1", payload).unwrap();
        let sign1 = decode_sign1(&bytes).unwrap();
        assert_eq!(sign1.payload.as_deref(), Some(payload.as_slice()));
        assert_eq!(
            sign1.protected.header.alg.as_ref(),
            Some(&coset::RegisteredLabelWithPrivate::Assigned(Algorithm::ES256))
        );
        verify_sign1(&sign1, key.verifying_key()).unwrap();
    }

    #[test]
    fn signature_is_raw_64_byte_r_s() {
        // RFC 9052 §8.1: the ES256 signature is r||s, 32 bytes each.
        let key = fixed_key();
        let sign1 = decode_sign1(&encode_sign1(&key, "k", b"payload").unwrap()).unwrap();
        assert_eq!(sign1.signature.len(), 64);
        let sig = p256::ecdsa::Signature::from_slice(&sign1.signature).unwrap();
        assert_eq!(sig.to_bytes().to_vec(), sign1.signature);
    }

    #[test]
    fn tampered_payload_fails() {
        let key = fixed_key();
        let mut bytes = encode_sign1(&key, "k", b"payload").unwrap();
        let idx = bytes.len() - 1;
        bytes[idx] ^= 1;
        let sign1 = decode_sign1(&bytes).unwrap();
        assert!(verify_sign1(&sign1, key.verifying_key()).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key = fixed_key();
        let other = crate::sign::signing_key_from_secret(&sha256(b"other")).unwrap();
        let bytes = encode_sign1(&key, "k", b"payload").unwrap();
        let sign1 = decode_sign1(&bytes).unwrap();
        assert!(verify_sign1(&sign1, other.verifying_key()).is_err());
    }

    /// `n` nested arrays, `[[...]]`: `n` levels.
    fn arrays(n: usize) -> Vec<u8> {
        [vec![0x81; n - 1], vec![0x80]].concat()
    }

    #[test]
    fn the_envelope_walk_reads_the_subset_to_16_levels() {
        let envelope = encode_sign1(&fixed_key(), "k", b"{\"a\":1}").unwrap();
        check_envelope_cbor(&envelope).unwrap();
        let inside: [&[u8]; 8] = [
            &[0x80],
            &[0xa0],
            &[0xf6],
            &[0x3a, 0xff, 0xff, 0xff, 0xff],
            &[0x5a, 0x00, 0x00, 0x00, 0x01, 0x00],
            &[0x63, 0xef, 0xb7, 0x90],
            &[0x82, 0xa1, 0x00, 0x40, 0x60],
            &[0xb8, 0x01, 0x61, 0x61, 0x19, 0x00, 0x01],
        ];
        for item in inside {
            assert!(check_envelope_cbor(item).is_ok(), "{item:02x?}");
        }
        check_envelope_cbor(&arrays(MAX_ENVELOPE_DEPTH)).unwrap();
        let deeper = check_envelope_cbor(&arrays(MAX_ENVELOPE_DEPTH + 1)).unwrap_err().to_string();
        assert!(deeper.contains("level 17"), "{deeper}");
        assert!(check_envelope_cbor(&arrays(1_000_000)).is_err());
    }

    #[test]
    fn the_envelope_walk_refuses_what_the_input_cannot_back() {
        for (bytes, word) in [
            (&[][..], "ends where"),
            (&[0x18][..], "ends inside"),
            (&[0x82, 0x81, 0x00][..], "ends where"),
            (&[0x5a, 0xff, 0xff, 0xff, 0xff][..], "longer than"),
            (&[0x9a, 0xff, 0xff, 0xff, 0xff][..], "more than"),
            (&[0xba, 0x80, 0x00, 0x00, 0x00, 0x00][..], "more than"),
            (&[0x00, 0x00][..], "after"),
        ] {
            let e = check_envelope_cbor(bytes).unwrap_err().to_string();
            assert!(e.contains(word), "{bytes:02x?}: {e}");
        }
    }

    #[test]
    fn the_envelope_walk_answers_every_input_of_up_to_two_bytes() {
        // The walk runs on untrusted input: it returns, it never panics.
        for a in 0..=255u8 {
            let alone = check_envelope_cbor(&[a]).is_ok();
            let expected = matches!(a, 0x00..=0x17 | 0x20..=0x37 | 0x40 | 0x60 | 0x80 | 0xa0 | 0xf6);
            assert_eq!(alone, expected, "{a:02x}");
            for b in 0..=255u8 {
                let _ = check_envelope_cbor(&[a, b]);
            }
        }
    }
}
