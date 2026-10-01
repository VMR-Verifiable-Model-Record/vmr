//! The calls js/vmr-check.js makes, as safe Rust: requests in, JSON out.
// ============================================================================
//  api.rs — one entry point, `call(op, request)`, and the calls behind it
//
//  A request is a sequence of frames, each a u32 little-endian length and
//  that many bytes. Frame 0 is a JSON object of the call's scalar arguments;
//  the frames after it are its byte arguments, in the order below. The answer
//  is always JSON (UTF-8): the call's result, or the fail shape of
//  `refusal.rs`. Nothing here panics on any bytes (tests/robustness.rs).
//
//    op 1 version              no frame needed
//    op 2 verify               {at, previous, pack, authority_store,
//                              require_complete_lineage,
//                              require_signed_pack}; record, trust store,
//                              [pack], [authority store], previous...
//    op 3 inspect              {}; record
//    op 4 store_for_embedded_key {expected_fingerprint, attestation_level};
//                              record
//    op 5 check_files          {files: [{name | name_utf16, sha256, size}]};
//                              record
// ============================================================================

use crate::files::{GivenFile, GivenName};
use crate::inspect::read_record;
use crate::pack::{Authorities, PackEvaluator};
use crate::refusal::{
    Refusal, AUTHORITY_STORE_ISSUERS, AUTHORITY_STORE_ISSUER_KEY, EVALUATION_TIME_RANGE, REQUEST_MALFORMED,
};
use crate::safe::display_safe_value;
use serde_json::{json, Value};
use vmr_record::timestamp::Timestamp;
use vmr_verify::policy::PolicyEvaluator;
use vmr_verify::{TrustStore, Verifier, VerifyOptions};

/// `version()`.
pub const OP_VERSION: u32 = 1;
/// `verify(...)`.
pub const OP_VERIFY: u32 = 2;
/// `inspect(record)`.
pub const OP_INSPECT: u32 = 3;
/// `storeForEmbeddedKey(record, ...)`.
pub const OP_STORE_FOR_EMBEDDED_KEY: u32 = 4;
/// `checkFiles(...)`.
pub const OP_CHECK_FILES: u32 = 5;

/// The arguments of `verify`.
#[derive(Debug, Clone, Default)]
pub struct VerifyRequest<'a> {
    /// The record's bytes, in either form.
    pub record: &'a [u8],
    /// The trust store's bytes.
    pub trust_store: &'a [u8],
    /// The evaluation time, seconds since 1970-01-01T00:00:00Z: the caller's
    /// clock, never this module's.
    pub at: Option<i64>,
    /// A policy pack's bytes.
    pub pack: Option<&'a [u8]>,
    /// An authority store's bytes: the policy authorities a pack's signature
    /// is checked against instead of the trust store's.
    pub authority_store: Option<&'a [u8]>,
    /// Refuse a pack that is unsigned, or signed by a key no trusted policy
    /// authority holds.
    pub require_signed_pack: bool,
    /// Predecessor records, immediate predecessor first.
    pub previous: Vec<&'a [u8]>,
    /// Fail unless the whole lineage back to the initial record verifies.
    pub require_complete_lineage: bool,
}

/// `version()`: this build's version and the record format it reads.
pub fn version() -> Value {
    json!({ "vmr": crate::VERSION, "record_format": crate::RECORD_FORMAT })
}

/// `verify`: the verifier's report for the record, against the caller's
/// trust store at the caller's time, with a pack's evaluation when one is
/// given — or the fail shape for a store, pack or time that cannot be used.
///
/// The report is returned twice: `report_json`, the library's own JSON
/// (`VerificationReport::to_json`) byte for byte, and `report`, the same
/// report with every string through `display_safe` (the library leaves a
/// record's claims, a store's names and a pack's texts raw in it). `policy`
/// is the report's `policy.evaluation`, shown the same way, when a pack was
/// given, else `null`.
pub fn verify(req: &VerifyRequest<'_>) -> Value {
    match verified(req) {
        Ok(value) => value,
        Err(refusal) => refusal.to_value(),
    }
}

fn verified(req: &VerifyRequest<'_>) -> Result<Value, Refusal> {
    // The order of `vmr record verify`: the stores, the time, the pack, then
    // the record (verify_cmd.rs), so a refusal names the input the CLI would.
    let store = TrustStore::from_json(req.trust_store)
        .map_err(|e| Refusal::new(e.kind.id(), "trust_store", e.detail))?;
    let authority_store = match req.authority_store {
        Some(bytes) => Some(authority_store(&store, bytes)?),
        None => None,
    };
    let at = req.at.and_then(Timestamp::from_unix_seconds).ok_or_else(|| {
        Refusal::new(
            EVALUATION_TIME_RANGE,
            "at",
            "at is not a whole number of seconds since 1970-01-01T00:00:00Z inside the years 0000-9999",
        )
    })?;
    let pack = match req.pack {
        Some(bytes) => {
            let authorities = match &authority_store {
                Some(authority_store) => Authorities::AuthorityStore(authority_store),
                None => Authorities::TrustStore(&store),
            };
            Some(PackEvaluator::load(bytes)?.check_signature(authorities, at, req.require_signed_pack)?)
        }
        None => None,
    };
    let mut opts = VerifyOptions::new(at)
        .with_previous(&req.previous)
        .require_complete_lineage(req.require_complete_lineage);
    if let Some(evaluator) = &pack {
        opts = opts.with_policy(evaluator as &dyn PolicyEvaluator);
    }
    let report = Verifier::new(store).verify(req.record, &opts);
    let report_json = report
        .to_json()
        .map_err(|e| Refusal::new(REQUEST_MALFORMED, "record", format!("the report could not be written: {e}")))?;
    let shown = display_safe_value(serde_json::from_str(&report_json).unwrap_or(Value::Null));
    let policy = match pack {
        Some(_) => shown.pointer("/policy/evaluation").cloned().unwrap_or(Value::Null),
        None => Value::Null,
    };
    // The answer `vmr record verify` gives as its exit code (QA S3): 0 the
    // record verified and is accepted, 4 it verified but the pack's
    // evaluation does not accept it, 3 it failed.
    let outcome = match report.exit_code() {
        0 => "verified",
        4 => "verified_not_accepted",
        _ => "failed",
    };
    // The trusted key's fingerprint, as `vmr record verify` prints it beside
    // the key id (QA N5): the trust store's key, present only once the
    // signature verified under it and the store trusts it for the issuer.
    let fingerprint = report.issuer.as_ref().and_then(|issuer| vmr_record::jwk::fingerprint(&issuer.key_id));
    Ok(json!({
        "accepted": report.accepted,
        "outcome": outcome,
        "fingerprint": fingerprint,
        "report": shown,
        "report_json": report_json,
        "policy": policy,
        "at_source": "caller",
    }))
}

/// An authority store, refused as `vmr record verify --authority-store`
/// refuses one: unusable, listing issuers, or holding a key the trust store
/// trusts for an issuer.
fn authority_store(store: &TrustStore, bytes: &[u8]) -> Result<TrustStore, Refusal> {
    let authorities =
        TrustStore::from_json(bytes).map_err(|e| Refusal::new(e.kind.id(), "authority_store", e.detail))?;
    if authorities.issuer_count() > 0 {
        return Err(Refusal::new(
            AUTHORITY_STORE_ISSUERS,
            "authority_store",
            format!(
                "it trusts {} issuer(s), and an authority store lists only policy_authorities, with \"issuers\": []",
                authorities.issuer_count()
            ),
        ));
    }
    let document = authorities.to_document();
    if let Some(issuer_key) =
        document.policy_authorities.iter().flat_map(|a| &a.keys).find_map(|key| store.lookup(&key.key_id))
    {
        return Err(Refusal::new(
            AUTHORITY_STORE_ISSUER_KEY,
            "authority_store",
            format!(
                "it trusts {} for a policy authority, and the trust store trusts the same key for issuer {}: one key \
                 may not vouch both for records and for the policy packs they are judged by",
                issuer_key.key_id, issuer_key.issuer_id
            ),
        ));
    }
    Ok(authorities)
}

/// `inspect(record)`: see [`crate::inspect::inspect`].
pub fn inspect(record: &[u8]) -> Value {
    crate::inspect::inspect(record)
}

/// `storeForEmbeddedKey(record, {expectedFingerprint, attestationLevel})`:
/// `{"trust_store": text}`, or the fail shape.
pub fn store_for_embedded_key(record: &[u8], expected_fingerprint: &str, attestation_level: Option<&str>) -> Value {
    let stored = read_record(record).and_then(|record| {
        let level = crate::store::attestation_level(attestation_level)?;
        crate::store::store_for_embedded_key(&record, expected_fingerprint, level)
    });
    match stored {
        Ok(text) => json!({ "trust_store": text }),
        Err(refusal) => refusal.to_value(),
    }
}

/// `checkFiles({record, files})`: see [`crate::files::check_files`].
pub fn check_files(record: &[u8], files: &[GivenFile]) -> Value {
    match read_record(record) {
        Ok(record) => crate::files::check_files(&record, files),
        Err(refusal) => refusal.to_value(),
    }
}

/// Answer one framed request (see the module header) with JSON bytes.
pub fn call(op: u32, request: &[u8]) -> Vec<u8> {
    let answer = match frames(request) {
        Some(frames) => dispatch(op, &frames),
        None => malformed("the request's frames do not add up to its length"),
    };
    serde_json::to_vec(&answer).unwrap_or_else(|_| b"{\"refusal\":{\"id\":\"request.malformed\"}}".to_vec())
}

fn malformed(detail: &str) -> Value {
    Refusal::new(REQUEST_MALFORMED, "request", detail).to_value()
}

/// The frames of a request: each a u32 little-endian length and its bytes,
/// to the end exactly.
fn frames(mut rest: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (length, tail) = rest.split_at_checked(4)?;
        let length = usize::try_from(u32::from_le_bytes(length.try_into().ok()?)).ok()?;
        let (frame, tail) = tail.split_at_checked(length)?;
        out.push(frame);
        rest = tail;
    }
    Some(out)
}

fn dispatch(op: u32, frames: &[&[u8]]) -> Value {
    if op == OP_VERSION {
        return version();
    }
    let header: Value = match frames.first().map(|h| serde_json::from_slice(h)) {
        Some(Ok(header @ Value::Object(_))) => header,
        _ => return malformed("frame 0 is not a JSON object"),
    };
    let blobs = frames.get(1..).unwrap_or_default();
    let flag = |name: &str| header.get(name).and_then(Value::as_bool).unwrap_or(false);
    let Some(record) = blobs.first().copied() else {
        return malformed("the request carries no record");
    };
    match op {
        OP_VERIFY => {
            let (has_pack, has_authorities) = (flag("pack"), flag("authority_store"));
            let previous = header.get("previous").and_then(Value::as_u64).unwrap_or(0);
            let named = 2 + usize::from(has_pack) + usize::from(has_authorities);
            let Some(expected) = usize::try_from(previous).ok().and_then(|p| p.checked_add(named)) else {
                return malformed("too many predecessors");
            };
            if blobs.len() != expected {
                return malformed("the request's byte arguments do not match its header");
            }
            let mut rest = blobs.iter().copied().skip(2);
            let pack = if has_pack { rest.next() } else { None };
            let authority_store = if has_authorities { rest.next() } else { None };
            verify(&VerifyRequest {
                record,
                trust_store: blobs.get(1).copied().unwrap_or_default(),
                at: header.get("at").and_then(Value::as_i64),
                pack,
                authority_store,
                require_signed_pack: flag("require_signed_pack"),
                previous: rest.collect(),
                require_complete_lineage: flag("require_complete_lineage"),
            })
        }
        OP_INSPECT => inspect(record),
        OP_STORE_FOR_EMBEDDED_KEY => {
            let Some(expected) = header.get("expected_fingerprint").and_then(Value::as_str) else {
                return malformed("the header carries no expected_fingerprint");
            };
            store_for_embedded_key(record, expected, header.get("attestation_level").and_then(Value::as_str))
        }
        OP_CHECK_FILES => {
            let Some(files) = header.get("files").and_then(Value::as_array) else {
                return malformed("the header carries no files");
            };
            let mut given = Vec::with_capacity(files.len());
            for file in files {
                // A name is text, or, when it is not Unicode (a lone
                // surrogate), its UTF-16 code units (QA N1).
                let name = match (file.get("name").and_then(Value::as_str), file.get("name_utf16").and_then(Value::as_array)) {
                    (Some(name), None) => GivenName::Text(name.to_string()),
                    (None, Some(units)) => {
                        let units: Option<Vec<u16>> =
                            units.iter().map(|u| u.as_u64().and_then(|u| u16::try_from(u).ok())).collect();
                        match units {
                            Some(units) => GivenName::NotUnicode(units),
                            None => return malformed("a file's name_utf16 is not a list of UTF-16 code units"),
                        }
                    }
                    _ => return malformed("a file has neither a name nor a name_utf16"),
                };
                let Some(sha256) = file.get("sha256").and_then(Value::as_str) else {
                    return malformed("a file has no sha256");
                };
                given.push(GivenFile { name, sha256: sha256.to_string(), size: file.get("size").and_then(Value::as_u64) });
            }
            check_files(record, &given)
        }
        _ => malformed("unknown call"),
    }
}
