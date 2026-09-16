// ============================================================================
//  vmr-policy — the open policy-pack format, and evaluation against a record
//
//  This crate loads a jurisdiction-agnostic policy pack, evaluates it against
//  a record payload, and returns an `Evaluation` that can become the
//  record's `policy_compliance` section. Any authority - a national
//  regulator, a standards body, an enterprise, an industry consortium - can
//  author a pack by writing JSON against
//  `specs/policy-pack-schema/v0.1.json`.
//
//  The five reference packs under `specs/policy-packs/` encode standards that
//  already govern AI deployments worldwide: the EU AI Act, the NIST AI RMF,
//  ISO/IEC 42001, C2PA AI disclosure and IETF RATS. They are reference
//  implementations of the format and not legal advice, which each of them
//  says in its own `disclaimer`. Any jurisdiction-specific pack - including
//  any corridor-specific one - is one authority among many, never the
//  default.
//
//  Design invariants:
//
//    * No unsafe code (`#![forbid(unsafe_code)]`).
//    * No network, no file system, no clock: the evaluation time is an input
//      (P6-5) and every input is passed in.
//    * No panics in library code: every fallible path returns a typed error,
//      and clippy denies the panicking shortcuts below.
//    * Deterministic: the same pack, record and evaluation time give the
//      same `Evaluation`, member for member, on every machine (Law 1).
//    * It shares the format crate rather than growing a second
//      implementation of JCS, SHA-256, base64url, ES256 or key ids (P6-7).
//
//  What it deliberately does NOT do: decide whether to trust a record.
//  Evaluating a pack against an unverified record evaluates the issuer's
//  own claims. Verification comes first (`vmr-verify`,
//  `specs/record-format-v0.1.md` §6), and a policy result never changes a
//  verification verdict (§6.6).
// ============================================================================

//! The VMR policy-pack format v0.1: load a pack, evaluate it against a
//! record payload, convert the result for the record's
//! `policy_compliance`. Normative reference:
//! `specs/policy-pack-format-v0.1.md`, with
//! `specs/policy-pack-schema/v0.1.json` for the pack's structure.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// An evaluator runs on documents from strangers: no panicking shortcuts in
// library code (Law 9), as in vmr-record and vmr-verify.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unreachable,
        clippy::todo
    )
)]

pub mod context;
pub mod error;
pub mod evaluation;
pub mod evidence;
pub mod pack;
pub mod refusal;
pub mod rules;
pub mod schema;
pub mod signing;
pub mod validator;

pub use context::{EvaluationContext, LineageContext, LineageOutcome, VerifiedPredecessor};
pub use error::Error;
pub use refusal::Refusal;
pub use evaluation::{Evaluation, RuleResult, Status};
pub use pack::{
    AttestationLevelRule, AuditIntegrityRule, Authority, DataResidencyRule,
    DocumentationDeclaredRule, ExecutionIntegrityRule, ExportControlRule, PackSignature,
    PolicyPack, Rule, RuleCommon, Severity, SourceScreeningRule,
};
pub use signing::{payload_hash, signed_payload, verify_pack_signature};
pub use validator::validate;

/// The format crate, re-exported: a caller (or a test) that needs a
/// timestamp, a key or the record types needs no second dependency, and
/// there is only ever one version of the format in the tree (P6-7).
pub use vmr_record;

use serde_json::Value;
use vmr_record::timestamp::Timestamp;

/// The pack FORMAT version this build reads.
pub const PACK_FORMAT_VERSION: &str = "0.1";

/// The largest pack document that is read, in bytes. A policy pack is a
/// human-authored document; 1 MiB is the record's bound too.
pub const MAX_PACK_BYTES: usize = 1_048_576;

/// A pack that has been parsed and validated, together with the document it
/// came from. The document is kept because it, and not a re-serialisation of
/// the typed pack, is what an authority signs (P6-8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPack {
    pack: PolicyPack,
    document: Value,
    payload_hash: String,
}

impl LoadedPack {
    /// The typed pack.
    pub fn pack(&self) -> &PolicyPack {
        &self.pack
    }

    /// The document as received, parsed but not reshaped.
    pub fn document(&self) -> &Value {
        &self.document
    }

    /// `sha256:` + the hex of the hash of the bytes an authority signs
    /// ([`signing::signed_payload`]), whether or not the pack is signed.
    pub fn payload_hash(&self) -> &str {
        &self.payload_hash
    }

    /// Verify the pack's signature under `key` ([`verify_pack_signature`]).
    pub fn verify_signature(&self, key: &p256::ecdsa::VerifyingKey) -> Result<(), Error> {
        signing::verify_pack_signature(&self.pack, &self.document, key)
    }

    /// Step 4 of the format document's §4 on its own, which needs no key: the
    /// `signed_payload_hash` a signature section states is this pack's
    /// payload hash. A pack that fails it was changed after it was signed, or
    /// carries another pack's section, and is not reported as signed by the
    /// key it names (QA Q6-05): [`Error::PayloadHashMismatch`]. An unsigned
    /// pack states no hash, and passes.
    pub fn check_payload_hash(&self) -> Result<(), Error> {
        match &self.pack.signature {
            Some(section) if section.signed_payload_hash != self.payload_hash => Err(Error::PayloadHashMismatch {
                stated: section.signed_payload_hash.clone(),
                recomputed: self.payload_hash.clone(),
            }),
            _ => Ok(()),
        }
    }

    /// Evaluate this pack against a record payload at `evaluated_at`.
    pub fn evaluate(&self, record: &Value, evaluated_at: Timestamp) -> Evaluation {
        evaluate(&self.pack, record, evaluated_at)
    }

    /// Evaluate this pack with what verification established about the
    /// record ([`evaluate_in_context`]).
    pub fn evaluate_in_context(
        &self,
        record: &Value,
        context: &EvaluationContext,
        evaluated_at: Timestamp,
    ) -> Evaluation {
        evaluate_in_context(&self.pack, record, context, evaluated_at)
    }
}

impl std::ops::Deref for LoadedPack {
    type Target = PolicyPack;

    fn deref(&self) -> &PolicyPack {
        &self.pack
    }
}

/// Load a policy pack from its JSON text: parse it strictly, keep the
/// document, and validate it. For the bytes of a file, which may not be
/// UTF-8, [`load_pack_bytes`].
///
/// Refusals, each with its own [`Error`] variant and its own test (P6-9):
/// a document over [`MAX_PACK_BYTES`]; JSON that does not parse; an unknown,
/// duplicate, missing or `null` member, or a rule `type` this build does not
/// know; a `version` other than [`PACK_FORMAT_VERSION`]; a broken value rule
/// of the schema; an empty `rules`; a duplicate `rule_id`; a rule that states
/// no requirement. Whichever variant carries it, [`Error::refusal`] names the
/// refusal of the format document's §3 (`crate::refusal`).
pub fn load_pack(json: &str) -> Result<LoadedPack, Error> {
    if json.len() > MAX_PACK_BYTES {
        return Err(Error::PackTooLarge { bytes: json.len(), limit: MAX_PACK_BYTES });
    }
    // Twice over the same text on purpose: once into a Value, which is what
    // an authority signs (P6-8), and once into the typed pack, whose
    // `deny_unknown_fields` structs are the strict parser (P6-9), read through
    // vmr_record::strict_json: an object written as the array of its values
    // is refused, where serde's derive would read it as the struct (QA QT-01;
    // refusal 2). Only a failed parse looks at the text again, to name its
    // refusal.
    let document: Value =
        serde_json::from_str(json).map_err(|e| parse_error(&e, refusal::of_value_parse(json)))?;
    let pack: PolicyPack = vmr_record::strict_json::from_str(json)
        .map_err(|e| parse_error(&e, refusal::of_typed_parse(json, &document)))?;
    validate(&pack)?;
    let payload_hash = signing::payload_hash(&document);
    Ok(LoadedPack { pack, document, payload_hash })
}

/// Load a policy pack from the bytes of a file, in the order the format
/// document's §3 fixes (QA16-02):
///
/// 1. a document over [`MAX_PACK_BYTES`]: refusal 1;
/// 2. bytes whose depth, counted by [`refusal::nests_past_bound`], passes
///    [`refusal::MAX_TEXT_NESTING`] levels: refusal 12, whatever else they
///    break (a byte order mark, bytes that are not UTF-8, a syntax error);
/// 3. bytes that are not UTF-8: refusal 2;
/// 4. [`load_pack`] on the text, which names every other refusal.
///
/// For every text [`load_pack`] can take, both name the same refusal.
pub fn load_pack_bytes(bytes: &[u8]) -> Result<LoadedPack, Error> {
    if bytes.len() > MAX_PACK_BYTES {
        return Err(Error::PackTooLarge { bytes: bytes.len(), limit: MAX_PACK_BYTES });
    }
    if refusal::nests_past_bound(bytes) {
        return Err(Error::PackParse {
            refusal: Refusal::Nesting,
            detail: format!(
                "the text nests arrays and objects more than {} levels deep, the outermost counting as the first",
                refusal::MAX_TEXT_NESTING
            ),
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|e| Error::PackParse {
        refusal: Refusal::Structure,
        detail: format!("it is not UTF-8 text: {e}"),
    })?;
    load_pack(text)
}

/// A serde_json error as [`Error::PackParse`] for `refusal`, its text made
/// terminal-safe: serde echoes an unknown member name or an unknown word as it
/// was written (QA Q6-10).
fn parse_error(e: &serde_json::Error, refusal: Refusal) -> Error {
    Error::PackParse { refusal, detail: error::escape_unsafe(&e.to_string()) }
}

/// Evaluate a policy pack against a record's JSON payload.
///
/// `record` is the record as a JSON value — `serde_json::to_value` of a
/// `vmr_record::Record`, or the parsed document. `evaluated_at` is the
/// caller's evaluation time (P6-5): this crate reads no clock.
///
/// Any value is answered, never refused and never a panic (Law 9). A value
/// at a member a rule reads that nests arrays and objects more than
/// [`evidence::MAX_DEPTH`] levels deep, which only code can build (no parsed
/// document is that deep), is not read: that rule is Indeterminate.
///
/// No verification context is given, so a rule setting that needs one
/// (`require_verified_lineage` on a record with predecessors,
/// `require_state_kept` on a deployment or policy-change record) is
/// Indeterminate, never a pass (P6-17).
pub fn evaluate(pack: &PolicyPack, record: &Value, evaluated_at: Timestamp) -> Evaluation {
    rules::evaluate_all(pack, record, None, evaluated_at)
}

/// [`evaluate`], with what a verifier established about the record: its
/// verified lineage and the predecessors whose links verified (P6-17). The
/// context enters the evidence hash of the rule types that can read it.
pub fn evaluate_in_context(
    pack: &PolicyPack,
    record: &Value,
    context: &EvaluationContext,
    evaluated_at: Timestamp,
) -> Evaluation {
    rules::evaluate_all(pack, record, Some(context), evaluated_at)
}
