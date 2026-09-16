//! What a rule looked at, and the hash that pins it (P6-2).
// ============================================================================
//  evidence.rs — evidence pointers and evidence_hash
//
//  Every result a record carries must let a third party check what the
//  rule looked at, so `evidence_hash` is defined here rather than left as
//  decoration (P6-2):
//
//    * each rule type has a FIXED list of JSON pointers into the record -
//      the "Reads" column of P6-3, in that order;
//    * the evidence VALUE is the value at the pointer when there is one
//      pointer, and the JSON array of the values, in the listed order, when
//      there are several;
//    * a pointer that resolves to nothing contributes JSON `null`, so the
//      hash is defined for every record, present field or not, and an
//      absent member cannot be confused with a present `null` (a record
//      cannot hold one: spec §2.3);
//    * a value nested deeper than `MAX_DEPTH` (128) arrays and objects is
//      not read: it contributes `null` as an absent member does, and the
//      rule is Indeterminate (QA Q6-04, Law 9). Canonicalizing or even
//      cloning such a value recurses, and a deep enough one overflows the
//      stack. serde_json parses no document nested deeper than 127 levels,
//      so no record read from a document reaches the bound and no
//      evidence hash of one is affected;
//    * P6-17: the two rule types that can read verification context,
//      `audit_integrity` and `execution_integrity`, hash one element more
//      after their record reads - the context slot. It is `null` without
//      context, and `null` for a context that adds nothing to the record:
//      an `initial` outcome, or a record whose `lineage_chain_length` is
//      not a count of 2 or more (`EvaluationContext::applies_to`), so an
//      initial record hashes the same whether or not a verifier supplied
//      context. Otherwise `audit_integrity`'s is the array of the lineage
//      outcome word and each verified predecessor's signed-payload hash,
//      immediate predecessor first; `execution_integrity`'s is the verified
//      immediate predecessor's `model_hash` (task 10.12a, D12a-3), or `null`;
//    * `evidence_hash` is `sha256:` + the hex of the SHA-256 of the JCS
//      (RFC 8785) form of that value, through `vmr_record::canonical::jcs`
//      and `vmr_record::hash` - the project's one canonicalizer and one
//      hash-string form (P6-7).
//
//  Two verifiers with the same record and the same pack therefore produce
//  the same `evidence_hash` byte for byte, whatever their JSON libraries do
//  with member order or number formatting. The pointer list is part of the
//  contract: it is in `docs/CODEMAP.md` §4.8, and changing one changes every
//  evidence hash a pack of that rule type produces.
// ============================================================================

use crate::context::EvaluationContext;
use crate::pack::Rule;
use serde_json::Value;
use vmr_record::canonical::jcs;
use vmr_record::hash::{format_hash, sha256};

/// Every record member a rule may read, by name (P6-3).
pub mod pointer {
    /// Where the training data came from, as a country code.
    pub const DATA_RESIDENCY: &str =
        "/learning_provenance/training_input_provenance/data_residency";
    /// Where it came from, when it resides in several countries (task
    /// 10.12a, D12a-4).
    pub const DATA_RESIDENCY_COUNTRIES: &str =
        "/learning_provenance/training_input_provenance/data_residency_countries";
    /// Whether the record withholds its training input, `not-held` or
    /// `not-disclosed` (task 10.12a, D12a-5).
    pub const TRAINING_INPUT_DISCLOSURE: &str = "/learning_provenance/training_input_disclosure";
    /// The model's identity (task 10.12a, D12a-3).
    pub const MODEL_HASH: &str = "/model_identity/model_hash";
    /// What kind of source it was.
    pub const SOURCE_TYPE: &str = "/learning_provenance/training_input_provenance/source_type";
    /// The kind of boundary inference runs inside.
    pub const BOUNDARY_TYPE: &str = "/deployment_context/inference_boundary/type";
    /// Whether the boundary lets anything out.
    pub const EGRESS_ALLOWED: &str = "/deployment_context/inference_boundary/egress_allowed";
    /// Where it may go, if anywhere.
    pub const ALLOWED_EGRESS_DESTINATIONS: &str =
        "/deployment_context/inference_boundary/allowed_egress_destinations";
    /// How many records this one's lineage counts.
    pub const LINEAGE_CHAIN_LENGTH: &str = "/lineage/lineage_chain_length";
    /// The predecessor's signed-payload hash, when there is one.
    pub const PREVIOUS_RECORD_HASH: &str = "/lineage/previous_record_hash";
    /// The commitment to the training input.
    pub const TRAINING_INPUT_MERKLE_ROOT: &str = "/learning_provenance/training_input_merkle_root";
    /// The hash of what was learned.
    pub const LEARNED_STATE_HASH: &str = "/model_identity/learned_state_hash";
    /// Its three components, each with a hash and a size.
    pub const LEARNED_STATE_COMPONENTS: &str = "/model_identity/learned_state_components";
    /// Which software did the learning, as the issuer names it (task 10.12a,
    /// D12a-2).
    pub const TRAINING_SOFTWARE: &str = "/learning_provenance/training_environment/training_software";
    /// The hash of the software stack it ran in.
    pub const SOFTWARE_HASH: &str = "/learning_provenance/training_environment/software_hash";
    /// The trusted-execution measurement, when there is one.
    pub const TEE_MEASUREMENT: &str = "/learning_provenance/training_environment/tee_measurement";
    /// How strongly the issuer attests.
    pub const ATTESTATION_LEVEL: &str = "/issuer/attestation_level";
    /// How many training input frames the Merkle root commits to (P6-17).
    pub const TRAINING_INPUT_COUNT: &str = "/learning_provenance/training_input_count";
    /// When training started (P6-17).
    pub const TRAINING_STARTED_AT: &str = "/learning_provenance/training_started_at";
    /// When training ended (P6-17).
    pub const TRAINING_ENDED_AT: &str = "/learning_provenance/training_ended_at";
    /// When the training input's collection began (P6-17).
    pub const COLLECTION_PERIOD_START: &str =
        "/learning_provenance/training_input_provenance/collection_period/start";
    /// When it ended (P6-17).
    pub const COLLECTION_PERIOD_END: &str =
        "/learning_provenance/training_input_provenance/collection_period/end";
    /// When the record was issued (P6-17).
    pub const ISSUED_AT: &str = "/issued_at";
    /// What kind of step this record records in its lineage (P6-17).
    pub const LINEAGE_TYPE: &str = "/lineage/lineage_type";
    /// The issuer's data governance documentation, pinned by hash; an
    /// optional member (task 10.11a).
    pub const DATA_GOVERNANCE: &str = "/data_governance";
    /// The issuer's human oversight documentation, pinned by hash; an
    /// optional member (task 10.11a).
    pub const HUMAN_OVERSIGHT: &str = "/human_oversight";
}

use pointer as p;

/// The pointers `data_residency` reads (P6-3, extended by task 10.12a).
pub const DATA_RESIDENCY: &[&str] = &[p::DATA_RESIDENCY, p::DATA_RESIDENCY_COUNTRIES];

/// The pointers `source_screening` reads (P6-3, extended by task 10.12a).
pub const SOURCE_SCREENING: &[&str] = &[p::SOURCE_TYPE, p::DATA_RESIDENCY, p::DATA_RESIDENCY_COUNTRIES];

/// The pointers `export_control` reads.
pub const EXPORT_CONTROL: &[&str] =
    &[p::BOUNDARY_TYPE, p::EGRESS_ALLOWED, p::ALLOWED_EGRESS_DESTINATIONS];

/// The pointers `audit_integrity` reads (P6-3, extended by P6-17 and task
/// 10.12a).
pub const AUDIT_INTEGRITY: &[&str] = &[
    p::LINEAGE_CHAIN_LENGTH,
    p::PREVIOUS_RECORD_HASH,
    p::TRAINING_INPUT_MERKLE_ROOT,
    p::TRAINING_INPUT_COUNT,
    p::TRAINING_STARTED_AT,
    p::TRAINING_ENDED_AT,
    p::COLLECTION_PERIOD_START,
    p::COLLECTION_PERIOD_END,
    p::ISSUED_AT,
    p::TRAINING_INPUT_DISCLOSURE,
];

/// The pointers `execution_integrity` reads (P6-3, extended by P6-17 and task
/// 10.12a).
pub const EXECUTION_INTEGRITY: &[&str] = &[
    p::LEARNED_STATE_HASH,
    p::LEARNED_STATE_COMPONENTS,
    p::TRAINING_SOFTWARE,
    p::SOFTWARE_HASH,
    p::TEE_MEASUREMENT,
    p::LINEAGE_TYPE,
    p::MODEL_HASH,
];

/// The pointers `attestation_level` reads.
pub const ATTESTATION_LEVEL: &[&str] = &[p::ATTESTATION_LEVEL];

/// The pointers `documentation_declared` reads: both documentation members,
/// whichever one a rule names (task 10.11a, D11-4).
pub const DOCUMENTATION_DECLARED: &[&str] = &[p::DATA_GOVERNANCE, p::HUMAN_OVERSIGHT];

/// The pointers a rule of this type reads, in the order they are hashed.
/// A type this build does not know reads nothing — unreachable through
/// [`Rule`], whose seven variants are the seven types.
pub fn pointers_for(rule_type: &str) -> &'static [&'static str] {
    match rule_type {
        "data_residency" => DATA_RESIDENCY,
        "source_screening" => SOURCE_SCREENING,
        "export_control" => EXPORT_CONTROL,
        "audit_integrity" => AUDIT_INTEGRITY,
        "execution_integrity" => EXECUTION_INTEGRITY,
        "attestation_level" => ATTESTATION_LEVEL,
        "documentation_declared" => DOCUMENTATION_DECLARED,
        _ => &[],
    }
}

/// The pointers this rule reads.
pub fn pointers(rule: &Rule) -> &'static [&'static str] {
    pointers_for(rule.rule_type())
}

/// How deeply a value at a read member may nest arrays and objects and
/// still be read: 128 levels, the value itself counting as the first when
/// it is an array or an object. serde_json refuses a document nested deeper
/// than 127, so only a value built in code can exceed it (QA Q6-04).
pub const MAX_DEPTH: usize = 128;

/// The first of `pointers` whose value nests arrays and objects more than
/// [`MAX_DEPTH`] levels deep, or `None` when every value may be read. The
/// levels are counted with an explicit stack, so the check cannot itself
/// overflow the call stack.
pub fn too_deep<'p>(record: &Value, pointers: &[&'p str]) -> Option<&'p str> {
    pointers.iter().copied().find(|p| record.pointer(p).is_some_and(nests_past_max_depth))
}

/// Whether `value` nests arrays and objects more than [`MAX_DEPTH`] levels
/// deep, walked iteratively.
fn nests_past_max_depth(value: &Value) -> bool {
    let mut pending: Vec<(&Value, usize)> = vec![(value, 1)];
    while let Some((v, depth)) = pending.pop() {
        let children: Vec<&Value> = match v {
            Value::Array(items) => items.iter().collect(),
            Value::Object(members) => members.values().collect(),
            _ => continue,
        };
        if depth > MAX_DEPTH {
            return true;
        }
        pending.extend(children.into_iter().map(|c| (c, depth + 1)));
    }
    false
}

/// The evidence value: the single pointer's value, or the array of the
/// values of several, with `null` for a pointer that resolves to nothing or
/// to a value nested more than [`MAX_DEPTH`] levels deep, which is not read.
pub fn value(record: &Value, pointers: &[&str]) -> Value {
    let at = |p: &&str| match record.pointer(p) {
        Some(v) if !nests_past_max_depth(v) => v.clone(),
        _ => Value::Null,
    };
    match pointers {
        [] => Value::Null,
        [only] => at(only),
        many => Value::Array(many.iter().map(at).collect()),
    }
}

/// `sha256:` + the hex of the SHA-256 of the JCS form of [`value`]: the
/// record reads alone. For the two rule types that read context, a rule's
/// evidence hash is [`hash_in_context`].
pub fn hash(record: &Value, pointers: &[&str]) -> String {
    format_hash(&sha256(jcs(&value(record, pointers)).as_bytes()))
}

/// The context slot a rule type hashes after its record reads, or `None`
/// for a type that reads no context (P6-17). Only a context that applies to
/// `record` fills it.
fn context_slot(rule_type: &str, record: &Value, context: Option<&EvaluationContext>) -> Option<Value> {
    let context = crate::context::applicable(context, record);
    match rule_type {
        "audit_integrity" => Some(match context {
            None => Value::Null,
            Some(c) => {
                let mut items = vec![Value::from(c.lineage.outcome.id())];
                items.extend(
                    c.lineage.predecessors.iter().map(|p| Value::from(p.signed_payload_hash.as_str())),
                );
                Value::Array(items)
            }
        }),
        "execution_integrity" => Some(
            context
                .and_then(EvaluationContext::immediate_predecessor)
                .and_then(|p| p.record.pointer(pointer::MODEL_HASH))
                .filter(|v| !nests_past_max_depth(v))
                .cloned()
                .unwrap_or(Value::Null),
        ),
        _ => None,
    }
}

/// The evidence value of a rule of `rule_type`: its record reads
/// ([`value`]), followed, for a type that reads context, by the context
/// slot (`null` without context).
pub fn value_in_context(rule_type: &str, record: &Value, context: Option<&EvaluationContext>) -> Value {
    let reads = value(record, pointers_for(rule_type));
    match context_slot(rule_type, record, context) {
        None => reads,
        Some(slot) => match reads {
            Value::Array(mut items) => {
                items.push(slot);
                Value::Array(items)
            }
            single => Value::Array(vec![single, slot]),
        },
    }
}

/// `sha256:` + the hex of the SHA-256 of the JCS form of
/// [`value_in_context`].
pub fn hash_in_context(rule_type: &str, record: &Value, context: Option<&EvaluationContext>) -> String {
    format_hash(&sha256(jcs(&value_in_context(rule_type, record, context)).as_bytes()))
}

/// The evidence hash of a rule against a record payload, without context.
pub fn hash_for(rule: &Rule, record: &Value) -> String {
    hash_in_context(rule.rule_type(), record, None)
}

/// The evidence hash of a rule against a record payload, in `context`.
pub fn hash_for_in_context(rule: &Rule, record: &Value, context: Option<&EvaluationContext>) -> String {
    hash_in_context(rule.rule_type(), record, context)
}
