//! `execution_integrity`: what ran is pinned by hashes a reader can check.
// ============================================================================
//  execution_integrity.rs (P6-3, extended by P6-17 and task 10.12a)
//
//  Reads:          /model_identity/learned_state_hash
//                  /model_identity/learned_state_components
//                  /learning_provenance/training_environment/training_software
//                  /learning_provenance/training_environment/software_hash
//                  /learning_provenance/training_environment/tee_measurement
//                  /lineage/lineage_type
//                  /model_identity/model_hash
//                  and the verified immediate predecessor's model_hash
//                  (P6-17; task 10.12a)
//  Steps, in order; the first that yields a status ends the rule:
//    1. require_learned_state_components: learned_state_hash and every
//       component's hash are hashes, every component a positive size.
//    2. require_environment_pinned: training_software and software_hash.
//    3. require_tee: tee_measurement.
//    4. require_state_kept: a deployment or policy-change record keeps the
//       model of its verified immediate predecessor: the same value at the
//       member the pack's `compare` names, model_hash by default, or
//       learned_state_hash (QA QR-05).
//    5. Pass.
//  Fail:           a declared hash does not parse, a component declares a
//                  zero size, a required environment member is "", or a
//                  state-keeping step names another model
//
//  Task 10.12a: D12a-2 names the training software training_software, as
//  record format §8.5 defines it for any model (formerly engine_version).
//  D12a-3 (QA QC-02) compares model_hash, the model's identity, instead of
//  learned_state_hash, which follows each issuer's choice of components
//  (record format §7.3): a deployer listing other components of the same
//  model keeps it. In the engine profile the two are equal (§7.4).
//  Indeterminate:  a member a set requirement needs is absent or of another
//                  JSON type, or the context a state-keeping step needs is
//                  missing
//
//  P6-17 (E2, the owner, 2026-09-13): software_hash and tee_measurement are
//  required members whose schema value is "a hash or the empty string", so
//  "" is what an issuer signs to say "none", and a requirement for that
//  member fails on it; training_software, a required string, likewise. This
//  reverses P6-3's reading that made a record emitted without a TEE
//  indeterminate under require_tee: it is now non-compliant under it.
//
//  The §5 sketch's minimum_test_vectors and require_reference_suite are
//  deleted: the record carries no test-vector count (P6-3).
// ============================================================================

use super::{declared_string, fail, indeterminate, not_declared, not_present, pass, Verdict};
use crate::context::EvaluationContext;
use crate::evidence::pointer::{
    LEARNED_STATE_COMPONENTS, LEARNED_STATE_HASH, LINEAGE_TYPE, SOFTWARE_HASH,
    TEE_MEASUREMENT, TRAINING_SOFTWARE,
};
use crate::pack::ExecutionIntegrityRule;
use crate::schema::quote;
use serde_json::Value;
use vmr_record::hash::parse_hash;

/// The lineage steps that keep their predecessor's model (P6-17, the owner,
/// 2026-09-13; compared by `model_hash` since task 10.12a). The others -
/// `initial`, `training-update`, `fine-tune`, `quantization` - legitimately
/// change it.
const STATE_KEEPING_LINEAGE_TYPES: [&str; 2] = ["deployment", "policy-change"];

/// The string at `pointer`, the empty string included (E2), or `None` when
/// it is absent or not a string.
fn string_member<'a>(record: &'a Value, pointer: &str) -> Option<&'a str> {
    record.pointer(pointer).and_then(Value::as_str)
}

pub fn evaluate(
    rule: &ExecutionIntegrityRule,
    record: &Value,
    context: Option<&EvaluationContext>,
) -> Verdict {
    let mut met: Vec<String> = Vec::new();

    if rule.require_learned_state_components {
        let Some(state_hash) = declared_string(record, LEARNED_STATE_HASH) else {
            return not_declared(LEARNED_STATE_HASH);
        };
        if parse_hash(state_hash).is_err() {
            return fail(format!("learned_state_hash {} is not a sha256: hash", quote(state_hash)));
        }
        let Some(components) = record.pointer(LEARNED_STATE_COMPONENTS).and_then(Value::as_array)
        else {
            return not_declared(LEARNED_STATE_COMPONENTS);
        };
        if components.is_empty() {
            return not_declared(LEARNED_STATE_COMPONENTS);
        }
        for component in components {
            let name = component.get("name").and_then(Value::as_str).unwrap_or("(unnamed)");
            let Some(hash) = component.get("hash").and_then(Value::as_str).filter(|s| !s.is_empty())
            else {
                return indeterminate(format!(
                    "learned state component {} declares no hash",
                    quote(name)
                ));
            };
            if parse_hash(hash).is_err() {
                return fail(format!(
                    "learned state component {} carries {}, which is not a sha256: hash",
                    quote(name),
                    quote(hash)
                ));
            }
            let Some(size) = super::count(component.get("size_bytes")) else {
                return indeterminate(format!(
                    "learned state component {} declares no size_bytes",
                    quote(name)
                ));
            };
            if size == 0 {
                return fail(format!(
                    "learned state component {} declares size_bytes 0: a component of no bytes \
                     pins nothing",
                    quote(name)
                ));
            }
        }
        met.push(format!("{} learned state component(s) are pinned by hash and size", components.len()));
    }

    if rule.require_environment_pinned {
        let Some(training_software) = string_member(record, TRAINING_SOFTWARE) else {
            return not_present(TRAINING_SOFTWARE);
        };
        if training_software.is_empty() {
            return fail(
                "training_software is empty: the record names no training software, so the \
                 environment the learning ran in is not pinned",
            );
        }
        let Some(software) = string_member(record, SOFTWARE_HASH) else {
            return not_present(SOFTWARE_HASH);
        };
        if software.is_empty() {
            return fail(
                "software_hash is empty: the record declares that the software stack the \
                 learning ran in is not pinned by a hash",
            );
        }
        if parse_hash(software).is_err() {
            return fail(format!("software_hash {} is not a sha256: hash", quote(software)));
        }
        met.push(format!("the environment is pinned: training software {}", quote(training_software)));
    }

    if rule.require_tee {
        let Some(tee) = string_member(record, TEE_MEASUREMENT) else {
            return not_present(TEE_MEASUREMENT);
        };
        if tee.is_empty() {
            return fail(
                "tee_measurement is empty: the record declares that no trusted execution \
                 environment measured the learning",
            );
        }
        if parse_hash(tee).is_err() {
            return fail(format!("tee_measurement {} is not a sha256: hash", quote(tee)));
        }
        met.push("a TEE measurement is declared".into());
    }

    if rule.require_state_kept {
        let Some(lineage_type) = declared_string(record, LINEAGE_TYPE) else {
            return not_declared(LINEAGE_TYPE);
        };
        if !STATE_KEEPING_LINEAGE_TYPES.contains(&lineage_type) {
            met.push(format!("a {} record may change its model", quote(lineage_type)));
        } else {
            // QA QR-05 (the owner, 2026-09-16): the pack names the member,
            // model_hash by default.
            let compared = rule.compare.pointer();
            let member = rule.compare.id();
            let Some(own) = declared_string(record, compared) else {
                return not_declared(compared);
            };
            let Ok(own_digest) = parse_hash(own) else {
                return fail(format!("{member} {} is not a sha256: hash", quote(own)));
            };
            let Some(context) = context else {
                return indeterminate(format!(
                    "a {} record must keep its predecessor's model, and this evaluation was given \
                     no verification context",
                    quote(lineage_type)
                ));
            };
            let Some(predecessor) = context.immediate_predecessor() else {
                return indeterminate(format!(
                    "a {} record must keep its predecessor's model, and its immediate predecessor \
                     was not supplied to verification (vmr record verify --previous)",
                    quote(lineage_type)
                ));
            };
            let Some(theirs) = declared_string(&predecessor.record, compared) else {
                return indeterminate(format!(
                    "the verified immediate predecessor declares no {member}"
                ));
            };
            let Ok(their_digest) = parse_hash(theirs) else {
                return indeterminate(format!(
                    "the verified immediate predecessor's {member} {} is not a sha256: hash",
                    quote(theirs)
                ));
            };
            if own_digest != their_digest {
                return fail(format!(
                    "a {} record must keep its predecessor's model, but its {member} {} differs \
                     from the verified immediate predecessor's {}",
                    quote(lineage_type),
                    quote(own),
                    quote(theirs)
                ));
            }
            met.push(format!(
                "the {} record keeps its verified predecessor's model, by {member}",
                quote(lineage_type)
            ));
        }
    }

    if met.is_empty() {
        // Unreachable through a loaded pack: `validate` refuses an
        // execution_integrity rule that sets no requirement (P6-9).
        return indeterminate("the rule sets no execution requirement");
    }
    pass(met.join("; "))
}
