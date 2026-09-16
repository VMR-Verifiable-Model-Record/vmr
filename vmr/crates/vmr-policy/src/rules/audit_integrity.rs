//! `audit_integrity`: the audit trail is long enough, tamper-evident,
//! ordered, committed and verified.
// ============================================================================
//  audit_integrity.rs (P6-3, extended by P6-17 and task 10.12a)
//
//  Reads:          /lineage/lineage_chain_length
//                  /lineage/previous_record_hash
//                  /learning_provenance/training_input_merkle_root
//                  /learning_provenance/training_input_count
//                  /learning_provenance/training_started_at
//                  /learning_provenance/training_ended_at
//                  /learning_provenance/training_input_provenance/collection_period/start
//                  /learning_provenance/training_input_provenance/collection_period/end
//                  /issued_at
//                  /learning_provenance/training_input_disclosure
//                  and the verification context's lineage (P6-17)
//  Steps, in order; the first that yields a status ends the rule:
//    1. lineage_chain_length is not a count: Indeterminate.
//    2. it is below minimum_chain_length: Fail.
//    3. require_tamper_evident: a declared training_input_disclosure
//       answers the commitment at the pack's `withheld` status (task
//       10.12a; QA QR-04); otherwise the Merkle root is a hash (else Fail,
//       or Indeterminate when not declared). Either way, a chain longer
//       than one record names its predecessor by a hash, likewise, and both
//       reasons are reported.
//    4. require_input_committed: a declared training_input_disclosure
//       answers at the pack's `withheld` status (task 10.12a; QA QR-04);
//       the count is a count and the root a hash (else Indeterminate / Fail
//       as in 3); a count of 0 commits to nothing, Fail; a count of 1 or
//       more over the empty tree's root contradicts itself, Fail.
//
//  Task 10.12a (D12a-5): training_input_disclosure, `not-held` or
//  `not-disclosed` (record format §8.4), is a signed statement that the
//  record commits to no training input, so both requirements for the
//  commitment answer on it, as a signed "" fails an environment requirement
//  (E2). Before, such a record was Indeterminate at its "" root. QA QR-04
//  (the owner, 2026-09-16): the pack's `withheld` says with which status,
//  `fail` by default - the five reference packs keep that - or
//  `indeterminate` for a pack that tolerates withholding. The step still
//  checks the lineage linkage, so a withholding record with a broken link
//  reports both reasons.
//    5. require_ordered_record: the five times are timestamps (else
//       Indeterminate); training ending before it starts, a collection
//       period ending before it starts, or training ending after issued_at is
//       Fail. The reference builder refuses to sign these (QA P5-08); no
//       verifier check covers them, so another issuer's record can carry
//       one and verify.
//    6. require_verified_lineage: Pass when verification reached the initial
//       record (outcome initial or complete), or, with no context, when the
//       chain is one record long. Otherwise Indeterminate: a lineage not
//       shown to its origin did not say, it did not say the wrong thing.
//    7. Pass.
//
//  "Tamper-evident" is defined by P6-3 in terms of what the record
//  actually carries: the commitment to the training input, and the link to
//  the predecessor. A chain of one record has no predecessor, so its
//  absent previous_record_hash is not held against it - that is the spec's
//  own lineage rule (§6.5), not a gap in the evidence.
// ============================================================================

use super::{declared_string, fail, indeterminate, not_declared, pass, Verdict};
use crate::context::{EvaluationContext, LineageOutcome};
use crate::evidence::pointer::{
    COLLECTION_PERIOD_END, COLLECTION_PERIOD_START, ISSUED_AT, LINEAGE_CHAIN_LENGTH,
    PREVIOUS_RECORD_HASH, TRAINING_ENDED_AT, TRAINING_INPUT_COUNT, TRAINING_INPUT_DISCLOSURE,
    TRAINING_INPUT_MERKLE_ROOT, TRAINING_STARTED_AT,
};
use crate::evaluation::Status;
use crate::pack::{AuditIntegrityRule, Withheld};
use crate::schema::quote;
use serde_json::Value;
use vmr_record::hash::parse_hash;
use vmr_record::merkle::empty_root;
use vmr_record::timestamp::Timestamp;

/// Task 10.12a (D12a-5): a declared `training_input_disclosure` answers a
/// requirement for the commitment to the training input. QA QR-04 (the owner,
/// 2026-09-16): the pack's `withheld` says with which status - `fail` by
/// default, `indeterminate` for a pack that tolerates withholding.
fn withheld(setting: Withheld, disclosure: &str) -> Verdict {
    let detail = format!(
        "training_input_disclosure is {}: the record declares that it commits to no training \
         input, so the training input is not committed",
        quote(disclosure)
    );
    match setting {
        Withheld::Fail => fail(detail),
        Withheld::Indeterminate => indeterminate(detail),
    }
}

/// Two reasons of one requirement, reported together at the heavier status
/// (QA QR-04: a withholding record must not hide a broken chain link).
fn both(first: Verdict, second: Verdict) -> Verdict {
    let status = match (first.0, second.0) {
        (Status::Fail, _) | (_, Status::Fail) => Status::Fail,
        _ => Status::Indeterminate,
    };
    (status, format!("{}; {}", first.1, second.1))
}

pub fn evaluate(rule: &AuditIntegrityRule, record: &Value, context: Option<&EvaluationContext>) -> Verdict {
    let Some(length) = super::count(record.pointer(LINEAGE_CHAIN_LENGTH)) else {
        return not_declared(LINEAGE_CHAIN_LENGTH);
    };
    if length < rule.minimum_chain_length {
        return fail(format!(
            "lineage_chain_length {length} is below the required {}",
            rule.minimum_chain_length
        ));
    }
    let mut met = vec![format!("lineage_chain_length {length} meets the required {}", rule.minimum_chain_length)];

    if rule.require_tamper_evident {
        // A withheld training input answers the commitment half of the
        // requirement; the lineage-linkage half below is still checked, and
        // both reasons are reported (QA QR-04).
        let mut commitment: Option<Verdict> = None;
        if let Some(disclosure) = declared_string(record, TRAINING_INPUT_DISCLOSURE) {
            commitment = Some(withheld(rule.withheld, disclosure));
        } else {
            let Some(root) = declared_string(record, TRAINING_INPUT_MERKLE_ROOT) else {
                return not_declared(TRAINING_INPUT_MERKLE_ROOT);
            };
            if parse_hash(root).is_err() {
                return fail(format!(
                    "training_input_merkle_root {} is not a sha256: hash, so the training input is \
                     not committed",
                    quote(root)
                ));
            }
            met.push("the training input is committed by a Merkle root".into());
        }

        let linkage: Option<Verdict> = if length > 1 {
            match declared_string(record, PREVIOUS_RECORD_HASH) {
                None => Some(not_declared(PREVIOUS_RECORD_HASH)),
                Some(previous) if parse_hash(previous).is_err() => Some(fail(format!(
                    "previous_record_hash {} is not a sha256: hash, so the chain is not linked",
                    quote(previous)
                ))),
                Some(_) => {
                    met.push("the predecessor is named by its hash".into());
                    None
                }
            }
        } else {
            met.push("an initial record has no predecessor to link".into());
            None
        };

        match (commitment, linkage) {
            (Some(c), Some(l)) => return both(c, l),
            (Some(c), None) => return c,
            (None, Some(l)) => return l,
            (None, None) => {}
        }
    }

    if rule.require_input_committed {
        if let Some(disclosure) = declared_string(record, TRAINING_INPUT_DISCLOSURE) {
            return withheld(rule.withheld, disclosure);
        }
        let Some(count) = super::count(record.pointer(TRAINING_INPUT_COUNT)) else {
            return not_declared(TRAINING_INPUT_COUNT);
        };
        let Some(root) = declared_string(record, TRAINING_INPUT_MERKLE_ROOT) else {
            return not_declared(TRAINING_INPUT_MERKLE_ROOT);
        };
        let Ok(digest) = parse_hash(root) else {
            return fail(format!(
                "training_input_merkle_root {} is not a sha256: hash, so the training input is \
                 not committed",
                quote(root)
            ));
        };
        if count == 0 {
            return fail("training_input_count is 0: the record commits to no training input");
        }
        if digest == empty_root() {
            return fail(format!(
                "training_input_count is {count}, but training_input_merkle_root is the root of \
                 the empty tree: the commitment contradicts its own count"
            ));
        }
        met.push(format!("{count} training input frame(s) are committed by a Merkle root"));
    }

    if rule.require_ordered_record {
        let time = |pointer: &str| -> Result<Timestamp, Verdict> {
            let Some(text) = declared_string(record, pointer) else {
                return Err(not_declared(pointer));
            };
            Timestamp::parse(text).map_err(|_| {
                indeterminate(format!("{pointer} is {}, which is not a timestamp", quote(text)))
            })
        };
        let times = [TRAINING_STARTED_AT, TRAINING_ENDED_AT, COLLECTION_PERIOD_START, COLLECTION_PERIOD_END, ISSUED_AT]
            .map(time);
        let [started, ended, from, to, issued] = match times {
            [Ok(a), Ok(b), Ok(c), Ok(d), Ok(e)] => [a, b, c, d, e],
            [a, b, c, d, e] => {
                let first_error = [a, b, c, d, e].into_iter().find_map(Result::err);
                return first_error.unwrap_or_else(|| indeterminate("a time of the record is not a timestamp"));
            }
        };
        if ended < started {
            return fail(format!(
                "training_ended_at {ended} is before training_started_at {started}: training \
                 cannot end before it starts"
            ));
        }
        if to < from {
            return fail(format!(
                "collection_period end {to} is before its start {from}: a collection period \
                 cannot end before it starts"
            ));
        }
        if ended > issued {
            return fail(format!(
                "training_ended_at {ended} is after issued_at {issued}: the record records \
                 training that had not ended when it was issued"
            ));
        }
        met.push("the record's times are in order".into());
    }

    if rule.require_verified_lineage {
        match context.map(|c| c.lineage.outcome) {
            Some(LineageOutcome::Initial) | Some(LineageOutcome::Complete) => {
                met.push("verification reached the initial record".into());
            }
            Some(LineageOutcome::NotChecked) => {
                return indeterminate(format!(
                    "the lineage of {length} records was not verified: none of its predecessors \
                     was supplied to verification (vmr record verify --previous)"
                ));
            }
            Some(LineageOutcome::Partial) => {
                return indeterminate(format!(
                    "the lineage of {length} records was verified only in part: the predecessors \
                     supplied to verification stop before its initial record (supply the rest \
                     with vmr record verify --previous)"
                ));
            }
            None if length == 1 => met.push("an initial record has no lineage to verify".into()),
            None => {
                return indeterminate(format!(
                    "the lineage of {length} records was not verified: this evaluation was given \
                     no verification context"
                ));
            }
        }
    }
    pass(met.join("; "))
}
