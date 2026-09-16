//! `attestation_level`: the issuer attests at least at the required level.
// ============================================================================
//  attestation_level.rs (P6-3)
//
//  Reads:          /issuer/attestation_level
//  Pass:           the declared level is at least minimum_level, ordered
//                  self < software < hardware
//  Fail:           it is weaker
//  Indeterminate:  it is absent, empty, or a word this build does not know
//
//  A level the pack asks for that this build does not know cannot happen
//  through a loaded pack (the schema's enum), and is answered Indeterminate
//  rather than assumed, so a future level can never be read as "weakest".
//
//  The declared level is the issuer's claim. What the TRUST STORE grants the
//  signing key is a different question, and the verifier answers it
//  (`trust.attestation`, spec §6.2 check 17) before any pack is evaluated.
// ============================================================================

use super::{declared_string, fail, indeterminate, not_declared, pass, Verdict};
use crate::evidence::pointer::ATTESTATION_LEVEL;
use crate::pack::AttestationLevelRule;
use crate::schema::{quote, ATTESTATION_LEVELS};
use serde_json::Value;

/// The level's rank, weakest 0; `None` for a word this build does not know.
fn rank(level: &str) -> Option<usize> {
    ATTESTATION_LEVELS.iter().position(|l| *l == level)
}

pub fn evaluate(rule: &AttestationLevelRule, record: &Value) -> Verdict {
    let Some(declared) = declared_string(record, ATTESTATION_LEVEL) else {
        return not_declared(ATTESTATION_LEVEL);
    };
    let Some(have) = rank(declared) else {
        return indeterminate(format!(
            "the record declares attestation_level {}, which is not one of {:?}",
            quote(declared),
            ATTESTATION_LEVELS
        ));
    };
    let Some(want) = rank(&rule.minimum_level) else {
        return indeterminate(format!(
            "the pack requires attestation_level {}, which is not one of {:?}",
            quote(&rule.minimum_level),
            ATTESTATION_LEVELS
        ));
    };
    if have >= want {
        pass(format!(
            "declared attestation_level {} is at least the required {}",
            quote(declared),
            quote(&rule.minimum_level)
        ))
    } else {
        fail(format!(
            "declared attestation_level {} is weaker than the required {}",
            quote(declared),
            quote(&rule.minimum_level)
        ))
    }
}
