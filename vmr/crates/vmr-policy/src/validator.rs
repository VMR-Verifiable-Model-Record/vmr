//! Everything a pack must satisfy beyond parsing: values, ids, substance.
// ============================================================================
//  validator.rs — the checks a loader runs before a pack may be evaluated
//
//  Three groups, in order:
//
//    1. the schema's value rules (`crate::schema::validate_values`);
//    2. identity: `rule_id` is unique inside the pack, or a result could not
//       be attributed to one rule;
//    3. substance (P6-9, P6-17): a rule must state a requirement that some
//       record can fail. P6-3 deleted two rule parameters because a rule
//       that is always Indeterminate "poisons every pack that contains it";
//       a rule that asks for nothing is the same mistake with the other
//       sign - it looks like policy and constrains nothing. Refused: a rule
//       whose parameters ask for nothing at all (no flag set, a chain length
//       of 0); an `audit_integrity` rule whose only requirement is
//       `require_verified_lineage`, which never fails; and an
//       `attestation_level` rule asking for `self`, which every record
//       that declares a level meets (P6-17, V3, the owner, 2026-09-13). A
//       setting that only a verified record meets by construction still
//       loads - the library evaluates unverified payloads too, where it can
//       fail - and the reference packs are held to failability by their own
//       test (`every_mandatory_rule_of_a_reference_pack_can_fail_on_a_valid_record`).
//       The refusal hints name only settings that can fail.
//
//  Every refusal is a typed `Error` with the pack member that caused it.
// ============================================================================

use crate::error::Error;
use crate::pack::{PolicyPack, Rule};
use crate::schema;
use std::collections::BTreeSet;

/// Check a parsed pack. `Ok(())` means it may be evaluated.
pub fn validate(pack: &PolicyPack) -> Result<(), Error> {
    schema::validate_values(pack)?;

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for rule in &pack.rules {
        let id = rule.rule_id();
        if !seen.insert(id) {
            return Err(Error::DuplicateRuleId(id.to_string()));
        }
        if let Some(detail) = states_no_requirement(rule) {
            return Err(Error::RuleWithoutRequirement {
                rule_id: id.to_string(),
                detail: detail.to_string(),
            });
        }
    }
    Ok(())
}

/// The settings that would make this rule ask for something a record can
/// fail, or `None` when it already does. `data_residency` and
/// `source_screening` always ask: their lists are non-empty (the schema).
/// `documentation_declared` always asks too: its `document` is required, and
/// a record without that member fails it (task 10.11a).
fn states_no_requirement(rule: &Rule) -> Option<&'static str> {
    match rule {
        Rule::ExportControl(v) if !v.require_air_gapped && !v.require_egress_denied => {
            Some("set require_air_gapped or require_egress_denied")
        }
        Rule::AuditIntegrity(v)
            if v.minimum_chain_length == 0
                && !v.require_tamper_evident
                && !v.require_ordered_record
                && !v.require_input_committed =>
        {
            Some(
                "set require_ordered_record, require_input_committed, require_tamper_evident, or a \
                 minimum_chain_length of 2 or more; require_verified_lineage alone never fails",
            )
        }
        Rule::ExecutionIntegrity(v)
            if !v.require_learned_state_components
                && !v.require_environment_pinned
                && !v.require_tee
                && !v.require_state_kept =>
        {
            Some(
                "set require_learned_state_components, require_environment_pinned, require_tee or \
                 require_state_kept",
            )
        }
        Rule::AttestationLevel(v) if v.minimum_level == "self" => Some(
            "set minimum_level to software or hardware: every record that declares an \
             attestation level declares at least self",
        ),
        _ => None,
    }
}
