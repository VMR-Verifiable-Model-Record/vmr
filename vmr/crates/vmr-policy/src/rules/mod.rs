//! The seven rule evaluators and the dispatcher over a pack.
// ============================================================================
//  rules/mod.rs — one evaluator per rule type (P6-3)
//
//  Each evaluator reads the JSON pointers of the P6-3 table (extended by
//  P6-17) and nothing else, and answers Pass, Fail or Indeterminate. The
//  rules that hold everywhere:
//
//    * a field the rule reads that is ABSENT, of another JSON type, or an
//      empty string where a value is required, is Indeterminate - never
//      Fail. A record that did not say is not a record that said the
//      wrong thing.
//    * one exception (P6-17, E2, the owner, 2026-09-13): the required
//      members whose value is "a hash or the empty string" -
//      `software_hash`, `tee_measurement` - and `training_software` are
//      DECLARED when empty. "" is what an issuer signs to say "none", so a
//      requirement for that member fails on it.
//    * a second exception (task 10.11a, D11-4, the reviewer, 2026-09-13):
//      `data_governance` and `human_oversight` are OPTIONAL members, so an
//      absent one is how a record declares that it pins no such document,
//      and `documentation_declared` fails on it. A `null` one is a member of
//      the wrong type, and Indeterminate.
//    * a setting that needs verification context (`crate::context`) and
//      has none is Indeterminate, never a pass.
//    * a count (`count`) is a JSON integer from 0 to 2^53 - 1; a larger
//      integer, or a number with a fraction or an exponent, is not one
//      (QA Q7-05 S1 and S2, the owner, 2026-09-13).
//    * string comparison is exact and case-sensitive.
//
//  Nothing here reads a clock, a file or the network, and nothing panics:
//  every value is fetched through `serde_json::Value::pointer` and every
//  absence has an answer. A value at a member the rule reads that nests more
//  than `evidence::MAX_DEPTH` arrays and objects is not read at all, by the
//  evaluator or by the evidence hash: the rule is Indeterminate, so a value
//  built in code cannot overflow the stack (Law 9, QA Q6-04).
// ============================================================================

mod attestation_level;
mod audit_integrity;
mod data_residency;
mod documentation_declared;
mod execution_integrity;
mod export_control;
mod source_screening;

use crate::context::EvaluationContext;
use crate::evaluation::{Evaluation, RuleResult, Status};
use crate::evidence;
use crate::pack::{PolicyPack, Rule};
use serde_json::Value;
use vmr_record::timestamp::Timestamp;

/// Evaluate every rule of `pack` against a record payload, with the
/// verification context when there is one.
pub fn evaluate_all(
    pack: &PolicyPack,
    record: &Value,
    context: Option<&EvaluationContext>,
    evaluated_at: Timestamp,
) -> Evaluation {
    let results = pack.rules.iter().map(|rule| evaluate_one_in_context(rule, record, context)).collect();
    Evaluation::new(pack, evaluated_at, results)
}

/// Evaluate one rule against a record payload, without context.
pub fn evaluate_one(rule: &Rule, record: &Value) -> RuleResult {
    evaluate_one_in_context(rule, record, None)
}

/// Evaluate one rule against a record payload, with the verification
/// context when there is one (P6-17).
pub fn evaluate_one_in_context(rule: &Rule, record: &Value, context: Option<&EvaluationContext>) -> RuleResult {
    // A context that adds nothing to the record is neither read nor hashed
    // (P6-17, `EvaluationContext::applies_to`).
    let context = crate::context::applicable(context, record);
    let (status, detail) = match evidence::too_deep(record, evidence::pointers(rule)) {
        Some(pointer) => nested_too_deep(pointer),
        None => match rule {
            Rule::DataResidency(r) => data_residency::evaluate(r, record),
            Rule::SourceScreening(r) => source_screening::evaluate(r, record),
            Rule::ExportControl(r) => export_control::evaluate(r, record),
            Rule::AuditIntegrity(r) => audit_integrity::evaluate(r, record, context),
            Rule::ExecutionIntegrity(r) => execution_integrity::evaluate(r, record, context),
            Rule::AttestationLevel(r) => attestation_level::evaluate(r, record),
            Rule::DocumentationDeclared(r) => documentation_declared::evaluate(r, record),
        },
    };
    let common = rule.common();
    RuleResult {
        rule_id: common.rule_id.to_string(),
        rule_type: rule.rule_type().to_string(),
        severity: common.severity,
        reference: common.reference.to_string(),
        status,
        evidence_hash: evidence::hash_for_in_context(rule, record, context),
        detail,
    }
}

/// What one evaluator answers: a status and why.
pub(crate) type Verdict = (Status, String);

pub(crate) fn pass(detail: impl Into<String>) -> Verdict {
    (Status::Pass, detail.into())
}

pub(crate) fn fail(detail: impl Into<String>) -> Verdict {
    (Status::Fail, detail.into())
}

pub(crate) fn indeterminate(detail: impl Into<String>) -> Verdict {
    (Status::Indeterminate, detail.into())
}

/// The string at `pointer`, or `None` when it is absent, not a string, or
/// empty: the three cases P6-3 makes Indeterminate.
pub(crate) fn declared_string<'a>(record: &'a Value, pointer: &str) -> Option<&'a str> {
    record.pointer(pointer).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// The count `value` holds: a JSON integer from 0 to 2^53 - 1
/// (`vmr_record::canonical::MAX_SAFE_INTEGER`), or `None` for anything
/// else - absent, another JSON type, a number written with a fraction, an
/// exponent or a minus sign, or an integer above that bound (QA Q7-05 S1 and
/// S2, the owner, 2026-09-13). Above 2^53 - 1 the evidence hash holds the
/// nearest double (RFC 8785), so two different values would share one hash
/// and compare differently; such a value is not a count, and the step that
/// needs one is Indeterminate.
pub(crate) fn count(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64).filter(|n| *n <= vmr_record::canonical::MAX_SAFE_INTEGER)
}

/// The answer for a member too deeply nested to read: Indeterminate, naming
/// it and the bound.
fn nested_too_deep(pointer: &str) -> Verdict {
    indeterminate(format!(
        "{pointer} nests arrays or objects more than {} levels deep, which no parsed document \
         can; it is not read",
        evidence::MAX_DEPTH
    ))
}

/// "`<pointer>` is not declared" - the one wording every evaluator uses for
/// a field it needs and did not get.
pub(crate) fn not_declared(pointer: &str) -> Verdict {
    indeterminate(format!("{pointer} is not declared, or is empty"))
}

/// The wording for a P6-17 (E2) member that is absent or not a string: an
/// empty one is declared, so "or is empty" does not apply.
pub(crate) fn not_present(pointer: &str) -> Verdict {
    indeterminate(format!("{pointer} is not declared"))
}

/// The declared countries of the training data (record format §8.5; task
/// 10.12a, D12a-4), each with the member that declares it: `data_residency`
/// when it is a declared string, then every code of
/// `data_residency_countries` when that is an array. The list is read only
/// whole: an empty array, or an element that is not a declared string, said
/// nothing checkable, and is Indeterminate even beside a declared
/// `data_residency`. A list that is not an array is not declared. With no
/// code at all the answer is Indeterminate too.
pub(crate) fn declared_residency(record: &Value) -> Result<Vec<(&'static str, &str)>, Verdict> {
    use crate::evidence::pointer::{DATA_RESIDENCY, DATA_RESIDENCY_COUNTRIES};
    let mut codes: Vec<(&'static str, &str)> =
        declared_string(record, DATA_RESIDENCY).map(|code| ("data_residency", code)).into_iter().collect();
    if let Some(list) = record.pointer(DATA_RESIDENCY_COUNTRIES).and_then(Value::as_array) {
        if list.is_empty() {
            return Err(not_declared(DATA_RESIDENCY_COUNTRIES));
        }
        for element in list {
            let Some(code) = element.as_str().filter(|s| !s.is_empty()) else {
                return Err(indeterminate(format!(
                    "{DATA_RESIDENCY_COUNTRIES} holds an element that is not a declared string, so the \
                     countries are not declared"
                )));
            };
            codes.push(("data_residency_countries", code));
        }
    }
    if codes.is_empty() {
        return Err(not_declared(DATA_RESIDENCY));
    }
    Ok(codes)
}

/// The declared countries as a detail reads them: `data_residency "PH"`,
/// `data_residency_countries "DE", "FR"`, or both joined by "and".
pub(crate) fn described_residency(codes: &[(&str, &str)]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for member in ["data_residency", "data_residency_countries"] {
        let quoted: Vec<String> =
            codes.iter().filter(|(m, _)| *m == member).map(|(_, code)| crate::schema::quote(code)).collect();
        if !quoted.is_empty() {
            parts.push(format!("{member} {}", quoted.join(", ")));
        }
    }
    parts.join(" and ")
}
