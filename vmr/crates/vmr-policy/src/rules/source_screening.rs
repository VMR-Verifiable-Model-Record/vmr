//! `source_screening`: no declared origin is on a restricted list.
// ============================================================================
//  source_screening.rs (P6-3, extended by task 10.12a)
//
//  Reads:          /learning_provenance/training_input_provenance/source_type
//                  /learning_provenance/training_input_provenance/data_residency
//                  /learning_provenance/training_input_provenance/data_residency_countries
//  Pass:           neither the source type nor any declared country appears
//                  in restricted_list
//  Fail:           at least one does
//  Indeterminate:  the source type is absent or empty, or no country is
//                  declared (`declared_residency`)
//
//  Task 10.12a (D12a-4): each country of data_residency_countries is
//  screened as data_residency is.
//
//  `source_description` is free text and is NEVER matched (P6-3): screening
//  a prose field would make the result depend on how an issuer phrased it.
//  The §9 sketch read a `source_identifiers` array, which no record has.
// ============================================================================

use super::{declared_residency, declared_string, described_residency, fail, not_declared, pass, Verdict};
use crate::evidence::pointer::SOURCE_TYPE;
use crate::pack::SourceScreeningRule;
use crate::schema::quote;
use serde_json::Value;

pub fn evaluate(rule: &SourceScreeningRule, record: &Value) -> Verdict {
    let Some(source_type) = declared_string(record, SOURCE_TYPE) else {
        return not_declared(SOURCE_TYPE);
    };
    let codes = match declared_residency(record) {
        Ok(codes) => codes,
        Err(verdict) => return verdict,
    };
    let restricted = |v: &str| rule.restricted_list.iter().any(|r| r == v);
    let hits: Vec<&str> = std::iter::once(source_type)
        .chain(codes.iter().map(|(_, code)| *code))
        .filter(|v| restricted(v))
        .collect();
    if hits.is_empty() {
        pass(format!(
            "neither source_type {} nor {} is restricted",
            quote(source_type),
            described_residency(&codes)
        ))
    } else {
        fail(format!(
            "restricted origin declared: {}",
            hits.iter().map(|h| quote(h)).collect::<Vec<_>>().join(", ")
        ))
    }
}
