//! `data_residency`: every declared country of the training input is allowed.
// ============================================================================
//  data_residency.rs (P6-3, extended by task 10.12a)
//
//  Reads:          /learning_provenance/training_input_provenance/data_residency
//                  /learning_provenance/training_input_provenance/data_residency_countries
//  Pass:           every declared country is in allowed_jurisdictions
//  Fail:           one is not; the first is named
//  Indeterminate:  no country is declared, or the countries list is empty or
//                  holds an element that is not a declared string
//                  (`declared_residency`)
//
//  Task 10.12a (D12a-4): data kept in several countries is declared in
//  data_residency_countries (record format §8.5), and each of them must be
//  allowed. Before, the rule read data_residency alone and such a record was
//  Indeterminate.
//
//  The rule type is jurisdiction-agnostic on purpose: it is here for the
//  authorities whose law does require residency, not because any reference
//  standard does (P6-4).
//
//  A failure's detail names at most `LISTED` of the allowed entries and says
//  how many there are: a pack may list thousands, and a detail travels whole
//  in a report (QA Q6-10).
// ============================================================================

use super::{declared_residency, described_residency, fail, pass, Verdict};
use crate::pack::DataResidencyRule;
use crate::schema::quote;
use serde_json::Value;

/// The most allowed jurisdictions a failure's detail lists.
const LISTED: usize = 8;

pub fn evaluate(rule: &DataResidencyRule, record: &Value) -> Verdict {
    let codes = match declared_residency(record) {
        Ok(codes) => codes,
        Err(verdict) => return verdict,
    };
    let allowed = |code: &str| rule.allowed_jurisdictions.iter().any(|a| a == code);
    match codes.iter().find(|(_, code)| !allowed(code)) {
        None if codes.len() == 1 => pass(format!("declared {} is allowed", described_residency(&codes))),
        None => pass(format!("declared {} are all allowed", described_residency(&codes))),
        Some((member, code)) => {
            let named = if *member == "data_residency" {
                format!("declared data_residency {}", quote(code))
            } else {
                format!("data_residency_countries names {}, which", quote(code))
            };
            fail(format!(
                "{named} is not one of the {} allowed: {}",
                rule.allowed_jurisdictions.len(),
                listed(&rule.allowed_jurisdictions)
            ))
        }
    }
}

/// The first [`LISTED`] entries, quoted, and how many more there are.
fn listed(allowed: &[String]) -> String {
    let mut shown: Vec<String> = allowed.iter().take(LISTED).map(|a| quote(a)).collect();
    if allowed.len() > LISTED {
        shown.push(format!("and {} more", allowed.len() - LISTED));
    }
    shown.join(", ")
}
