//! The result of evaluating a pack, and its conversion for a record.
// ============================================================================
//  evaluation.rs — Evaluation, RuleResult, Status (P6-1, P6-2, P6-5)
//
//  The crate's own result is three-valued per rule - Pass, Fail,
//  Indeterminate - because a record that does not declare a field has not
//  broken the rule, it has left it unanswerable (P6-3). The overall status
//  is computed from the MANDATORY rules only: a mandatory failure is Fail;
//  a mandatory indeterminate with no failure is Indeterminate; otherwise
//  Pass. Recommended and informational rules are reported and do not move it.
//
//  The record's `policy_compliance` cannot express Indeterminate per rule
//  (`specs/record-schema/v0.1.json`: the enum is pass | fail, and
//  `evidence_hash` is required), so [`Evaluation::to_policy_compliance`]
//  omits indeterminate rules from `results` and the evaluation keeps their
//  ids in [`Evaluation::indeterminate`] (P6-1). The crate keeps its own
//  names and converts at that one boundary; the record's names do not move.
//
//  The evaluation time is an input (P6-5): nothing here reads a clock.
// ============================================================================

use crate::pack::{PolicyPack, Severity};
use serde::Serialize;
use vmr_record::record::{PolicyCompliance, PolicyResult};
use vmr_record::timestamp::Timestamp;

/// What a rule said about a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The record satisfies the rule.
    Pass,
    /// The record declares something the rule forbids.
    Fail,
    /// The record does not say enough to decide: a field the rule reads is
    /// absent, or empty where a value is required (P6-3). Never a failure.
    Indeterminate,
}

impl Status {
    /// The word this status is written with.
    pub fn id(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Indeterminate => "indeterminate",
        }
    }

    /// The record's `overall_status` word for this status (P6-1).
    pub fn overall_id(self) -> &'static str {
        match self {
            Status::Pass => "compliant",
            Status::Fail => "non-compliant",
            Status::Indeterminate => "indeterminate",
        }
    }
}

/// One rule's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleResult {
    /// The rule's identifier, from the pack.
    pub rule_id: String,
    /// The rule's `type`, e.g. `data_residency`.
    pub rule_type: String,
    /// How a failure of this rule weighs.
    pub severity: Severity,
    /// The clause the rule encodes (P6-4), copied so a result can be read
    /// without the pack beside it.
    pub reference: String,
    /// Pass, fail or indeterminate.
    pub status: Status,
    /// `sha256:` + the hex of the hash of what the rule read (P6-2).
    pub evidence_hash: String,
    /// Why, in English. Deterministic, and derived from the record's own
    /// declarations; a caller that prints it to a terminal passes it through
    /// its own escaping, as the CLI does for every record-derived string.
    pub detail: String,
}

/// The result of evaluating a whole pack against one record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evaluation {
    /// The pack that was evaluated.
    pub pack_id: String,
    /// Its own version.
    pub pack_version: String,
    /// The regime it encodes.
    pub jurisdiction: String,
    /// When the caller says the evaluation happened (P6-5): an input, in the
    /// record's timestamp profile.
    #[serde(serialize_with = "as_string")]
    pub evaluated_at: Timestamp,
    /// Every rule of the pack, in the pack's order.
    pub results: Vec<RuleResult>,
    /// The ids of the rules that were indeterminate, in the pack's order
    /// (P6-1): they are the ones `to_policy_compliance` cannot carry.
    pub indeterminate: Vec<String>,
    /// The overall status, from the mandatory rules only.
    pub overall: Status,
}

fn as_string<S: serde::Serializer>(t: &Timestamp, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_string())
}

impl Evaluation {
    /// Assemble an evaluation from the results of a pack's rules.
    pub(crate) fn new(pack: &PolicyPack, evaluated_at: Timestamp, results: Vec<RuleResult>) -> Self {
        let overall = Self::compute_overall(&results);
        let indeterminate = results
            .iter()
            .filter(|r| r.status == Status::Indeterminate)
            .map(|r| r.rule_id.clone())
            .collect();
        Evaluation {
            pack_id: pack.pack_id.clone(),
            pack_version: pack.pack_version.clone(),
            jurisdiction: pack.jurisdiction.clone(),
            evaluated_at,
            results,
            indeterminate,
            overall,
        }
    }

    /// Fail if any mandatory rule failed; Indeterminate if any mandatory rule
    /// is indeterminate and none failed; Pass otherwise. The severity is read
    /// from the result, which carries the pack's, so this cannot silently
    /// treat an unknown rule as mandatory.
    pub fn compute_overall(results: &[RuleResult]) -> Status {
        let mandatory = results.iter().filter(|r| r.severity == Severity::Mandatory);
        let mut indeterminate = false;
        for r in mandatory {
            match r.status {
                Status::Fail => return Status::Fail,
                Status::Indeterminate => indeterminate = true,
                Status::Pass => {}
            }
        }
        if indeterminate {
            Status::Indeterminate
        } else {
            Status::Pass
        }
    }

    /// The result of one rule, by id.
    pub fn result(&self, rule_id: &str) -> Option<&RuleResult> {
        self.results.iter().find(|r| r.rule_id == rule_id)
    }

    /// This evaluation as the record's `policy_compliance` section (P6-1).
    ///
    /// `Pass` becomes `"pass"` and `Fail` becomes `"fail"`; an indeterminate
    /// rule is OMITTED from `results` - the v0.1 schema's enum has no word
    /// for it - and its id stays in [`Evaluation::indeterminate`]. The
    /// overall status becomes `compliant` / `non-compliant` /
    /// `indeterminate`, so a record whose mandatory rules could not be
    /// decided says so rather than claiming compliance.
    ///
    /// The section is the issuer's declaration once it is signed
    /// (`specs/record-format-v0.1.md` §6.6); `evaluated_at` must not be
    /// later than the record's `issued_at` (P6-6), which the builder and
    /// the verifier both check.
    pub fn to_policy_compliance(&self) -> PolicyCompliance {
        PolicyCompliance {
            policy_pack_id: self.pack_id.clone(),
            evaluated_at: self.evaluated_at.to_string(),
            results: self
                .results
                .iter()
                .filter(|r| r.status != Status::Indeterminate)
                .map(|r| PolicyResult {
                    rule_id: r.rule_id.clone(),
                    status: r.status.id().to_string(),
                    evidence_hash: r.evidence_hash.clone(),
                })
                .collect(),
            overall_status: self.overall.overall_id().to_string(),
        }
    }
}
