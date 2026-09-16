//! What verification established, for the rules that read it (P6-17).
// ============================================================================
//  context.rs — the verification context an evaluation may be given
//
//  A record says what its issuer signed. Two P6-17 rule settings need more:
//  whether its lineage was verified back to its initial record
//  (`audit_integrity`'s `require_verified_lineage`), and the learned state of
//  its verified immediate predecessor (`execution_integrity`'s
//  `require_state_kept`). Only a verifier knows those.
//
//  This crate does not depend on the verifier (P6-10), so it states the
//  context in its own plain types, and the caller that holds a verification
//  result fills them in (`vmr-cli`'s `policy_pack.rs` does, from
//  `vmr_verify::policy::VerifiedRecord`). An evaluation without context
//  (`crate::evaluate`) answers those settings Indeterminate: missing context
//  never passes and never fails.
//
//  The context enters the evidence hash of the two rule types that can read
//  it, as one element after their record reads (`crate::evidence`).
//
//  A context counts only where it adds something to the record's own
//  members (`EvaluationContext::applies_to`): an outcome other than
//  `initial`, for a record whose chain is 2 or more long. Any other
//  context is neither hashed nor read, so an initial record gets the same
//  evidence hash from an issuer, from this crate without context and from a
//  verifier that supplies one (made normative 2026-09-13).
// ============================================================================

use crate::evidence::pointer::LINEAGE_CHAIN_LENGTH;
use serde_json::Value;

/// How far verification took a record's lineage (spec §6.5). A broken
/// lineage fails verification and is never evaluated, so it has no word here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageOutcome {
    /// An initial record, with no predecessor supplied.
    Initial,
    /// Every supplied link verified, back to an initial record.
    Complete,
    /// Every supplied link verified, but the walk ends at a non-initial
    /// record.
    Partial,
    /// A non-initial record, and no predecessor was supplied.
    NotChecked,
}

impl LineageOutcome {
    /// The word for this outcome, as the verification report writes it and
    /// as the evidence hash takes it.
    pub fn id(self) -> &'static str {
        match self {
            LineageOutcome::Initial => "initial",
            LineageOutcome::Complete => "complete",
            LineageOutcome::Partial => "partial",
            LineageOutcome::NotChecked => "not_checked",
        }
    }
}

/// A predecessor whose link verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPredecessor {
    /// Its signed-payload hash, as the verifier recomputed it: the value its
    /// successor's `previous_record_hash` matched.
    pub signed_payload_hash: String,
    /// The predecessor's record, as JSON.
    pub record: Value,
}

/// A record's lineage, as verification established it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageContext {
    /// How far the lineage was verified.
    pub outcome: LineageOutcome,
    /// The predecessors whose links verified, immediate predecessor first.
    pub predecessors: Vec<VerifiedPredecessor>,
}

/// What a verifier established about a record beyond what it says.
///
/// An evaluation takes the context as given. Only a context a verifier
/// produced, from the predecessors it verified, carries meaning, and this
/// crate does not verify it again: that would put a second verifier in the
/// evaluator, against P6-10. A context that contradicts its own predecessors
/// (`Complete` or `Partial` with none, `NotChecked` with some), which no
/// verifier produces, is evaluated as written (format document §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationContext {
    /// The verified lineage.
    pub lineage: LineageContext,
}

impl EvaluationContext {
    /// The verified immediate predecessor, when one was supplied.
    pub fn immediate_predecessor(&self) -> Option<&VerifiedPredecessor> {
        self.lineage.predecessors.first()
    }

    /// Whether this context says anything `record`'s own members do not
    /// (P6-17): an outcome other than `initial`, for a record whose
    /// `lineage_chain_length` is a count of 2 or more. A count is an integer
    /// from 0 to 2^53 - 1 (QA Q7-05 S2), so a larger value is not one.
    ///
    /// An initial outcome adds nothing. Neither does any outcome for a chain
    /// of 1: on every verified record a chain of 1 is exactly an initial
    /// record, because `lineage.consistency` (spec §6.5, check 20)
    /// requires `lineage_chain_length` 1 of `initial` and 2 or more of every
    /// other type. A context that adds nothing is neither hashed nor read:
    /// the evaluation is the one without context.
    pub fn applies_to(&self, record: &Value) -> bool {
        self.lineage.outcome != LineageOutcome::Initial
            && crate::rules::count(record.pointer(LINEAGE_CHAIN_LENGTH)).is_some_and(|n| n >= 2)
    }
}

/// `context` when it [applies to](EvaluationContext::applies_to) `record`,
/// and none otherwise: the context an evaluation of that record reads and
/// hashes.
pub fn applicable<'a>(context: Option<&'a EvaluationContext>, record: &Value) -> Option<&'a EvaluationContext> {
    context.filter(|c| c.applies_to(record))
}
