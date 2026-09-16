// ============================================================================
//  profile.rs — the kinds an entry may carry are a profile's, not the core's
//  (`specs/audit-log-format-v0.1.md` §5).
// ============================================================================

//! An entry profile: the vocabulary of kinds one writer uses, and the rules
//! its detail follows. The core checks an entry's shape (§4.1) and hands the
//! kind and the detail to the profile, so a log from any writer is read by the
//! same code.

use crate::error::Error;
use serde_json::Value;

/// The kinds and detail rules of one log writer (§5). A verifier is given the
/// profile along with the audit key it pins; no member of the log names it.
pub trait EntryProfile {
    /// The profile's name, `<owner>.<name>`, as §5 registers it.
    fn name(&self) -> &str;

    /// Check `kind` and its `detail`, which the core has already read as a
    /// string and an object. A refusal is `audit_entry.structure`, the core's
    /// own id, so a reader reports one refusal whatever the profile.
    fn check(&self, kind: &str, detail: &Value) -> Result<(), Error>;
}

/// The core profile: every kind the core's grammar allows (§5.1), with any
/// object as its detail. It is what a reader uses for a log whose profile it
/// does not have; it checks the log's shape, chain, signatures and proofs, and
/// nothing about the meaning of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Core;

impl EntryProfile for Core {
    fn name(&self) -> &str {
        "vmr.audit-core"
    }

    fn check(&self, _kind: &str, _detail: &Value) -> Result<(), Error> {
        Ok(())
    }
}

/// The core profile ([`Core`]).
pub const CORE: Core = Core;
