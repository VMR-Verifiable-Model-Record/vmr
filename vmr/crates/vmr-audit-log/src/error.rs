//! Typed refusals, each with a stable id.
// ============================================================================
//  error.rs — one refusal id per way a document or a log is refused.
//
//  Every id is a `<namespace>.<name>` string from
//  `specs/audit-log-format-v0.1.md`: `audit_entry.*`, `audit_log.*`,
//  `checkpoint.*` and `audit_proof.*`. A format that builds on this one adds
//  its own (the enforcer's `bundle.*`, `export_token.*` and `startup.*`).
//  A refusal names the id and a message; nothing here panics and
//  nothing here is a verification result — a bad document is an operator or a
//  peer error, exactly as a bad trust store is in vmr-verify.
//
//  An `Io` variant carries an operating-system failure (a locked log, a write
//  that did not land): not a refusal id, an operator error.
// ============================================================================

/// Why an audit-log document, a log or an operation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A refusal with one of the format's stable ids.
    #[error("{id}: {message}")]
    Refused {
        /// The `<namespace>.<name>` id from the format document.
        id: &'static str,
        /// What was wrong, terminal-safe (see [`display_safe`]).
        message: String,
    },

    /// An operating-system failure: a file could not be opened, locked, read
    /// or written. Not a refusal id.
    #[error("io: {0}")]
    Io(String),
}

impl Error {
    /// A refusal with id `id` and message `message`, the message made
    /// terminal-safe.
    pub fn refused(id: &'static str, message: impl Into<String>) -> Self {
        Error::Refused { id, message: display_safe(&message.into()) }
    }

    /// An operating-system failure, its message made terminal-safe.
    pub fn io(message: impl Into<String>) -> Self {
        Error::Io(display_safe(&message.into()))
    }

    /// The refusal id, or `"io"` for an operating-system failure. Tests and
    /// the vectors compare against it.
    pub fn id(&self) -> &'static str {
        match self {
            Error::Refused { id, .. } => id,
            Error::Io(_) => "io",
        }
    }
}

/// A message with every character a terminal acts on or hides escaped, so a
/// refusal quoting a stranger's document (a bundle, a token, a log line)
/// cannot move the cursor or hide text. This is `vmr_verify::display_safe`,
/// which the crate already depends on.
pub fn display_safe(message: &str) -> String {
    vmr_verify::display_safe(message)
}
