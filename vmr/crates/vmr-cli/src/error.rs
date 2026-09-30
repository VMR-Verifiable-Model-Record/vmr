//! The CLI's errors and its exit-code contract (docs/dev/phase5.md C10).
// ============================================================================
//  error.rs — every way a command can fail, and the code it exits with
//
//  A command either produces its output — possibly with a non-zero code:
//  `record verify` exits 3 on a failed verification, which is a result,
//  not an error — or fails with a CliError. Nothing panics and nothing exits
//  from the middle of a command (Law 9): `main` turns every outcome into a
//  message and one of these codes.
// ============================================================================

/// The command did its job (for `verify`: the record verified and was
/// accepted).
pub const EXIT_OK: u8 = 0;
/// Usage, input or I/O error: the command could not do its job.
pub const EXIT_INPUT: u8 = 1;
/// Engine error: the engine refused (the engine build only; task 10.13a).
pub const EXIT_ENGINE: u8 = 2;
/// Verification failed: the verdict is `fail`.
pub const EXIT_VERIFICATION_FAILED: u8 = 3;
/// The record verified, but the policy evaluation did not accept it:
/// `record verify --policy-pack` found it non-compliant, or could not
/// decide it (P6-13: "indeterminate" is not acceptance).
pub const EXIT_POLICY_NOT_ACCEPTED: u8 = 4;

/// `record verify`'s exit codes, as its `--help` prints them
/// (docs/dev/cli-polish.md CP-3: each command's help lists its own codes).
pub const EXIT_CODES_VERIFY: &str = "\
Exit codes:
  0  done; for `record verify`: the record verified
  1  usage, input or I/O error (bad arguments, unreadable or malformed input
     files, an unusable trust store, authority store or policy pack, a pack
     signature that does not verify or that --require-signed-pack does not
     accept, an existing output file)
  3  verification failed (malformed, truncated, tampered, forged or untrusted
     record)
  4  verified, but the policy evaluation did not accept it: --policy-pack
     found the record non-compliant, or could not decide it";

/// The exit-code table the top-level `--help` prints: every code this tool
/// returns, which are `record verify`'s, with `log verify`'s refusals under
/// code 3. A build that adds a command with codes of its own prints its own
/// table.
pub const EXIT_CODES_HELP: &str = "\
Exit codes:
  0  done; for `record verify`: the record verified
  1  usage, input or I/O error (bad arguments, unreadable or malformed input
     files, an unusable trust store, authority store or policy pack, a pack
     signature that does not verify or that --require-signed-pack does not
     accept, an existing output file)
  3  verification failed (malformed, truncated, tampered, forged or untrusted
     record; for `log verify`, an audit log or a checkpoint refused; for `log
     check-item`, content that is not what the entry committed to)
  4  verified, but the policy evaluation did not accept it: --policy-pack
     found the record non-compliant, or could not decide it";

/// `log verify`'s exit codes, as its `--help` prints them.
pub const EXIT_CODES_LOG_VERIFY: &str = "\
Exit codes:
  0  done: the log verified, and every checkpoint given with it
  1  usage, input or I/O error (bad arguments, an unreadable log or checkpoint
     file, an unusable audit key file)
  3  verification failed: a line of the log or a checkpoint was refused, or a
     checkpoint is not of this log";

/// `log seal`'s exit codes, as its `--help` prints them. A refused event is
/// an answer on standard output, not an exit code.
pub const EXIT_CODES_LOG_SEAL: &str = "\
Exit codes:
  0  done: the input ended and the final checkpoint was written
  1  usage, input or I/O error (bad arguments, a directory `log init` did not
     make, a log another seal holds or a line of it refused, a write that
     failed, standard output closed)";

/// `log check-item`'s exit codes, as its `--help` prints them.
pub const EXIT_CODES_LOG_CHECK_ITEM: &str = "\
Exit codes:
  0  done: the content is what the entry's digest committed to
  1  usage, input or I/O error (bad arguments, an unreadable file, an entry
     with no such digest member, an item key that is not 64 hexadecimal
     characters)
  3  the content is not what the entry's digest committed to, or a line of the
     log up to the entry was refused";

/// The exit codes of every other command: `record emit`, `record inspect`,
/// `model hash`, `key generate`, `key export` and `trust-store add`.
pub const EXIT_CODES_DONE: &str = "\
Exit codes:
  0  done
  1  usage, input or I/O error (bad arguments, unreadable or malformed input
     files, an existing output file)";

/// A command that could not do its job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    /// The exit code: [`EXIT_INPUT`] (or, for the engine, 2).
    pub code: u8,
    /// What went wrong, for a human. Never contains secret material.
    pub message: String,
    /// What to do about it, when there is something useful to say.
    pub hint: Option<String>,
}

impl CliError {
    /// A usage, input or I/O error (exit 1).
    pub fn input(message: impl Into<String>) -> Self {
        CliError { code: EXIT_INPUT, message: message.into(), hint: None }
    }

    /// An engine error (exit 2): the engine refused. This tool never returns
    /// it; a build that adds an engine does (task 10.13a).
    pub fn engine(message: impl Into<String>) -> Self {
        CliError { code: EXIT_ENGINE, message: message.into(), hint: None }
    }

    /// A fault in this tool itself (exit 1, the code every failure that is
    /// neither the engine's nor a verification's result carries): a guard
    /// that holds whenever `vmr` is correct did not hold. Nothing here is the
    /// user's input, and the message says so rather than blaming what they
    /// gave: a wrong diagnosis sends an author looking for a mistake in their
    /// own file.
    pub fn internal(message: impl Into<String>) -> Self {
        CliError {
            code: EXIT_INPUT,
            message: format!(
                "{}: this is a fault in {} itself, not in what you gave it",
                message.into(),
                crate::tool_name!()
            ),
            hint: Some(format!(
                "nothing was written; please report it with the command you ran and the version `{} --version` \
                 prints",
                crate::tool_name!()
            )),
        }
    }

    /// The same error with a hint line.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_input_error_exits_1_and_carries_its_hint() {
        let e = CliError::input("x").with_hint("h");
        assert_eq!((e.code, e.message.as_str(), e.hint.as_deref()), (1, "x", Some("h")));
    }

    #[test]
    fn an_engine_error_exits_2() {
        assert_eq!(CliError::engine("x").code, 2);
    }

    #[test]
    fn a_fault_of_this_tool_exits_1_and_never_blames_the_input() {
        let e = CliError::internal("the signature just made does not verify");
        assert_eq!(e.code, 1);
        assert!(e.message.ends_with("this is a fault in vmr itself, not in what you gave it"), "{}", e.message);
        assert!(e.hint.unwrap().starts_with("nothing was written; please report it"));
    }
}
