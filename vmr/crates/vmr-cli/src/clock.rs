//! The one clock read of the workspace (docs/dev/phase5.md C2).
// ============================================================================
//  clock.rs — "now", at the application boundary, and nowhere else
//
//  Law 1: every library crate takes time as an input (the verifier's
//  evaluation time, the builder's issued_at) and none reads a clock; their
//  clippy.toml forbids it. The CLI is where a human's "now" enters: when a
//  command is not given an explicit time (`verify --at`, `emit --issued-at`),
//  it calls `now_utc` — this file's single allowed SystemTime::now — and
//  prints that it did, so every output says where its time came from.
// ============================================================================

use crate::error::CliError;
use std::time::{SystemTime, UNIX_EPOCH};
use vmr_record::timestamp::Timestamp;

/// Where a command's time came from; printed next to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSource {
    /// An explicit argument (`--at`, `--issued-at`).
    Argument(&'static str),
    /// This machine's clock, at the moment the command ran.
    Clock,
}

impl TimeSource {
    /// How the output labels it: `(--at)` or `(current time)`.
    pub fn label(self) -> String {
        match self {
            TimeSource::Argument(flag) => format!("({flag})"),
            TimeSource::Clock => "(current time)".into(),
        }
    }

    /// How a terminal screen labels it (docs/dev/cli-polish.md CP-3):
    /// `from --at` or `current time`.
    pub fn rich_label(self) -> String {
        match self {
            TimeSource::Argument(flag) => format!("from {flag}"),
            TimeSource::Clock => "current time".into(),
        }
    }
}

/// The given time, or else the current UTC second from this machine's clock.
pub fn given_or_now(given: Option<Timestamp>, flag: &'static str) -> Result<(Timestamp, TimeSource), CliError> {
    match given {
        Some(t) => Ok((t, TimeSource::Argument(flag))),
        None => Ok((now_utc()?, TimeSource::Clock)),
    }
}

/// Refuse a time given with `flag` that is after this machine's current UTC
/// second (QA P5-04: `emit --issued-at 2099-...` wrote a record that every
/// verifier checking it now rejects, `time.not_future`). The clock is read
/// only to compare: the time used stays the one given, so what a command
/// writes still depends on its inputs alone. `what` names the file that
/// would be written: "record" for a model's files, "record" for the
/// engine profile (task 10.13a QA QM-08).
pub fn refuse_future(t: Timestamp, flag: &'static str, what: &str) -> Result<(), CliError> {
    let now = now_utc()?;
    if t > now {
        return Err(CliError::input(format!(
            "{flag} {t} is after the current time, {now} (this machine's clock): a verifier checking the \
             {what} now would reject it (time.not_future); nothing was written"
        ))
        .with_hint(format!("give {flag} a time that is not in the future, or leave it out to use the current time")));
    }
    Ok(())
}

/// The current UTC second.
#[allow(clippy::disallowed_methods)] // the one clock read (C2): the boundary where "now" enters
fn now_utc() -> Result<Timestamp, CliError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::input("this machine's clock is set before 1970-01-01T00:00:00Z"))?
        .as_secs();
    i64::try_from(seconds)
        .ok()
        .and_then(Timestamp::from_unix_seconds)
        .ok_or_else(|| CliError::input("this machine's clock is past 9999-12-31T23:59:59Z"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_time_after_now_is_refused_and_one_before_it_is_not() {
        let past = Timestamp::parse("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(refuse_future(past, "--issued-at", "record"), Ok(()));
        let e = refuse_future(Timestamp::parse("9999-12-31T23:59:59Z").unwrap(), "--issued-at", "record").unwrap_err();
        assert_eq!(e.code, 1);
        assert!(e.message.starts_with("--issued-at 9999-12-31T23:59:59Z is after the current time, "), "{}", e.message);
        assert!(e.message.contains("a verifier checking the record now would reject it (time.not_future)"), "{}", e.message);
        let e = refuse_future(Timestamp::parse("9999-12-31T23:59:59Z").unwrap(), "--issued-at", "record").unwrap_err();
        assert!(e.message.contains("checking the record now"), "the engine profile keeps its word: {}", e.message);
    }

    #[test]
    fn an_explicit_time_is_used_as_given_and_labelled_with_its_flag() {
        let t = Timestamp::parse("2026-09-11T00:00:00Z").unwrap();
        assert_eq!(given_or_now(Some(t), "--at").unwrap(), (t, TimeSource::Argument("--at")));
        assert_eq!(TimeSource::Argument("--at").label(), "(--at)");
        assert_eq!(TimeSource::Clock.label(), "(current time)");
    }
}
