// ============================================================================
//  vmr-cli — the KHALM-VMR command-line tool: a library and the `vmr` binary
//  (Phase 5; task 10.13a)
//
//  The binary (src/main.rs) is the Community `vmr`: an issuer emits a record
//  of any model's files; anyone holding the record and a trust store
//  provisioned beforehand verifies it offline — no network, no contact with
//  the issuer. Design and decisions: docs/dev/phase5.md; user documentation:
//  docs/CLI.md.
//
//  A library too (task 10.13a, D13a-3): a build that extends the command tree
//  runs these commands through `main_with`, with its own additions handled
//  first. The engine build of `vmr` is such a build, kept outside this crate;
//  this crate knows no engine.
//
//  This crate orchestrates; it has no trust logic of its own. Verification
//  is vmr-verify's (the report is the whole answer; the CLI renders it),
//  the format is vmr-record's, and emission of a record of any model's files
//  is vmr-builder's.
//
//  Law 1 boundaries: the only clock read of the workspace and the only use
//  of the OS random-number generator live here, each in one place, each
//  visible in the output (docs/dev/phase5.md C2, C3).
//  Law 9: no panics, no exits from the middle of a command — every failure
//  becomes a message on stderr and an exit code (error.rs).
// ============================================================================

//! `vmr`: emit, verify and inspect Verifiable Model Records (VMR).

#![forbid(unsafe_code)]
// Malformed input must never crash the CLI (Law 9): no panicking shortcuts
// outside tests.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unreachable,
        clippy::todo
    )
)]

pub mod cli;
pub mod clock;
pub mod emit_cmd;
pub mod error;
pub mod files;
pub mod inspect_cmd;
pub mod keys;
pub mod manifest;
pub mod model_cmd;
#[cfg(test)]
mod mutate;
pub mod names;
pub mod output;
pub mod policy_pack;
pub mod progress;
pub mod render;
pub mod rich;
pub mod screens;
pub mod trust_store_cmd;
pub mod verify_cmd;
pub mod view;
pub mod width_tables;

use clap::FromArgMatches;
use cli::{Cli, Command, KeyCommand, ModelCommand, RecordCommand, TrustStoreCommand};
use error::CliError;
use output::Output;
use std::process::ExitCode;
use view::View;

/// A `vmr` binary, whole: parse the command line with `command`, run it, and
/// write its outcome. `command` is `Cli::command()` in the Community build. A
/// build that extends that tree passes its extension and `extension`, which
/// runs the command lines only that build understands and returns `None` for
/// every other; `run` runs those. Both builds' output, errors and exit codes
/// are written here, in the view the global `--color` and `--ascii` choose.
pub fn main_with<F>(mut command: clap::Command, extension: F) -> ExitCode
where
    F: FnOnce(&Cli, &clap::ArgMatches) -> Option<Result<Output, CliError>>,
{
    let args = command_line();
    let matches = match command.try_get_matches_from_mut(std::env::args_os()) {
        Ok(matches) => matches,
        Err(e) => return output::clap_outcome(&e, &args, &command),
    };
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => {
            let e = e.format(&mut command);
            return output::clap_outcome(&e, &args, &command);
        }
    };
    let result = match extension(&cli, &matches) {
        Some(result) => result,
        None => run(&cli),
    };
    output::finish(result, View::new(cli.color, cli.ascii).with_data(writes_data(&cli.command)))
}

/// Whether a command writes data a script reads: `--json`, or a public key to
/// standard output. Its error stays plain text, never a screen (QA QP-06).
fn writes_data(command: &Command) -> bool {
    match command {
        Command::Record(RecordCommand::Verify(args)) => args.json,
        Command::Model(ModelCommand::Hash(args)) => args.json,
        Command::Key(KeyCommand::Export(args)) => args.output.is_none(),
        _ => false,
    }
}

/// Whether `command`'s loading bar is drawn on this standard error: never for
/// a command that writes data a script reads (QA QP-06, QPB-01).
fn bar_draws(command: &Command, stderr_terminal: bool, term_supports_color: bool) -> bool {
    progress::draws(writes_data(command), stderr_terminal, term_supports_color)
}

/// The command line as text: what clap's messages may quote, so that
/// `output` can escape it (QA P5-03).
fn command_line() -> Vec<String> {
    std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect()
}

/// Dispatch to the command. A command that reads a model's files gets the
/// loading bar for standard error (docs/dev/cli-polish.md CP-6).
pub fn run(cli: &Cli) -> Result<Output, CliError> {
    use std::io::IsTerminal;
    let draw = bar_draws(&cli.command, std::io::stderr().is_terminal(), anstyle_query::term_supports_color());
    let mut bar = progress::stderr_bar(cli.ascii, draw);
    match &cli.command {
        Command::Record(RecordCommand::Emit(args)) => emit_cmd::run(args, &mut bar),
        Command::Record(RecordCommand::Verify(args)) => verify_cmd::run(args),
        Command::Record(RecordCommand::Inspect(args)) => inspect_cmd::run(args),
        Command::Model(ModelCommand::Hash(args)) => model_cmd::hash(args, &mut bar),
        Command::Key(KeyCommand::Generate(args)) => keys::generate(args),
        Command::Key(KeyCommand::Export(args)) => keys::export(args),
        Command::TrustStore(TrustStoreCommand::Add(args)) => trust_store_cmd::add(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn command(words: &[&str]) -> Command {
        Cli::try_parse_from(words).unwrap().command
    }

    #[test]
    fn a_command_that_writes_data_never_gets_the_bar() {
        // QA QPB-01: --json and a public key on standard output are data.
        assert!(bar_draws(&command(&["vmr", "model", "hash", "--model", "m"]), true, true));
        assert!(!bar_draws(&command(&["vmr", "model", "hash", "--model", "m", "--json"]), true, true));
        assert!(!bar_draws(&command(&["vmr", "key", "export", "--key", "k"]), true, true));
        assert!(!bar_draws(&command(&["vmr", "model", "hash", "--model", "m"]), false, true));
    }
}
