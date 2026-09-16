// ============================================================================
//  vmr — the KHALM-VMR command-line tool, the Community build (vmr-cli)
//
//  The binary: the command tree and every command are the library's
//  (src/lib.rs), which also writes the outcome and chooses the exit code.
// ============================================================================

//! `vmr`: emit, verify and inspect Verifiable Model Records (VMR).

#![forbid(unsafe_code)]

use clap::CommandFactory;
use std::process::ExitCode;
use vmr_cli::cli::Cli;

fn main() -> ExitCode {
    vmr_cli::main_with(Cli::command(), |_, _| None)
}
