//! `write_corpus <DIR>` — materializes every fuzz target's seeds
//! (`vmr_fuzz_targets::seeds`) as files under `<DIR>/<target>/seed-NNNN`,
//! ready for `cargo +nightly fuzz run <target> <DIR>/<target>`
//! (`tools/fuzz.ps1`, task 10.13's pre-release fuzzing task). Builds and
//! runs on stable: no libFuzzer, no nightly.
//!
//! `<DIR>` is meant to be a directory outside this repository (the owner,
//! 2026-09-16: corpora and crash inputs are build output, never committed).
//! Existing files are left alone: a seed already there (by content) is
//! written again under a fresh name, which libFuzzer's own de-duplication
//! on the next run treats as redundant, not wrong.

use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _argv0 = args.next();
    let Some(dir) = args.next() else {
        eprintln!("usage: write_corpus <DIR>  (writes <DIR>/<target>/seed-NNNN for every fuzz target)");
        return ExitCode::FAILURE;
    };
    let dir = std::path::PathBuf::from(dir);
    let mut total = 0usize;
    for (target, seeds) in vmr_fuzz_targets::seeds::all() {
        let target_dir = dir.join(target);
        if let Err(e) = fs::create_dir_all(&target_dir) {
            eprintln!("write_corpus: cannot create {}: {e}", target_dir.display());
            return ExitCode::FAILURE;
        }
        for (i, seed) in seeds.iter().enumerate() {
            let path = target_dir.join(format!("seed-{:04}", i + 1));
            if let Err(e) = fs::write(&path, seed) {
                eprintln!("write_corpus: cannot write {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        }
        println!("{target}: {} seed(s) in {}", seeds.len(), target_dir.display());
        total += seeds.len();
    }
    println!("write_corpus: {total} seed(s) across {} target(s) in {}", vmr_fuzz_targets::seeds::NAMES.len(), dir.display());
    ExitCode::SUCCESS
}
