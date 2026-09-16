// fuzz-targets/tests/vectors.rs — stable-Rust check of fuzz-targets/src/
// lib.rs's plain target bodies over specs/test-vectors/ and the worked
// examples (task 10.13's pre-release fuzzing task, AGENTS.md): "Each
// target's body is a plain function that stable unit tests also run, over
// seeds from specs/test-vectors/, so it is checked without nightly."
// `cargo test -p vmr-fuzz-targets` runs these; `cargo +nightly fuzz run
// <target>` (the `fuzz/` package) runs the same function under libFuzzer,
// coverage-guided, over a larger corpus seeded from the same vectors
// (`src/bin/write_corpus.rs`, run by `tools/fuzz.ps1`).
//
// A seed a target rejects is not a failure — every one of these parsers
// exists to reject malformed input. Only a panic fails a test here (Rust
// turns it into a test failure the normal way), and only a non-empty seed
// list proves the seeding itself did not silently come up empty.
//
// QA QR-22: a count alone does not prove the corpus is worth fuzzing. A
// corpus every parser rejected at its first byte would pass every test here
// while libFuzzer explored nothing past the entry check, so each target also
// asserts that at least one of its seeds is ACCEPTED
// (`vmr_fuzz_targets::accepts`, the same parser entry point).

use vmr_fuzz_targets::{accepts, seeds};

/// Every seed runs through `body`, and at least one is accepted by `accepts`
/// (QA QR-22), over at least `least` seeds (QA QR-35: every target counts).
fn exercise(target: &str, cases: &[Vec<u8>], least: usize, body: fn(&[u8]), accepted: fn(&[u8]) -> bool) {
    assert!(cases.len() >= least, "too few {target} seeds: {}", cases.len());
    for seed in cases {
        body(seed);
    }
    let good = cases.iter().filter(|seed| accepted(seed)).count();
    assert!(good >= 1, "no {target} seed parses: the corpus explores nothing past the entry check");
}

#[test]
fn record_json_seeds_never_panic() {
    exercise(
        "record_json",
        &seeds::record_json(),
        5,
        vmr_fuzz_targets::record_json,
        accepts::record_json,
    );
}

#[test]
fn record_cose_seeds_never_panic() {
    exercise(
        "record_cose",
        &seeds::record_cose(),
        3,
        vmr_fuzz_targets::record_cose,
        accepts::record_cose,
    );
}

#[test]
fn trust_store_seeds_never_panic() {
    exercise(
        "trust_store",
        &seeds::trust_store(),
        10,
        vmr_fuzz_targets::trust_store,
        accepts::trust_store,
    );
}

#[test]
fn policy_pack_seeds_never_panic() {
    exercise(
        "policy_pack",
        &seeds::policy_pack(),
        5,
        vmr_fuzz_targets::policy_pack,
        accepts::policy_pack,
    );
}

#[test]
fn public_key_seeds_never_panic() {
    exercise(
        "public_key",
        &seeds::public_key(),
        3,
        vmr_fuzz_targets::public_key,
        accepts::public_key,
    );
}

#[test]
fn manifest_seeds_never_panic() {
    exercise(
        "manifest",
        &seeds::manifest(),
        2,
        vmr_fuzz_targets::manifest,
        accepts::manifest,
    );
}

#[test]
fn audit_entry_seeds_never_panic() {
    exercise(
        "audit_entry",
        &seeds::audit_entry(),
        8,
        vmr_fuzz_targets::audit_entry,
        accepts::audit_entry,
    );
}

#[test]
fn audit_log_seeds_never_panic() {
    exercise(
        "audit_log",
        &seeds::audit_log(),
        4,
        vmr_fuzz_targets::audit_log,
        accepts::audit_log,
    );
}

#[test]
fn audit_checkpoint_seeds_never_panic() {
    exercise(
        "audit_checkpoint",
        &seeds::audit_checkpoint(),
        5,
        vmr_fuzz_targets::audit_checkpoint,
        accepts::audit_checkpoint,
    );
}

#[test]
fn audit_inclusion_proof_seeds_never_panic() {
    exercise(
        "audit_inclusion_proof",
        &seeds::audit_inclusion_proof(),
        5,
        vmr_fuzz_targets::audit_inclusion_proof,
        accepts::audit_inclusion_proof,
    );
}

#[test]
fn audit_consistency_proof_seeds_never_panic() {
    exercise(
        "audit_consistency_proof",
        &seeds::audit_consistency_proof(),
        5,
        vmr_fuzz_targets::audit_consistency_proof,
        accepts::audit_consistency_proof,
    );
}
