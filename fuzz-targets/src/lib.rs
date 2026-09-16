//! Plain bodies for `../fuzz/fuzz_targets/*.rs` (libFuzzer, nightly:
//! `cargo +nightly fuzz run <target>`, from the `fuzz/` package) and for
//! `tests/vectors.rs` in this crate (stable `cargo test -p
//! vmr-fuzz-targets`, no nightly needed): task 10.13's pre-release fuzzing
//! task (`AGENTS.md`), coverage-guided fuzzing of every Community parser of
//! untrusted input (`docs/DEV_PLAN.md` §5.7: "a malformed record must never
//! crash the verifier").
//!
//! Each function takes raw untrusted bytes and calls exactly one Community
//! parser's entry point, discarding its `Result`: a parse failure is the
//! parser doing its job; a panic (or, under ASan, a memory-safety fault) is
//! the bug this crate exists to find. Split from `fuzz/` (which holds only
//! the `#![no_main]` libFuzzer wrappers) so `cargo test` here never has to
//! link one of those: Cargo builds every `[[bin]]` in a package alongside
//! any test in it, for `CARGO_BIN_EXE_*`, and a `no_main` bin has no entry
//! point outside `cargo fuzz build`. This crate and `fuzz/` are exported
//! with the Community edition (`tools/community.json` lists them), so a
//! public clone can run the same targets; neither is published to
//! crates.io.

#![forbid(unsafe_code)]

pub mod seeds;

/// Whether each target's parser ACCEPTS the bytes, for the seed assertion of
/// `tests/vectors.rs` (QA QR-22): a corpus every parser rejects at its first
/// byte would pass every "never panics" test while the fuzzer explored
/// nothing past the entry check. Each function here calls exactly the same
/// parser entry point as its target above and reports only whether the
/// `Result` was `Ok`. Nothing here is used by a fuzz target.
pub mod accepts {
    use super::audit_key_secret;

    /// `record_json`'s parser accepted the bytes.
    pub fn record_json(data: &[u8]) -> bool {
        std::str::from_utf8(data).is_ok_and(|text| vmr_record::Record::from_json(text).is_ok())
    }

    /// `record_cose`'s parser accepted the bytes.
    pub fn record_cose(data: &[u8]) -> bool {
        vmr_record::Record::from_cose(data).is_ok()
    }

    /// `trust_store`'s parser accepted the bytes.
    pub fn trust_store(data: &[u8]) -> bool {
        vmr_verify::TrustStore::from_json(data).is_ok()
    }

    /// `policy_pack`'s parser accepted the bytes.
    pub fn policy_pack(data: &[u8]) -> bool {
        vmr_policy::load_pack_bytes(data).is_ok()
    }

    /// `public_key`'s parser accepted the bytes.
    pub fn public_key(data: &[u8]) -> bool {
        vmr_cli::keys::parse_public_key_file(data).is_ok()
    }

    /// `manifest`'s parser accepted the bytes.
    pub fn manifest(data: &[u8]) -> bool {
        vmr_cli::manifest::parse(data).is_ok()
    }

    /// `audit_entry`'s parser accepted the bytes under either profile.
    pub fn audit_entry(data: &[u8]) -> bool {
        let Ok(text) = std::str::from_utf8(data) else { return false };
        let Ok(value) = vmr_audit_log::json::parse_json_bounded(text) else { return false };
        vmr_audit_log::entry::validate_entry(&value, text, &vmr_audit_log::profile::CORE).is_ok()
            || vmr_audit_log::entry::validate_entry(
                &value,
                text,
                &vmr_audit_log::profiles::khalm_enforcer::PROFILE,
            )
            .is_ok()
    }

    /// `audit_log`'s parser accepted the bytes.
    pub fn audit_log(data: &[u8]) -> bool {
        vmr_audit_log::log::read_log(data, &vmr_audit_log::profile::CORE).is_ok()
    }

    /// `audit_checkpoint`'s parser accepted the bytes, and the signature
    /// verified under the vectors' audit key.
    pub fn audit_checkpoint(data: &[u8]) -> bool {
        let key = vmr_audit_log::vmr_record::sign::signing_key_from_secret(&audit_key_secret()).unwrap();
        vmr_audit_log::checkpoint::verify_checkpoint(data, key.verifying_key()).is_ok()
    }

    /// `audit_inclusion_proof`'s parser accepted the bytes, and the proof
    /// verified.
    pub fn audit_inclusion_proof(data: &[u8]) -> bool {
        let key = vmr_audit_log::vmr_record::sign::signing_key_from_secret(&audit_key_secret()).unwrap();
        vmr_audit_log::proof::verify_inclusion_proof(data, key.verifying_key(), &vmr_audit_log::profile::CORE).is_ok()
    }

    /// `audit_consistency_proof`'s parser accepted the bytes, and the proof
    /// verified.
    pub fn audit_consistency_proof(data: &[u8]) -> bool {
        let key = vmr_audit_log::vmr_record::sign::signing_key_from_secret(&audit_key_secret()).unwrap();
        vmr_audit_log::proof::verify_consistency_proof(data, key.verifying_key()).is_ok()
    }
}

/// `vmr_record::Record::from_json`: a record, JSON form. Bytes that are not
/// UTF-8 are not this parser's problem — the CLI and the verifier check that
/// before calling it (`Record::from_json` takes `&str`) — so this target
/// skips them rather than lossily reinterpreting them, and still explores
/// every UTF-8 string libFuzzer's mutator reaches.
pub fn record_json(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = vmr_record::Record::from_json(text);
    }
}

/// `vmr_record::Record::from_cose`: a record, COSE_Sign1 form.
pub fn record_cose(data: &[u8]) {
    let _ = vmr_record::Record::from_cose(data);
}

/// `vmr_verify::TrustStore::from_json`: a trust-store document.
pub fn trust_store(data: &[u8]) {
    let _ = vmr_verify::TrustStore::from_json(data);
}

/// `vmr_policy::load_pack_bytes`: a policy pack, its rules and its
/// (optional) authority signature section.
pub fn policy_pack(data: &[u8]) {
    let _ = vmr_policy::load_pack_bytes(data);
}

/// `vmr_cli::keys::parse_public_key_file`: a `vmr key export` public key
/// file (`{"key_id": ..., "public_key": {...}}`).
pub fn public_key(data: &[u8]) {
    let _ = vmr_cli::keys::parse_public_key_file(data);
}

/// `vmr_cli::manifest::parse`: a `vmr record emit --model` manifest.
pub fn manifest(data: &[u8]) {
    let _ = vmr_cli::manifest::parse(data);
}

/// The audit key `specs/test-vectors/audit-log/cases.json`'s environment,
/// checkpoints and proofs are signed under (`vmr-audit-log`'s own test
/// fixture label, `tests/common/mod.rs`'s `AUDIT_KEY`): fixed bytes, not a
/// real enforcer's key, but the one every committed checkpoint and proof
/// vector verifies against, so the seeded corpus (`seeds.rs`) is documents
/// this key actually accepts, as well as libFuzzer's mutants of them.
pub(crate) fn audit_key_secret() -> [u8; 32] {
    vmr_audit_log::vmr_record::hash::sha256(b"khalm phase8 tests: audit key")
}

/// `vmr_audit_log::entry::validate_entry`: one audit-log entry line, checked
/// under both the core profile and KHALM's `khalm-vmr.enforcer` profile —
/// the same bytes may satisfy either vocabulary's own detail rules, or
/// neither, so both are worth exploring from the same seed.
pub fn audit_entry(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(value) = vmr_audit_log::json::parse_json_bounded(text) {
            let _ = vmr_audit_log::entry::validate_entry(&value, text, &vmr_audit_log::profile::CORE);
            let _ =
                vmr_audit_log::entry::validate_entry(&value, text, &vmr_audit_log::profiles::khalm_enforcer::PROFILE);
        }
    }
}

/// `vmr_audit_log::log::read_log`: a whole log file (newline-terminated
/// entries), under the core profile.
pub fn audit_log(data: &[u8]) {
    let _ = vmr_audit_log::log::read_log(data, &vmr_audit_log::profile::CORE);
}

/// `vmr_audit_log::checkpoint::verify_checkpoint`: a signed checkpoint
/// document, under the fixed audit key the seeded vectors are signed with.
pub fn audit_checkpoint(data: &[u8]) {
    let key = vmr_audit_log::vmr_record::sign::signing_key_from_secret(&audit_key_secret()).unwrap();
    let _ = vmr_audit_log::checkpoint::verify_checkpoint(data, key.verifying_key());
}

/// `vmr_audit_log::proof::verify_inclusion_proof`: an inclusion proof, under
/// the same fixed audit key and the core profile (the proof's own embedded
/// entry text is read under it, as `validate_entry` is inside `audit_entry`).
pub fn audit_inclusion_proof(data: &[u8]) {
    let key = vmr_audit_log::vmr_record::sign::signing_key_from_secret(&audit_key_secret()).unwrap();
    let _ = vmr_audit_log::proof::verify_inclusion_proof(data, key.verifying_key(), &vmr_audit_log::profile::CORE);
}

/// `vmr_audit_log::proof::verify_consistency_proof`: a consistency proof,
/// under the same fixed audit key.
pub fn audit_consistency_proof(data: &[u8]) {
    let key = vmr_audit_log::vmr_record::sign::signing_key_from_secret(&audit_key_secret()).unwrap();
    let _ = vmr_audit_log::proof::verify_consistency_proof(data, key.verifying_key());
}
