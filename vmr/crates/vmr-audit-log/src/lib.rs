// ============================================================================
//  vmr-audit-log — the VMR audit log, open and general
//
//  specs/audit-log-format-v0.1.md. A log is a file of entries, each naming the
//  tree head before it; a checkpoint is its writer's signed statement of the
//  log's size and root; the two proofs show that an entry is in a log a
//  checkpoint covers, and that one checkpoint's log extends another's.
//
//  Whose log it is does not matter here. An entry's core is the same for every
//  writer (§4.1), and the vocabulary of kinds and the rules of their detail
//  come from a named profile (§5). KHALM's enforcer is one profile, in
//  `profiles::khalm_enforcer`; another vendor writes its own and the rest of
//  this crate does not change.
//
//  Design invariants (as in vmr-record, vmr-verify and vmr-policy):
//
//    * No unsafe code (`#![forbid(unsafe_code)]`).
//    * No panics in library code: every fallible path returns a typed error.
//    * No clock, no file and no network: a time is an input, the log's bytes
//      are an input, and nothing here opens anything.
//    * Deterministic: the same inputs give byte-identical documents (every one
//      is JCS), which the vectors depend on (Law 1).
//    * Nothing cryptographic is reimplemented (Refusal 4): SHA-256, JCS,
//      ES256, key ids and the Merkle tree come from vmr-record.
// ============================================================================

//! The VMR audit log: the entry and the log's Merkle tree, the signed
//! checkpoint, and the inclusion and consistency proofs, with the verifier of
//! all four. Normative reference: `specs/audit-log-format-v0.1.md`, with
//! `specs/audit-log-schema/v0.1.json` for the documents' structure.
//!
//! An entry's kinds are a profile's ([`profile::EntryProfile`]):
//! [`profile::CORE`] accepts any kind the core's grammar allows, and
//! [`profiles::khalm_enforcer::PROFILE`] is KHALM's enforcer's vocabulary.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// This crate parses documents from strangers (a log line, a checkpoint, a
// proof): no panicking shortcuts in library code (Law 9), as in vmr-record,
// vmr-verify and vmr-policy.
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

/// vmr-record, re-exported: a caller (or a test) that needs a timestamp, a
/// key, JCS or the Merkle tree needs no second dependency, and there is only
/// ever one version of the format's cryptography in the tree (Refusal 4).
pub use vmr_record;

pub mod checkpoint;
pub mod entry;
pub mod error;
pub mod json;
pub mod log;
pub mod profile;
pub mod profiles;
pub mod proof;
pub mod signing;
pub mod tree;

pub use error::Error;

/// The log format version this build writes and reads.
pub const LOG_VERSION: &str = "0.1";
/// The largest audit entry line, in bytes (§5.1).
pub const MAX_ENTRY_BYTES: usize = 65_536;
/// The nesting bound every document of this format shares (§2 rule 3).
pub const MAX_NESTING_DEPTH: usize = 127;
/// The largest inclusion-proof document, in bytes (§7).
pub const MAX_INCLUSION_PROOF_BYTES: usize = 262_144;
/// The largest consistency-proof document, in bytes (§8).
pub const MAX_CONSISTENCY_PROOF_BYTES: usize = 32_768;
/// The largest checkpoint document, in bytes (§6).
pub const MAX_CHECKPOINT_BYTES: usize = 16_384;
/// The most elements an inclusion proof's `audit_path` may hold (§7; the
/// schema's `maxItems`). A tree of 2^64 leaves has a path of 64 siblings, so
/// nothing longer is a path of any log (QA QR-06).
pub const MAX_AUDIT_PATH_ELEMENTS: usize = 64;
/// The most elements a consistency proof's `proof` may hold (§8; the
/// schema's `maxItems`) (QA QR-06).
pub const MAX_CONSISTENCY_PROOF_ELEMENTS: usize = 128;
