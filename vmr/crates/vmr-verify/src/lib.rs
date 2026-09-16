// ============================================================================
//  vmr-verify — the trustless Verifiable Model Record verifier
//
//  Answers one question: is this a well-formed v0.1 record, signed by a
//  key that this trust store trusts for the issuer the record names? —
//  offline, deterministically, without panicking. "Trustless" means: no
//  online party, no contact with the issuer, and no trust in anything a
//  record says about itself. Trust is anchored in a trust store the
//  operator obtained beforehand, out of band (specs/trust-store-format-v0.1.md).
//
//  No I/O of any kind: every function takes bytes or values and returns a
//  value. No clock: the evaluation time is an input. No unordered iteration:
//  every map is a BTreeMap. (Law 1; docs/dev/phase4.md §5.1, §5.8.)
//
//  Plan: docs/dev/phase4.md. Formats: specs/record-format-v0.1.md (§6 is
//  the verification algorithm) and specs/trust-store-format-v0.1.md.
// ============================================================================

//! The Verifiable Model Record verifier: trust store, verification report and
//! the checks of `specs/record-format-v0.1.md` §6.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// A malformed record or trust store must never crash the verifier (Law 9,
// DEV_PLAN §5.7): library code has no panicking shortcuts at all.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unreachable,
    clippy::todo
)]

pub mod policy;
pub mod report;
mod text;
pub mod trust_store;
mod verifier;

pub use report::VerificationReport;
pub use text::{display_safe, escape_controls, json_escape_unsafe};
pub use trust_store::{TrustStore, TrustStoreError};
pub use verifier::{Verifier, VerifyOptions, MAX_RECORD_BYTES, MAX_PREDECESSORS};
