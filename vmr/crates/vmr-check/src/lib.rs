//! KHALM-VMR's browser checker: a Verifiable Model Record checked on the
//! reader's own computer, with nothing uploaded, no account and no key
//! trusted by default (`docs/BROWSER.md`).
// ============================================================================
//  lib.rs — vmr-check
//
//  The open format's libraries, wrapped for a browser: vmr-verify's verifier,
//  vmr-policy's pack evaluator, and vmr-record's key fingerprint and
//  named-set digest (spec §7.2–7.3). Built for wasm32-unknown-unknown it is
//  `vmr-check.wasm`, which js/vmr-check.js (hand-written, no dependencies)
//  loads and calls through the plain C exports of `ffi.rs`.
//
//  Everything here is safe Rust except `ffi.rs`, the one module that turns
//  the module's memory into byte slices; every unsafe block there says why it
//  holds. The rest keeps the libraries' no-panic lint set: bad input is a
//  result, never a trap.
//
//  Nothing here reads a clock, the network or randomness: the evaluation
//  time is always the caller's (`at`), no call has I/O, and the getrandom
//  source the wasm build must register always fails (ffi.rs). No key is
//  embedded: every trust decision comes in the caller's trust store.
//
//  Every string taken from a record, a store or a pack leaves through
//  vmr-verify's `display_safe` (`safe.rs`), except two documented byte
//  forms: the verifier's report JSON exactly as the library writes it
//  (`report_json`), and a trust store's file text (`store.rs`).
// ============================================================================

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]
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

pub mod api;
pub mod files;
pub mod hasher;
pub mod inspect;
pub mod pack;
pub mod refusal;
pub mod safe;
pub mod store;

#[allow(unsafe_code)]
pub mod ffi;

pub use refusal::Refusal;

/// The version of the record format this checker reads.
pub const RECORD_FORMAT: &str = "0.1";

/// This build's version: the workspace's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
