// ============================================================================
//  vmr-builder — the engine-free record builder (task 10.13a)
//
//  Makes a signed record of a model: the checks a record must pass before
//  its issuer's key is used, and the signature. A record of any AI model,
//  from any vendor, whose weights the issuer holds needs nothing but this
//  crate and the format crate: no engine, no FFI, no build script, no unsafe
//  code (docs/dev/task-10.13a.md, D13a-1).
//
//  The KHALM engine profile's builder (vmr-provenance's RecordBuilder)
//  computes the profile's model identity from an engine and hands the rest
//  to this crate's assembly, so both descriptions are signed by one path.
//
//  Determinism (Doctrine L4): nothing here reads a clock or a random source.
//  Every time-bearing or identity-bearing field is the caller's input, and
//  ES256 signing is deterministic (RFC 6979): the same inputs and key give
//  the same record, byte for byte.
// ============================================================================

//! The engine-free record builder: assemble, check and sign a record.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// A malformed input must never crash an issuer's tool (Law 9): no panicking
// shortcuts outside tests.
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

pub mod assemble;
pub mod error;
pub mod files;
pub mod general;

pub use error::Error;
