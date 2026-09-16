// ============================================================================
//  vmr-record — the open Verifiable Model Record (VMR) format
//
//  Everything a party needs to read, write, hash, sign and check a v0.1
//  record, and nothing else: the record types, the canonical signed
//  payload (JCS, RFC 8785), the COSE_Sign1 envelope, JWK key ids (RFC 7638),
//  ES256, SHA-256 hash strings, base64url and the Merkle construction. The
//  builder (which needs the engine) lives in `vmr-provenance`; the verifier
//  (which needs a trust store) in `vmr-verify`. Both link this crate, so the
//  issuer and the verifier share one implementation of the format.
//
//  This crate has no build script, no FFI and no unsafe code: it builds and
//  tests anywhere, without clang, the C headers or the engine
//  (docs/dev/phase4.md, D2).
//
//  All cryptographic primitives come from audited libraries (sha2, p256,
//  coset) per Doctrine Refusal 4. The canonicalizer (RFC 8785 / JCS) is
//  serialization, not cryptography. It is tested against the RFC's two
//  samples (§3.2.2 primitives, §3.2.3 property sorting) and against
//  hand-written cases whose expected bytes were cross-checked with V8
//  (node 22) — NOT against the RFC's full test suite
//  (cyberphone/json-canonicalization), which is not vendored because this
//  project builds offline (QA P3-09).
//
//  Determinism (Doctrine L4): nothing in this crate reads a clock or a
//  random source while producing record bytes. Every time-bearing or
//  identity-bearing field (issued_at, record_id, ...) is caller-supplied;
//  test vectors use fixed values.
// ============================================================================

//! The Verifiable Model Record v0.1 format: types, canonical serialization, hashing,
//! signing, key ids and the COSE envelope. Normative reference:
//! `specs/record-format-v0.1.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// The verifier runs this code on untrusted input: no panicking shortcuts in
// library code (plan §5.8, Law 9). The few sites that remain are infallible
// by construction; each carries a scoped `allow` saying why.
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

pub mod canonical;
pub mod cose;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod integrity;
pub mod jwk;
pub mod merkle;
pub mod named_set;
pub mod record;
pub mod sign;
pub mod strict_json;
pub mod timestamp;
pub mod validate;

pub use error::Error;
pub use integrity::IntegrityError;
pub use record::Record;
