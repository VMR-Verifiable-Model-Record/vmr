// tests/cross_impl/main.rs — Phase 7, the cross-implementation tests
// (docs/dev/phase7.md; docs/TASKS.md Phase 7), in the Community build of vmr:
// G7-3,
//
//     cargo test -p vmr-cli --test cross_impl --manifest-path vmr/Cargo.toml
//
// Rust hashes, signs, verifies and evaluates, and the module holds that chain
// to values derived without the code under test: the published policy
// vectors.
//
//   policy_vectors  7.5  every verifiable policy vector through the vmr binary
//
// Phase 7's engine modules (7.1 to 7.3) are the engine build's target, G7-2,
// which takes this directory's policy_vectors and support modules by path
// (task 10.13a, Part A).

#[path = "../common/mod.rs"]
mod common;
mod support;

mod policy_vectors;
