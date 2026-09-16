# Contributing

Thank you for considering a contribution to VMR, the reference
implementation of the open Verifiable Model Record standard.

## Developer Certificate of Origin

Every contribution must be signed off under the [Developer Certificate of
Origin](https://developercertificate.org/) (DCO): add a `Signed-off-by`
trailer to each commit, stating that you wrote it or otherwise have the
right to submit it under this project's license.

```
git commit -s -m "your commit message"
```

A pull request whose commits carry no `Signed-off-by` trailer will be
asked to add one before it can be merged.

## Building and testing, with no engine present

This repository holds only the Community edition: the record format
library, the offline verifier, the policy-pack evaluator, the engine-free
record builder, and the `vmr` CLI. There is no learning engine here, no
C/C++ toolchain, and no GPU dependency — Rust (stable, see
`vmr/Cargo.toml`'s `rust-version`) is all that is needed.

```
cargo build --manifest-path vmr/Cargo.toml --workspace
cargo test --manifest-path vmr/Cargo.toml --workspace
cargo clippy --manifest-path vmr/Cargo.toml --workspace --all-targets -- -D warnings
```

The first build fetches this tree's Rust dependencies from crates.io, at
the versions `vmr/Cargo.lock` pins; add `--offline` once they are in your
cargo registry, and all three commands then run with no network access. None
of them uses an environment variable pointing at an engine library or
headers: a build that needs either of those is a bug in this tree, not a
missing dependency.

This repository is line-ending-pinned. Its `.gitattributes` keeps
`specs/test-vectors/**`, `specs/conformance/**` and the golden reports LF on
every checkout, whatever your `core.autocrlf` says, because the conformance
suite hashes those files as bytes. Do not remove those pins, and do not
convert those files; `git diff` should be empty after a fresh clone on any
operating system.

## Pull requests

- Keep a pull request scoped to one change.
- Add or update tests for the behavior you change.
- Describe what you changed and why, not just what the diff shows.

## Reporting a security issue

Do not open an issue or a Discord thread for a security vulnerability — see
`SECURITY.md`.
