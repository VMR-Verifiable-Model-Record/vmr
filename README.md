<p align="center">
  <img src="vmr.svg" width="120" alt="VMR" />
</p>

<p align="center">
  <a href="https://github.com/VMR-Verifiable-Model-Record/vmr/releases/latest"><img src="https://img.shields.io/github/v/tag/VMR-Verifiable-Model-Record/vmr?label=release&amp;sort=semver&amp;color=1f6feb" alt="Latest release" /></a>
  <a href="https://github.com/VMR-Verifiable-Model-Record/vmr/actions/workflows/community-ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/VMR-Verifiable-Model-Record/vmr/community-ci.yml?branch=main&amp;label=ci" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0" /></a>
  <a href="specs/record-format-v0.1.md"><img src="https://img.shields.io/badge/record%20format-v0.1-6e7681" alt="Record format v0.1" /></a>
  <img src="https://img.shields.io/badge/rust-1.85%2B-dea584" alt="Rust 1.85 or later" />
  <a href="https://discord.gg/vxvDTbAwnW"><img src="https://img.shields.io/badge/Discord-join-5865F2?logo=discord&amp;logoColor=white" alt="Discord" /></a>
</p>

# VMR — Verifiable Model Record

VMR is an open, global standard for a signed, checkable record of an AI
model: which files make it up, what an issuer states about it, and what a
policy pack says about the result. This repository is a reference
implementation of that standard, for any AI model, from any vendor, whose
weights the issuer holds — not the official one, and any conforming tool's
record is as valid as one made here.

## Why this exists

A semiconductor chip can be traced to the fab that made it. A model cannot be traced to the data it learned from or the people who trained it. Most deployments rest on one thing: trust the vendor.

VMR replaces that trust with a signed record. The record fixes what the model is, what its issuer states it learned from, and what policy pack its issuer says it was evaluated against — and anyone can run that evaluation again themselves. It is verifiable offline, by any downstream party, without contacting the issuer.

The standard, the schema, the test vectors, and the reference verifier are free and open source. The record is not a claim of legal compliance. It is evidence that can be shown to a regulator, an auditor, or a customer.

## Install

No Rust toolchain needed: every
[release](https://github.com/VMR-Verifiable-Model-Record/vmr/releases/latest)
carries a prebuilt `vmr`.

| System | File in the release | What it needs from the machine |
|---|---|---|
| **Linux** x86_64 | `vmr-<version>-x86_64-unknown-linux-musl.tar.gz` | nothing — statically linked, so any glibc |
| **Windows** x86_64 | `vmr-<version>-x86_64-pc-windows-msvc.zip` | nothing — no Visual C++ runtime |
| **macOS** Apple silicon | `vmr-<version>-aarch64-apple-darwin.tar.gz` | macOS 11 or later |
| **macOS** Intel | `vmr-<version>-x86_64-apple-darwin.tar.gz` | macOS 11 or later |

Each archive holds the binary, `LICENSE` and `NOTICE`.

**1 — Download** your system's archive and `SHA256SUMS` from the release.

**2 — Check the archive before you run it.** Your line prints `OK`:

```sh
grep x86_64-unknown-linux-musl SHA256SUMS | sha256sum -c      # Linux
grep aarch64-apple-darwin      SHA256SUMS | shasum -a 256 -c  # macOS, Apple silicon
grep x86_64-apple-darwin       SHA256SUMS | shasum -a 256 -c  # macOS, Intel
```

```powershell
# Windows: these two hashes must match
Select-String x86_64-pc-windows-msvc SHA256SUMS
(Get-FileHash vmr-*-x86_64-pc-windows-msvc.zip).Hash.ToLower()
```

With the GitHub CLI you can make one check a checksum cannot — that this
repository's release workflow built that exact file from the release's tag:

```sh
gh attestation verify <archive> --repo VMR-Verifiable-Model-Record/vmr
```

**3 — Unpack it and run it:**

```sh
vmr --version
```

> [!NOTE]
> Neither Apple nor Microsoft has signed these binaries. macOS quarantines a
> copy downloaded with a browser and will not open it: once the checksum
> matches, clear the flag with `xattr -d com.apple.quarantine vmr`. Windows
> may warn before running it.

To try the examples below you need this repository's files as well: clone it,
or download it with Code → Download ZIP, and run the commands from that
folder. Or build `vmr` yourself (**Build it**, below).

## See it: a record for an open-weight model

`docs/examples/phi-4-mini-instruct/` holds a signed record of
`microsoft/Phi-4-mini-instruct`, made by `vmr` from the model's files (an
example signer's record — Microsoft did not make, sign or endorse it).
Verify it offline:

```
vmr record verify \
  --record docs/examples/phi-4-mini-instruct/record.vmr \
  --trust-store docs/examples/phi-4-mini-instruct/trust-store.json
```

This answers one question: is this a well-formed record, signed by a key
the trust store trusts for the stated issuer? See that folder's own README
for what the record states and how to check it against the model itself.

## What is here

- `vmr/` — the format library, the offline verifier, the policy-pack
  evaluator, the engine-free record builder, and the `vmr` CLI;
- `specs/` — the record, trust-store, policy-pack and audit-log formats,
  their schemas, test vectors, and five reference policy packs — one author's
  reading of public documents, endorsed by nobody: read `docs/POLICY_PACKS.md`
  before you rely on a pack result;
- `specs/conformance/` — the conformance suite and its runner: the open test
  an implementation in any language passes to call itself conformant;
- `docs/` — the CLI reference, `POLICY_PACKS.md` (whose rules a pack is, and
  what "compliant" does and does not mean), the demo, and worked examples;
- `fuzz/` and `fuzz-targets/` — the coverage-guided fuzz targets over every
  parser of untrusted input here, and their stable-Rust seed tests.

Nothing here is a learning engine: this tree makes and checks records from a
model's files, and never trains, runs or opens the model itself.

## Build it

```
cargo build --release --manifest-path vmr/Cargo.toml -p vmr-cli
cargo test --manifest-path vmr/Cargo.toml
```

Rust only: no C/C++ toolchain and no GPU. The first build fetches this
tree's Rust dependencies from crates.io, at the exact versions
`vmr/Cargo.lock` pins; after that the build and every test run offline, and
nothing the tool does at run time touches the network. See `CONTRIBUTING.md`
for the full build and test flow.

## Status

This is a reference implementation under active development. It carries no
claim of legal compliance: a policy pack result labeled "compliant" means
only that the pack's mandatory rules passed, not that the model or its use
satisfies any law.

## License

Apache License, Version 2.0 (`LICENSE`, `NOTICE`). It covers the code, not
the "Verifiable Model Record" name or the VMR logo; see `NOTICE`.

## Community

- **Questions, bugs and requests:** the issue templates in this repository.
- **Chat:** https://discord.gg/vxvDTbAwnW
- **Contributing:** `CONTRIBUTING.md`; contributions carry a Developer
  Certificate of Origin sign-off.
- **Conforming implementations:** `specs/conformance/` holds the open test.
  A tool is conformant when it passes the named version of that test, whoever
  wrote it.

## Reporting a security issue

See `SECURITY.md`.
