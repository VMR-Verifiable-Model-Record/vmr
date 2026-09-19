<p align="center">
  <img src="vmr.svg" width="120" alt="VMR" />
</p>

[![Discord](https://img.shields.io/discord/1549579260094587014?label=Discord&logo=discord&color=5865F2)](https://discord.gg/vxvDTbAwnW)

# VMR — Verifiable Model Record

VMR is an open, global standard for a signed, checkable record of an AI
model: which files make it up, what an issuer states about it, and what a
policy pack says about the result. This repository is a reference
implementation of that standard, for any AI model, from any vendor, whose
weights the issuer holds — not the official one, and any conforming tool's
record is as valid as one made here.

## Why this exists

A semiconductor chip can be traced to the fab that made it. A model cannot be traced to the data it learned from or the people who trained it. Most deployments rest on one thing: trust the vendor.

VMR replaces that trust with a signed record. The record proves what the model is, what it claims to have learned from, and what policy pack it was evaluated against. It is verifiable offline, by any downstream party, without contacting the issuer.

The standard, the schema, the test vectors, and the reference verifier are free and open source. The record is not a claim of legal compliance. It is evidence that can be shown to a regulator, an auditor, or a customer.

## Install

Every [release](https://github.com/VMR-Verifiable-Model-Record/vmr/releases)
carries a prebuilt `vmr` for Windows x86_64, Linux x86_64 and macOS (Apple
silicon and Intel), each archive holding the binary, `LICENSE` and `NOTICE`.

1. **Download** your system's archive and `SHA256SUMS` from the latest
   release.
2. **Check the archive before you run it.** Name your system in the first
   command and compare the two hashes in the second:

   ```
   grep x86_64-unknown-linux-musl SHA256SUMS | sha256sum -c        # Linux
   grep aarch64-apple-darwin SHA256SUMS | shasum -a 256 -c         # Apple silicon
   grep x86_64-apple-darwin SHA256SUMS | shasum -a 256 -c          # Intel Mac
   ```

   ```
   Select-String x86_64-pc-windows-msvc SHA256SUMS                 # Windows PowerShell
   (Get-FileHash vmr-*-x86_64-pc-windows-msvc.zip).Hash.ToLower()
   ```

   With the GitHub CLI, `gh attestation verify <archive> --repo
   VMR-Verifiable-Model-Record/vmr` checks something the checksum cannot:
   that this repository's release workflow built the file from the release's
   tag.
3. **Unpack it and run** `vmr --version`.

What each binary needs: on Linux, nothing — it is statically linked, so no
particular glibc; on Windows, no Visual C++ runtime; on a Mac, macOS 11 or
later. Neither Apple nor Microsoft has signed them. macOS quarantines a copy
downloaded with a browser and will not open it; once the checksum matches,
clear the flag with `xattr -d com.apple.quarantine vmr`. Windows may warn
before running it.

To try it on the examples below, you need this repository's files too: clone
it, or download it with Code → Download ZIP, and run the commands from its
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
