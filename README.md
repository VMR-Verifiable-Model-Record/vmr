<p align="center">
  <img src="vmr.svg" width="120" alt="VMR" />
</p>

# VMR — Verifiable Model Record

VMR is an open, global standard for a signed, checkable record of an AI
model: which files make it up, what an issuer states about it, and what a
policy pack says about the result. This repository is a reference
implementation of that standard, for any AI model, from any vendor, whose
weights the issuer holds — not the official one, and any conforming tool's
record is as valid as one made here.

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
