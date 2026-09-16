# Roadmap

This is the public roadmap of the Verifiable Model Record (VMR) standard and
`vmr`, KHALM's free reference implementation. It lists what exists and what is
planned, with no dates. Propose changes with a feature request.

**Version 0.1 is published, and its bytes are frozen.** What is published at
`v0.1.0` does not change: an editorial correction that changes no rule is
released as v0.1.1, and anything that changes a rule as v0.2. Pin the vectors
and the schemas by hash and they will keep matching.

## In version 0.1

- **The record format, v0.1:** a signed record of which model it is, where it
  came from and what its issuer states about it, for any AI model, from any
  vendor, whose weights the issuer holds.
- **`vmr`:** make a record of a model's files, verify it offline against the
  trust store you choose, inspect it, and hash a model's files.
- **Verification without the issuer:** no network, no account, no contact with
  the issuer; the verifier trusts only the keys in your trust store.
- **Policy packs:** a format for rules a record is graded against, an
  evaluator, and five reference packs, each KHALM's own reading of the text it
  cites and named for it &mdash; `khalm-reading-eu-ai-act-2026`,
  `khalm-reading-nist-ai-rmf-1.0`, `khalm-reading-iso-42001-2023`,
  `khalm-reading-c2pa-ai-disclosure-2.2` and
  `khalm-reading-rats-rfc9334-v0.1`. A pack's result is not a legal finding,
  and any authority may publish its own pack instead.
- **References to other signed statements:** a record can name an OpenSSF Model
  Signing signature by its digest. A verifier checks the reference's form, not
  the signature.
- **The audit-log format and its verifier:** the entry, the tree, the signed
  checkpoint and the inclusion and consistency proofs, as a library any
  implementation can build on. Checking a checkpoint or a proof from the
  command line is planned, not built.
- **Test vectors and an open conformance test** any implementation can run:
  the runner, the suite and the cases are published with the standard, and a
  tool is conformant when it passes the named version of that test.

## Planned

- **Checking an OpenSSF Model Signing signature against a record:** that the
  two cover the same files.
- **Export to CycloneDX.**
- **Checking an audit-log checkpoint or proof from the command line,** so
  that reading a log needs no Rust.
- **Signing your own policy pack from the command line,** and checking a
  pack's signature on its own. The format lets any authority publish and
  sign a pack today; this makes it a command rather than code you write.
- **A guide to writing your own policy pack.**
- **Your proposals:** accepted feature requests are added here.

Planned items are not promises of a date, and nothing here is described as
done until it is.
