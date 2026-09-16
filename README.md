<p align="center">
  <img src="vmr.svg" width="120" alt="VMR" />
</p>

# Verifiable Model Record (VMR)

An open standard for a signed record of what an AI model is and who stands
behind it, checked offline by anyone.

**Status: in preparation.** Version 0.1 is being finished. Nothing is
published here yet, and this repository holds the place where it will be.

## What will be published here

- The specification of the record format, the trust store and the policy-pack
  format (Apache 2.0).
- Their JSON schemas (Apache 2.0).
- The test vectors, so any implementation can check itself against the same
  bytes (CC0 1.0).
- `vmr`, the free reference implementation: make a record of a model's files,
  verify it offline against the trust store you choose, inspect it, hash a
  model (Apache 2.0).
- Five reference policy packs — the EU AI Act, the NIST AI RMF, ISO/IEC 42001,
  C2PA AI disclosure and IETF RATS (RFC 9334) — each with its own disclaimer
  (Apache 2.0).

## What a record is, and what it is not

A record is a small signed file that states what a model is: each of its files
by cryptographic hash, what it was built from, how it was produced, and who
stands behind it. Checking it proves two things — that the record has not been
altered, and that it was signed by a key you have decided to trust. Everything
else in it is a signed statement by its issuer, not a proof.

A record is not a certification. Nothing in it grades a model's behaviour, and
nobody may describe a model as "VMR Verified".

- The standard: <https://verifiablemodel.org>
- Questions and answers: <https://verifiablemodel.org/faq>
- The policy packs, rule by rule: <https://verifiablemodel.org/policy-packs/>
- Licence and terms: <https://verifiablemodel.org/terms>

## Following along

Watch this repository to hear when version 0.1 is published. Issues open with
the first release.

---

VMR is authored by KHALM. It is not certified, approved or adopted by any
regulator or standards body.
