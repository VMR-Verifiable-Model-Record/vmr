# Policy packs — whose rules, and what a result means

A Verifiable Model Record says what a model is and who signed for it.
Verification answers one question: *is this record signed by a key I trust for
the issuer it names?* It never answers *is this model allowed here* — that
answer belongs to whoever is doing the allowing, not to us. A **policy pack**
is how that party writes their answer down.

## 1. Anyone can be the authority

A pack is a JSON document with an author. It names rules, each citing the clause
of some text it encodes, and its author may sign it. Nothing in this project
decides whose packs matter. The person running the verifier decides, the same
way they decide which issuers to trust: by putting keys in a trust store. A pack
signed by a key no trusted policy authority holds is still evaluated — and the
result says, in as many words, that nobody checked who wrote it.

So a regulator can publish a pack, and so can a notified body, an auditor, a
standards consortium, a customer's own compliance team, or one engineer with an
opinion about what their company will deploy. They all use the same format
(`specs/policy-pack-format-v0.1.md`), and their customers point the verifier at
their key instead of anyone else's. That is the whole design: we do not ask to
be trusted, we ask to be checkable. Choosing whose rules to trust is a decision
you make per gate, and it is visible: the pack file, its author, its signature,
and its payload hash, which names the exact text that was applied. Pin the
payload hash and you know which words judged you.

One limit, today: the signature is the format's, not yet this tool's. `vmr`
checks a pack's signature against the authorities you trust, but has no command
to make one, so a pack you publish now is an unsigned file — pin it by its
payload hash. KHALM's own five are unsigned.

## 2. KHALM's five are examples, not instruments

`specs/policy-packs/` holds five packs written by KHALM as reference
implementations of the format:

| Pack id | Its author's reading of |
|---|---|
| `khalm-reading-eu-ai-act-2026` | Regulation (EU) 2024/1689, as amended by (EU) 2026/1744 |
| `khalm-reading-iso-42001-2023` | ISO/IEC 42001:2023, Annex A controls |
| `khalm-reading-nist-ai-rmf-1.0` | NIST AI RMF 1.0 (NIST AI 100-1) |
| `khalm-reading-c2pa-ai-disclosure-2.2` | C2PA Technical Specification 2.2 |
| `khalm-reading-rats-rfc9334-v0.1` | IETF RFC 9334 (RATS architecture) |

Their ids begin with `khalm-reading-` because that is what they are: one
author's reading of a public document, in the part a v0.1 record can answer.
**No regulator, standards body or working group authored, reviewed or endorsed
any of them.** The European Union, ISO, IEC, NIST, the Coalition for Content
Provenance and Authenticity, the IETF and the RATS working group have no part in
them. They are not certifications, not conformance tests, and not legal advice.
Every pack says so in its `disclaimer`, and their `authority` is
`khalm-reference-packs` — never a real body's name.

Use them to see the format working, to start your own, or to ask a supplier a
first question. If you need rules that carry weight, publish your own, or use
the pack of an authority whose word already does.

## 3. What "compliant" means

`compliant` means exactly this: **the pack's mandatory rules passed against what
the record declares.** Recommended and informational rules are reported but do
not move that status. `non-compliant` means a mandatory rule failed;
`indeterminate` means one could not be decided — and that is not acceptance.

What it does not mean:

- **Not that a law is satisfied.** A pack encodes a fragment of a text, chosen
  by its author because a record can answer it. Compliance with the AI Act, or
  any other instrument, is broader than any document can show.
- **Not a certification.** Nobody audited anything. Conformity with ISO/IEC
  42001, for example, is assessed against an organisation's management system,
  not against a file.
- **Not legal advice**, and not an opinion about your obligations.
- **Not a statement about the record's truth.** See below.

## 4. What no pack can check

An evaluation reads the record and nothing else. It is offline, it opens no
files, and it contacts nobody. So no pack — ours or yours — can check:

- **Whether a declaration is true.** A record that declares an attestation
  level of `software` is declaring it about itself. A record that pins a
  document by SHA-256 shows *which* document its issuer relied on, not that the
  document exists, can be obtained, or says anything useful.
- **Whether a document is adequate.** A hash is not a review.
- **Anything outside the record** — the system in operation, its logs, its
  accuracy, the data actually used, the organisation behind it.

This is the boundary of the evidence, not a gap to be closed later. A record is
a signed set of claims, and a pack result tells you which claims were made, not
which are true. What verification *does* establish — that a key you trust signed
these exact bytes — is a separate, stronger statement, kept apart in the report.

## 5. Check it for yourself

Nothing above has to be taken on trust:

- **Read the pack.** Its `description` says what it covers and what its author
  could not confirm; `disclaimer`, what it is not.
- **Read each rule.** Every rule of every reference pack has a `description`
  saying what it checks and then, after **`Does not check:`**, what a pass does
  not establish. A rule that will not say that does not belong in a reference
  pack; a test holds all twenty to it.
- **Run it.**

  ```
  vmr record verify --record model.vmr --trust-store trust-store.json \
      --policy-pack specs/policy-packs/khalm-reading-eu-ai-act-2026.json
  ```
  The output shows the issuer's declaration and this verifier's finding as two
  statements, never merged; the pack's signature state and payload hash; and
  every rule that did not pass, with the clause it cites and why. Exit 0 means
  verified and accepted, 4 verified but not accepted, 3 not verified.

- **Compare implementations.** The format is normative
  (`specs/policy-pack-format-v0.1.md`) and the vectors under
  `specs/test-vectors/policy/` pin every status and evidence hash, so a second
  implementation is held to the same answers. `docs/CLI.md` §3.1.1 has the
  command in full.
