# Record verification vectors (v0.1)

The cross-implementation contract for **verifying** a Verifiable Model Record
(`../../record-format-v0.1.md` §6) against a trust store
(`../../trust-store-format-v0.1.md`). The trust store is a format of its own
and verification outcomes are a contract, so both have vectors. The record format's own conformance
vector is [`../record/example-v0.1.json`](../record/example-v0.1.json);
every case here starts from it.

## The contract

For each case in [`cases.json`](cases.json), a conforming verifier is given

- `input` — the record bytes, to verify **as** `form` (`json` or `cose`);
- `trust_store` — the name of a store in [`trust-stores/`](trust-stores/);
- `evaluation_time` — the evaluation time `T` (spec §6.1; never a clock);
- `previous` — the predecessors, immediate predecessor first (spec §6.5);
- `require_complete_lineage` — whether a partial or unchecked lineage fails;

and must produce `expected.verdict` and, for a failure, `expected.check`: the
id of the **first** failing check of spec §6.2. Where `expected.lineage` is
given, it is the lineage outcome of spec §6.5 (`initial`, `complete`,
`partial`, `not_checked`, `broken`). Nothing else is contract: the wording of
reasons and the layout of a report are each implementation's own.

**Input bytes.** An input (and each predecessor) is `{"form", "text"}` — the
exact document as UTF-8 — or `{"form", "hex"}` — the exact bytes (COSE
envelopes, and JSON that is deliberately not UTF-8). If `append_spaces` is
present, that many ASCII spaces (0x20) follow; it keeps the 1 MiB + 1 byte
case out of the repository.

**Coverage.** 428 cases: 81 that verify and 347 failures, at least one at
each of the 27 check ids. vmr-verify's vector test checks that every id is
exercised.

267 of them are the committed cases; the other 161 are their
**general-description copies** (the specification's owner, 2026-09-16, after
the release QA's QR-09). Supporting a registered profile is not a condition
of conformance, so every case that tests a rule of the general format on an
engine record has a copy, named `<id>-general-record`, over the same record
described generally: its `model_format` selects no profile, its
`learned_state_hash` is its components' named-set digest and its
`training_input_format` names its records' format (§7.1, §7.3, §8.2), and
every other byte is the vector's. The profile governs nothing else, so each
copy's expected verdict and check are its original's. A case of the
profile's own rules has no copy: the ones with `profile` in the id, and
`fail-consistency-parameter-count`, because the general description does not
check `parameter_count` (§7.3).

Of the 267 committed cases, the 57 that verify are:
- the vector in three JSON encodings and as COSE;
- a rotated key, window and time boundaries, an attestation under-claim, a
  declared non-compliance, and a policy evaluation dated before issuance;
- complete / partial / unchecked chains, a chain in mixed forms, and a chain
  across a key rotation;
- noncharacters raw and escaped, and the two bases of the integer-spelling
  cases;
- a record declaring the two optional documentation members, in both forms;
- a record in the general model description in both
  forms, a fine-tune of a base with no record, a fine-tune chained to
  another issuer's record, a diffusion model's weights, a one-file
  classical model, and the vector without a deployment;
- records naming other signed statements (`oms-v1`, an issuer's own format,
  `vmr-audit-checkpoint-v1`).

**Added on 2026-09-11** (spec §10; no earlier case changed): an integer has one spelling —
`pass-training-epochs-0` and `-10` verify, and the same signed bytes with
`training_epochs` written `-0`, `0.0`, `0e0`, `1e1` or `1E1` fail
`json.structure`; what is wrong inside the COSE protected header is
`cose.protected_header` — a tag where the kid's bstr head belongs, an empty
kid — and what the unprotected map holds, within the envelope's CBOR subset
and depth (below), is `cose.unprotected_header`;
strings are Unicode scalar values — a `\u` escape of a lone high or
low surrogate fails `json.structure`, surrogate bytes in CESU-8 form fail
`json.syntax`, and a signed record holding noncharacters verifies, raw or
escaped. The raw-noncharacter and CESU-8 inputs are given as `hex`,
so `cases.json` itself holds no noncharacter and no surrogate.

**Regenerated on 2026-09-12** (spec §10, the neutral example pack): the
record vector now declares `example-policy-pack-v1`, so the 92 cases
that embed it changed their input bytes (and predecessors); `fail-empty`
and `fail-garbage` did not. No case's expected verdict, check id or
lineage outcome changed, and no case was added or removed.

**Added on 2026-09-13** (spec §2 rule 13, §4.4
and §10; no earlier case changed): nesting, and the envelope's CBOR.
- A record nests four levels, the outermost object counting as the first,
  and a deeper text fails `json.structure` at any depth:
  `fail-nesting-5-levels`, `fail-nesting-127-levels` and
  `fail-nesting-128-levels` (either side of serde_json's default recursion
  limit), and `fail-nesting-10000-levels`. A syntax error past the deepest
  point still fails `json.syntax` (`fail-nesting-128-levels-unclosed`).
- The same payloads in COSE fail `cose.payload`:
  `fail-cose-nesting-5-levels`, `fail-cose-nesting-127-levels` and
  `fail-cose-nesting-128-levels`.
- The envelope's CBOR is one data item of the subset of spec §4.4, nesting at
  most 16 levels, its array counting as the first:
  - `fail-cose-nesting-16-cbor-levels` fails `cose.unprotected_header`, and
    `fail-cose-nesting-17-cbor-levels` fails `cose.structure`;
  - `null` is in the subset, so `fail-cose-cbor-null-in-unprotected-map`
    fails `cose.unprotected_header`;
  - outside it, each fails `cose.structure`: an unassigned simple value
    (`fail-cose-cbor-simple-value`), `true` (`fail-cose-cbor-true`), a float
    (`fail-cose-cbor-float`), a bignum (`fail-cose-cbor-bignum`), an
    indefinite length (`fail-cose-cbor-indefinite-length`), an 8-byte
    argument (`fail-cose-cbor-8-byte-argument`), all in the unprotected map,
    and an indefinite-length payload (`fail-cose-cbor-indefinite-payload`).
- Ten more, each
  where a verifier's CBOR decoder or JSON parser could read otherwise:
  - a map's keys are inside the map: `fail-cose-nesting-16-cbor-levels-in-a-key`
    fails `cose.unprotected_header`, and
    `fail-cose-nesting-17-cbor-levels-in-a-key` fails `cose.structure`;
  - a 4-byte argument is in the subset: `fail-cose-cbor-4-byte-argument`, in
    the unprotected map, fails `cose.unprotected_header`, and
    `fail-cose-non-preferred-4-byte-length`, the signature's length, fails
    `cose.canonical`;
  - outside the subset, each fails `cose.structure`: a text string that is
    not UTF-8 (`fail-cose-cbor-text-not-utf8`), `undefined`
    (`fail-cose-cbor-undefined`), reserved additional information
    (`fail-cose-cbor-reserved-additional-information`) and a double
    (`fail-cose-cbor-double-float`), all in the unprotected map, and an
    8-byte argument in the envelope's own items
    (`fail-cose-cbor-8-byte-signature-length`);
  - a text 100 000 levels deep fails `json.structure`
    (`fail-nesting-100000-levels`).

  The deepest JSON case is 100 000 levels. Rule 13 still has no depth limit
  within 1 MiB: a syntax pass that stops at some depth deeper than every
  case is still not conforming.
- A predecessor nested 128 levels breaks the chain
  (`fail-chain-predecessor-nesting-128-levels`).

The deep values are written as brackets inside each case's text (the COSE
payloads and the envelopes' CBOR inside its `hex`), so `cases.json` itself
nests no deeper than before.

**Added on 2026-09-13** (spec §10): a record may carry two optional members,
`data_governance` and `human_oversight`, each a closed object holding one
`documentation_hash`. Nine cases follow every earlier one, and each earlier
case is unchanged byte for byte:
- `pass-documentation-declared`, the vector with both members re-signed with
  key A, and `pass-documentation-declared-cose` verify with the same 21 and
  25 checks;
- `fail-documentation-hash-edited`: a hash changed after signing fails
  `signature.payload_hash`;
- `fail-documentation-hash-uppercase` and `-hash-empty`: a hash in upper-case
  hex, or `""`, fails `format.schema`;
- `fail-documentation-null`, `-unknown-member`, `-missing-hash` and
  `-not-an-object`: a `null` member, an unknown member inside one, `{}`
  without its hash, and a member written as a bare string fail
  `json.structure`.

The committed record vector declares neither member and did not change.

**Added on 2026-09-14** (spec §10): each failing case above sets one member only, so a
verifier that misread spec §2 rule 3 for the other member passed every case.
Seven cases follow every earlier one, each an earlier case's edit made on the
other member, and each earlier case is unchanged byte for byte:
- `fail-documentation-governance-hash-edited` fails
  `signature.payload_hash`;
- `fail-documentation-oversight-hash-uppercase` and
  `fail-documentation-governance-hash-empty` fail `format.schema`
  (`documentation_hash` is not one of spec §2 rule 9's optional hashes, so
  `""` fails for either member);
- `fail-documentation-oversight-null`,
  `fail-documentation-governance-unknown-member`,
  `fail-documentation-oversight-missing-hash` and
  `fail-documentation-governance-not-an-object` fail `json.structure`.

Each of the nine cases' edits is now made on both members (the two passing
cases carry both). A member written as a JSON array is not among
these cases; the next group holds such cases.

**Added on 2026-09-14** (spec §2
rule 2, §6.2 check 4j and §10): an object written as a JSON array
is not that object. Eighteen cases follow every earlier one, and each earlier
case is unchanged byte for byte. Each takes a signed record and, after
signing, writes one object as the array of its values in the order of the
schema's `properties`. That is the order in which a parser that reads a
record from the array of its fields takes them, so a verifier with that fault
reads each text as the signed record and verifies it.
- One case per nested object kind fails `json.structure`:
  - on the vector: `fail-issuer-as-array`, `fail-public-key-as-array`,
    `fail-model-identity-as-array`, `fail-architecture-as-array`,
    `fail-state-component-as-array`, `fail-learning-provenance-as-array`,
    `fail-training-environment-as-array`,
    `fail-training-input-provenance-as-array`,
    `fail-collection-period-as-array`, `fail-deployment-context-as-array`,
    `fail-inference-boundary-as-array`, `fail-policy-compliance-as-array`,
    `fail-policy-result-as-array` and `fail-signature-section-as-array`;
  - on `P2`, whose lineage has all five members: `fail-lineage-as-array`;
  - on `pass-documentation-declared`:
    `fail-documentation-governance-as-array` and
    `fail-documentation-oversight-as-array`.
- `P2` with its predecessor `P1` so written, its issuer's public key as an
  array, breaks the chain: `fail-chain-predecessor-public-key-as-array` fails
  `lineage.chain`.

The COSE form needs no such case: check 7c compares the payload byte for byte
with the canonical signed payload of the record it carries.

**Added on 2026-09-14** (spec §2
rule 2, §6.2 check 2 and §10): one case, after every earlier one,
each earlier case unchanged byte for byte. `fail-record-as-array` is the
vector written, after signing, as the array of its values in the order of the
schema's `properties`. Its first byte is `[`, so it fails check 2,
`input.form`, before check 4j, `json.structure`, is reached: rule 2's
"`json.structure` at every level" holds below the record itself.

**Added on 2026-09-14** (spec §7, §8 and §10). A record can now describe any kind of model:
`model_format` selects the KHALM engine profile `snn-compact-v1` or the
general description. Forty-three cases follow every earlier one, and each
earlier case is unchanged byte for byte. Unless a case says otherwise, it
starts from the general conformance vector
[`../record/example-general-v0.1.json`](../record/example-general-v0.1.json)
(a model of four synthetic files, `not-held` training records) and is
re-signed with key A.
- **Seven verify:**
  - `pass-general-open-weights-not-held` (JSON) and
    `pass-general-open-weights-not-held-cose`;
  - `pass-general-fine-tune-unrecorded-base`: a fine-tune's own files,
    `derived_from` naming a base with no record, three committed
    `named-set-v1` records, an accelerator, two residency countries, and no
    deployment;
  - `pass-general-fine-tune-chain-across-issuers`: that fine-tune issued by
    `did:web:other.example` with key B as a `fine-tune` successor of the
    general conformance vector (issuer A), supplied as its predecessor;
    lineage `complete`;
  - `pass-general-diffusion-weights-only`: the components are a diffusion
    model's three weight files, so `model_hash` (every file) differs from
    `learned_state_hash`;
  - `pass-general-classical-one-file-not-disclosed`: one ONNX file, training
    records `not-disclosed`, no deployment;
  - `pass-vector-without-deployment-and-accelerator-software`: the vector, a
    profile record, without `deployment_context` and `accelerator_software`.
- **The profile, and bytes fitted to it,** fail `format.consistency`:
  - `fail-profile-extra-component`: the vector with a fourth component;
  - `fail-profile-model-hash-of-files`: the vector with a files digest as
    `model_hash`;
  - `fail-profile-identifier-dropped`: the vector's `model_format` edited to
    `safetensors`;
  - `fail-profile-identifier-added`: the general vector's edited to
    `snn-compact-v1`;
  - `fail-profile-byte-fitted-under-general-format`: another model's bytes
    cut to the engine's layout with one hidden neuron, under `safetensors`;
  - `fail-profile-training-input-format`: the vector naming a record format.
- **The general description:** `fail-general-state-hash-not-digest`,
  `fail-general-components-unordered`,
  `fail-general-component-name-repeated`,
  `fail-general-component-name-dot-segment`,
  `fail-general-component-name-leading-slash`,
  `fail-general-component-name-empty`,
  `fail-general-component-hash-edited` (edited after signing) and
  `fail-general-training-format-missing` fail `format.consistency`;
  `fail-general-no-components` fails `format.schema`.
- **The training commitment:** `fail-not-held-with-digest`,
  `fail-not-held-count-not-zero`, `fail-not-held-with-format` and
  `fail-committed-root-empty` (the vector with `""` as its root) fail
  `format.consistency`; `fail-disclosure-outside-enum` fails
  `format.schema`; `fail-disclosure-edited` (after signing) fails
  `signature.payload_hash`.
- **Residency:** `fail-residency-countries-with-residency` (the vector, which
  names one country, naming two more) and
  `fail-residency-countries-unordered` fail `format.consistency`;
  `fail-residency-countries-one` and `fail-residency-countries-lowercase`
  fail `format.schema`.
- **Derived models, empty strings and structure:**
  - `fail-derived-from-unordered` fails `format.consistency`;
  - `fail-derived-from-relation-outside-enum`, `fail-derived-from-empty`,
    `fail-general-training-format-empty`, `fail-accelerator-empty` and
    `fail-accelerator-software-empty` fail
    `format.schema`;
  - `fail-derived-from-null`, `fail-deployment-context-null` (on the vector),
    `fail-training-epochs-null`, `fail-accelerator-not-a-string`,
    `fail-derived-from-entry-unknown-member` and
    `fail-derived-from-entry-as-array` fail `json.structure`.

The committed record vector did not change. Every earlier case's record
names `snn-compact-v1`, and the vector test checks that no earlier case
uses the general description.

**Added on 2026-09-14** (spec §2 rule 3, §7, §7.7 and §10). Fifty cases follow
every earlier one, and each earlier case is unchanged byte for byte. Each
breaks one rule with every other member consistent: where a name or an order
is refused, `learned_state_hash` and `model_hash` are recomputed over the
components as they stand, so only that rule can refuse the record. Unless a
case says otherwise it starts from the general conformance vector and is
re-signed with key A.
- **Names as stored** verify: `pass-general-component-name-backslash`
  (`unet\config.json`), `pass-general-component-names-nfc-and-nfd` and
  `pass-general-component-names-case-twins`.
- **The name rules and the order, the digest kept** fail
  `format.consistency`: `fail-general-component-name-empty-digest-kept`,
  `fail-general-component-name-dot-segment-digest-kept`,
  `fail-general-component-name-dotdot-segment-digest-kept`,
  `fail-general-component-name-leading-slash-digest-kept`,
  `fail-general-component-name-trailing-slash-digest-kept`,
  `fail-general-component-name-double-slash-digest-kept`,
  `fail-general-component-name-repeated-digest-kept`,
  `fail-general-components-unordered-digest-kept`,
  `fail-general-component-names-utf16-order` (U+1F600 before U+FF5E) and
  `fail-general-component-names-case-insensitive-order` (`a.bin` before
  `B.bin`); `pass-general-component-names-utf8-order` and
  `pass-general-component-names-capitals-first` verify.
- **The identifier, compared exactly:** `fail-profile-identifier-case`
  (the vector under `SNN-compact-v1`) fails `format.consistency`;
  `pass-general-profile-look-alike` (the vector's three components as a
  named-set digest, under `SNN-compact-v1`),
  `pass-general-profile-look-alike-fullwidth` (under an identifier with
  FULLWIDTH HYPHEN-MINUS, which NFKC maps to the profile's) and
  `pass-general-empty-model-format` verify.
- **The commitment, residency and bases:** `fail-not-held-with-root`,
  `fail-committed-digest-empty` (the vector),
  `fail-residency-countries-repeated` and `fail-derived-from-repeated` fail
  `format.consistency`; `pass-general-empty-file-component` verifies.
- **Shape selects nothing:** `pass-general-profile-shaped-components`,
  whose components are named and sized as the profile's, verifies as a
  general description.
- **Settled by the text:** `pass-profile-not-held` and
  `pass-profile-derived-from` (the vector), `pass-general-file-and-directory-names`
  (`unet` and `unet/config.json`) and `pass-general-component-name-with-controls`
  (names holding U+0001 and U+202E, written as JSON escapes) verify;
  `fail-derived-from-itself` fails `format.consistency`: a model is not made
  from itself.
- **`parameter_count`:** `pass-general-parameter-count-not-stated`, in
  JSON and as `pass-general-parameter-count-not-stated-cose`, verifies;
  `fail-profile-parameter-count-absent` (the vector) fails
  `format.consistency`, and `fail-general-parameter-count-null` fails
  `json.structure`.
- **`statement_references`:** `pass-statement-references-oms-v1`,
  `pass-statement-references-issuer-format` and
  `pass-statement-references-issuer-format-cose` verify;
  `fail-statement-references-dotless-unregistered`,
  `fail-statement-references-unordered` and
  `fail-statement-references-repeated` fail `format.consistency`;
  `fail-statement-references-empty`,
  `fail-statement-references-digest-uppercase`,
  `fail-statement-references-digest-empty`,
  `fail-statement-references-format-uppercase` and
  `fail-statement-references-format-look-alike` fail `format.schema`;
  `fail-statement-references-null`,
  `fail-statement-references-entry-member-repeated`,
  `fail-statement-references-entry-unknown-member`,
  `fail-statement-references-entry-as-array` and
  `fail-statement-references-format-not-a-string` fail `json.structure`.
- **Appended later:** nine cases, after all of the
  above. `pass-statement-references-registered-name-as-segment` (`oms-v1.x`
  and `x.oms-v1`, an issuer's formats, not `oms-v1`),
  `pass-statement-references-two-of-one-format` (two `oms-v1` statements),
  `pass-profile-statement-references` and its `-cose` form (the vector, in the
  profile, naming a statement), `pass-derived-from-learned-state-hash` and
  `pass-general-parameter-count-zero` verify;
  `fail-statement-references-dotless-oms-v2` (a format without `.` that is not
  registered) and `fail-derived-from-own-model-hash-differs-from-state-hash`
  (a record whose `model_hash` and `learned_state_hash` differ, naming its own
  `model_hash`) fail `format.consistency`;
  `fail-statement-references-format-fullwidth` (a fullwidth look-alike that
  NFKC maps to `oms-v1`) fails `format.schema`.

The vector test checks that no earlier case carries
`statement_references`.

**Added on 2026-09-15** (spec §7.7 and §10): a second registered statement
format, `vmr-audit-checkpoint-v1`, which names an audit-log checkpoint by the
SHA-256 of its signed payload. Four cases follow every earlier one, and no
earlier case's expected result changed:
`pass-statement-references-vmr-audit-checkpoint-v1` and its `-cose` form
verify; `fail-statement-references-vmr-audit-checkpoint-v1-case-variant`
(`VMR-audit-checkpoint-v1`) fails `format.schema`; and
`fail-statement-references-vmr-audit-checkpoint-look-alike`
(`vmr-audit-checkpoint-v2`, not registered) fails `format.consistency`.

## Keys (test-only)

All keys are **derived**, never generated: secret scalar = SHA-256 of a
fixed label. They are worthless outside tests.

| Key | Label (SHA-256 of) | Role |
|---|---|---|
| A | `khalm v0.1 test-vector signing key` | the record vector's key; trusted for `did:web:factory-operator.ph` |
| A2 | `khalm v0.1 verify-vector key A2` | the same issuer's second key (rotation) |
| B | `khalm v0.1 verify-vector key B` | `did:web:other.example`'s key |
| F | `khalm v0.1 verify-vector key F` | a forger's key, trusted by no store |

Signatures are deterministic (RFC 6979, then low-s), so every file here
regenerates byte for byte on any machine — no engine, no GPU.

## Trust stores

| Store | Trusts |
|---|---|
| `ts-basic` | A for the vector issuer; B for `did:web:other.example` (software, 2026-01-01 – 2027-01-01) |
| `ts-rotated` | A and A2 for the vector issuer |
| `ts-revoked` | A, revoked |
| `ts-window-before` | A from 2026-09-10T00:00:01Z (after the vector's `issued_at`) |
| `ts-window-until` | A until 2026-09-10T00:00:00Z (= `issued_at`: excluded) |
| `ts-window-from` | A from 2026-09-10T00:00:00Z (= `issued_at`: included) until one second later |
| `ts-attestation-hardware` | A at `hardware` |
| `ts-key-for-other-issuer` | A, but for `did:web:other.example` |
| `ts-two-keys` | A and B, both for the vector issuer |
| `ts-rotation-window` | A until 2026-09-10T06:00:00Z, A2 from then |
| `ts-a2-revoked` | A; A2 revoked |
| `ts-empty` | no one |

## Records in the chains

`P1` is the vector itself (`initial`). `P2`
(`urn:uuid:00000000-0000-4000-8000-0000000000b2`, `training-update`, issued
2026-09-10T12:00:00Z) and `P3` (`…00b3`, `fine-tune`, 18:00:00Z) are the
vector re-signed as successors: new id and time, `previous_record_id` /
`previous_record_hash` naming their predecessor by its **recomputed**
signed-payload hash (spec §2 rule 12), the same root, length + 1.

## The record vector and the rules of 2026-09-11

The format's revision of 2026-09-11 (`../../record-format-v0.1.md` §10) did
not regenerate `../record/example-v0.1.json`: every value in it already
satisfies the tightened rules — its seven timestamps are profile timestamps,
its three ids lower-case canonical UUID URNs, `hardware_id` / `software_hash`
`sha256:` hashes and `tee_measurement` `""`, its issuer and deployer ASCII
`did:web:` DIDs, its three state components in order with `parameter_count`
24 704 = 64·128 + 128² + 128, and `model_hash` = `learned_state_hash`.
Verifying it needs a trust store that trusts key A for its issuer: `ts-basic`
(case `pass-vector-json`).

## Regenerating

The files are written only by the generator, never by hand:

```
cd vmr
VMR_WRITE_VECTORS=1 cargo test -p vmr-verify --test vectors -- --ignored
cargo test -p vmr-verify --test vectors      # verify_vectors_are_reproducible
```

The generator declares
each case's expected result by hand, from the spec — it does not compute it
by running the verifier. A regeneration that changes any byte belongs in its
own commit, listing every changed case (as for the record vector).
`.gitattributes` keeps `specs/test-vectors/**` at LF line endings: these are
byte-exact inputs.
