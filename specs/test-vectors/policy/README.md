# Policy evaluation vectors (v0.1)

The cross-implementation contract for **evaluating** a VMR policy pack
against a record (`../../policy-pack-format-v0.1.md` §9). The pack format's structure has its schema
(`../../policy-pack-schema/v0.1.json`); these cases pin what an evaluator
must answer.

## The contract

For each case in [`cases.json`](cases.json), a conforming evaluator is given:

- `pack.text` — the pack document;
- `record.text` — the record's JSON document;
- `evaluation_time` — the evaluation time (never a clock);
- `context`, when the case has one — the verification context (§5):
  - `lineage_outcome` — `initial`, `complete`, `partial` or `not_checked`;
  - `predecessors` — the verified predecessors, immediate predecessor
    first, each with its `signed_payload_hash` and its record's `text`.

  A case without `context` is evaluated without one.

It must produce every member of `expected`:

- `pack_payload_hash` — the pack's payload hash (§4);
- `results` — for every rule in the pack's order: `rule_id`, `rule_type`,
  `severity`, `status` and `evidence_hash` (§6, §7);
- `indeterminate` — the ids of the indeterminate rules, in the pack's order;
- `overall` — `pass`, `fail` or `indeterminate` (§8);
- `policy_compliance` — the record section built from the evaluation (§8).

Nothing else is contract: the wording of a rule's reason and the layout of a
report are each implementation's own.

**Document texts.** Every `text` is the document in its JCS form (RFC 8785),
so a case does not depend on how a file was laid out or checked out. There
are six exceptions: a record text that writes one number as JCS would not
(`1.0`, `9007199254740993`, `1e21`, and `-0` three times), which its case's
`description` says. The
reference packs' texts are their committed files in JCS form. Their payload
hashes are the files' own, and they are pinned only here.

**`verifiable`.** It is `true` when a verifier can replay the case exactly:
`record.text` is a well-formed v0.1 record, and, for a record with
predecessors, `context` is the one verification establishes from the case's
predecessors.

- **How the replay goes.** vmr-cli's cross-implementation test
  replays each verifiable case in five steps:
  1. **Re-sign the record with key A** of the verification vectors (below),
     so that it verifies under `../verify/trust-stores/ts-basic.json`. That
     means:
     - replace `issuer.public_key` with key A's JWK;
     - replace `issuer.key_id` and `signature.signing_key_id` with its key id
       (record format §5);
     - recompute `signature.signed_payload_hash`, then sign.

     The store must trust the key for the record's `issuer.issuer_id`, at
     a level no lower than its `issuer.attestation_level`: `software` for
     every verifiable case here.
  2. **Supply the predecessors,** each `text` as a predecessor file, immediate
     predecessor first (`vmr record verify --previous`). Do not re-sign
     them: they are already signed with key A, and each successor names its
     predecessor's signed payload hash.
  3. **Verify** at `evaluation_time`, with the case's pack.
  4. **Check the lineage outcome.** Verification must establish the case's
     `lineage_outcome`, or `initial` for a case without `context`.
  5. **Check the evaluation.** Every status, severity and evidence hash must be
     the case's.
- **Why re-signing changes no evidence.** No rule reads a member that
  re-signing changes. Every record built from the conformance record
  already names key A, so re-signing it changes no byte of its payload. The
  demo record's issuer key members change, and no rule reads them.
- **What `false` means.** The case can be evaluated but not replayed by a
  verifier, for one of two reasons:
  - **The record is not one a verifier accepts:** a member removed or
    `null`, a member of the wrong JSON type, a zero-size component, a hash in
    upper-case hex, a level the store does not grant, and so on.
  - **The context is not one a verifier gives:** no context for a record
    with predecessors, or an outcome that contradicts the chain length.
- **The signature a case carries.** Signatures verify under key A for:
  - the unmodified conformance record;
  - every record of a chain (a successor, and each predecessor);
  - the unmodified demo record, under its own issuer's key.

  Any other record carries its source's signature, which does not hold.

## Coverage

291 cases, 131 of them verifiable, 31 in a verification context.

159 of them are the committed cases, counted below; the other 132 are their
**general-description copies** (the specification's owner, 2026-09-16, after
the release QA's QR-09). Supporting a registered profile is not a condition
of conformance, so every case that evaluates a rule against an engine record
has a copy, named `<id>-general-record`, over the same record described
generally: its `model_format` selects no profile, its `learned_state_hash`
is its components' named-set digest and its `training_input_format` names
its records' format (record format §7.1, §7.3, §8.2), and every other byte
is unchanged. No rule of this document reads those three members, so each
copy's expected statuses are its original's. A copy whose case edits the
model's state description is marked not verifiable, whatever its original
was: under the general description `learned_state_hash` is checked against
the components (record format §7.3), and under the profile it is not (§7.4),
so such a record is no longer one a verifier replays. Its evaluation is the
same either way — no rule here reads whether a record verifies. The cases over the committed
engine artifact (`-demo-record`) have no copy: that artifact cannot be
described generally without ceasing to be the artifact.

- **120 one-rule packs.**
  - **Every outcome.** Each of the seven rule types passes, fails and is
    indeterminate.
  - **Every step outcome of §6.** `vmr-policy`'s
    vector test `the_policy_vectors_reach_every_step_outcome` names a
    case for each, with the status it yields. It covers:
    - each `audit_integrity` and `execution_integrity` setting;
    - each step's indeterminate and fail branches;
    - both types' context steps.
  - **The terms of §5.**
    - **Absence and type:**
      - a pointer that is absent;
      - a member present as `null`, which hashes as the absent one
        (`data-residency-null`, `data-residency-absent`);
      - an empty string;
      - members of the wrong JSON type, each `indeterminate`, never `fail`;
      - a whole absent parent object, which contributes one `null` per read;
      - a parent that is not an object (`export-control-boundary-not-an-object`).
    - **Components:** one with no `hash`, one that is not an object, and an
      empty array.
    - **Levels and hashes:** an attestation level outside the three; hashes
      in upper-case and in mixed-case hex.
    - **Counts:** 2^53 − 1 (a count), 2^53 and 2^53 + 1 (not counts, one
      evidence hash), `1.0` and `1e21`; also for `training_input_count` and
      `size_bytes`. `-0` for all three counts: not a count, so
      `indeterminate`, while each case's twin whose text writes `0` passes or
      fails with the same evidence hash (§5; `audit-integrity-chain-length-zero`,
      `audit-integrity-input-committed-fail-no-input`,
      `execution-integrity-fail-zero-size`).
    - **Timestamps:** a date that is not in the calendar.
  - **The empty string (§6.5).** For `training_software`, `software_hash` and
    `tee_measurement`: `""`, which fails the requirement, against absent and
    wrong-typed, which are `indeterminate`.
  - **The verification context.**
    - **Successors:** `complete`, `partial` and `not_checked`, each verifiable
      and replayed with its predecessors, for `require_verified_lineage` and
      `require_state_kept`.
    - **Without context:** a successor evaluated with none, which is
      unverifiable.
    - **A context that does not apply:** `initial` on an initial record
      (verifiable); `initial` on a successor, and `complete` on a chain of
      one (unverifiable).
  - **Keeping the learned state:** a deployment that keeps it, a policy
    change that does not, and a training update that may change it.
  - **The order of steps.** `export_control`'s air-gap step decides before
    its egress step.
  - **`documentation_declared` (§6.7).** 21 cases, after every
    earlier case. Thirteen came with the task:
    - each document pinned by a hash (pass, verifiable);
    - each document absent (fail, verifiable: the conformance record as it
      is);
    - only the other document declared (fail, verifiable);
    - a record text that is not an object;
    - a member that is `null`, which hashes as the absent one but is
      `indeterminate`;
    - a member that is not an object, `{}`, a `""` hash, a number;
    - a string that is not a hash (fail);
    - upper-case hex (pass, unverifiable).

    Eight came later. They follow the two-rule pack below; each is unverifiable and
    sets `data_governance`:
    - §5's "A hash" at its edges, each a fail: `SHA256:` in upper case
      (`documentation-declared-hash-prefix-upper-case`), 63 and 65 hex
      digits (`-hash-63-digits`, `-hash-65-digits`), a trailing line feed
      and a leading space (`-hash-trailing-newline`, `-hash-leading-space`),
      and 64 fullwidth digits, U+FF11 (`-hash-fullwidth-digits`);
    - mixed-case hex (`documentation-declared-mixed-case-hash`): pass;
    - a hash beside a `title` member (`documentation-declared-extra-member`):
      pass, because step 3 reads no other member of the object.
  - **A signed pack.** `signed-pack-evaluates-as-unsigned` is
    `attestation-level-pass`'s pack with an authority signature. It has the
    same payload hash and the same evaluation (§4).
  - **RFC 8785.** The vector test `the_policy_vectors_tell_rfc_8785_from_a_naive_canonical_form`
    holds that a naive canonical form gets some case wrong. The cases that
    ensure it:
    - non-ASCII text, a quotation mark and a backslash in a verifiable
      record (`execution-integrity-training-software-non-ascii`);
    - non-ASCII text in a pack (`attestation-level-pack-text-non-ascii`);
    - member names whose UTF-16 order differs from their code-point order
      (`execution-integrity-components-member-order`);
    - numbers JCS writes differently from their text.
- **2 cases for time independence (§5).** `time-independence-first` and
  `time-independence-later` evaluate one pack and record a year apart. The
  results and evidence hashes are the same, and `evaluated_at` differs.
- **4 multi-rule packs for the overall status (§8):**
  - a mandatory failure over a mandatory indeterminate;
  - failures of recommended and informational rules, which leave the pack
    compliant;
  - a mandatory indeterminate;
  - a pack with no mandatory rule.
- **1 two-rule pack for §6.7's evidence.**
  `documentation-declared-two-rules-one-evidence-hash` holds two recommended
  rules, one per document, on a record that pins only its human oversight
  documentation. Both carry one evidence hash; one fails and one passes.
- **10 reference cases.** Each of the five reference packs
  (`../../policy-packs/`) against two records:
  - the conformance record, evaluated at `2026-09-11T00:00:00Z`;
  - the demo record, evaluated at `2026-09-11T12:00:00Z`. It
    pins its software environment by hash (`software_hash`) and a data
    governance document, and declares its issuer's evaluation of the EU pack.
    It is compliant against every pack in the format's sense (§8): every
    mandatory rule of the pack passed. That is not a finding that the
    record or its model meets the instrument a pack cites.

  The conformance record declares no documentation member, so it fails the
  EU pack's two recommended documentation rules; the demo record declares
  data governance only, so it fails the human oversight rule. Both sign an
  empty `tee_measurement`, so both fail RATS's recommended TEE rule. No
  recommended rule moves an overall status.
- **10 cases for records of any kind of model:** nine
  one-rule packs and an eleventh reference case, counted here and not in the
  groups above. They follow every earlier case, each verifiable. The
  record is the general conformance record
  ([`../record/example-general-v0.1.json`](../record/example-general-v0.1.json)):
  its components are its files, it commits no training records
  (`not-held`), and it states no times, environment or residency.
  - It fails `require_input_committed` and `require_tamper_evident`
    (`general-not-held-input-committed`, `general-not-held-tamper-evident`):
    its `training_input_disclosure` declares that nothing is committed
    (§6.4; `indeterminate` before task 10.12a).
  - It is `indeterminate` under `require_ordered_record`
    (`general-not-held-ordered-record`).
  - It passes `require_learned_state_components`
    (`general-learned-state-components`).
  - It fails `require_environment_pinned` on its `""` members
    (`general-not-held-environment-pinned`).
  - Naming two residency countries, DE and FR, re-signed, it passes
    `data_residency` when both are allowed
    (`general-residency-countries-data-residency`; `indeterminate` before
    task 10.12a), and is `indeterminate` for `source_screening`, since its
    source type is `""` (`general-residency-countries-source-screening`).
  - Without `deployment_context`, re-signed, it is `indeterminate` for
    `export_control` (`general-no-deployment-export-control`).
  - A deployment record following it keeps its model, the same `model_hash`,
    in a `complete` context (`general-deployment-state-kept`).
  - The EU AI Act reference pack finds it non-compliant. Record keeping fails
    on the declared withholding, technical documentation fails on the `""`
    training software, and accuracy and robustness passes
    (`reference-khalm-reading-eu-ai-act-2026-general-record`, an eleventh reference case).
- **8 cases of task 10.12a,** after every earlier case, counted here and not
  in the groups above; four are verifiable, and two are evaluated in a
  context:
  - `data_residency_countries`: a country that is not allowed fails
    (`general-residency-countries-data-residency-fail`); a list holding a
    value that is not a declared string is `indeterminate`
    (`data-residency-countries-not-a-list-of-codes`); `source_screening`
    passes and fails on the countries
    (`general-residency-countries-source-screening-pass`,
    `general-residency-countries-source-screening-fail`);
  - a declared `not-disclosed` fails `require_input_committed`
    (`general-not-disclosed-input-committed`), and a
    `training_input_disclosure` that is not a string declares nothing
    (`audit-integrity-disclosure-wrong-type`);
  - `require_state_kept` compares `model_hash`: other components of the same
    model keep it (`general-deployment-other-components-model-kept`), and
    another `model_hash` does not (`general-deployment-model-hash-changed`).

**Loading and a pack's signature** have files of their own:
[`pack-loader.json`](pack-loader.json) and
[`pack-signature.json`](pack-signature.json), described below.

**Not here at all: values nested past 128 levels.** A case is text, and a
record text that nests more than 127 levels of arrays and objects is refused
before it is evaluated (§5, input 2). So a case cannot hold a value past the
128-level rule of §5: that rule is for a value handed to an evaluator already
parsed, or built in code. vmr-policy's own tests cover it.

## The pack-loader vectors

[`pack-loader.json`](pack-loader.json) holds the loading contract of
`../../policy-pack-format-v0.1.md` §3 and §4.

- **A case** is a pack, given as `text`, or as `hex` (its bytes in lower-case
  hex) where the bytes are not UTF-8 or start with a byte order mark. Either
  is followed by `append_spaces` ASCII spaces when that member is present.
  Its `expected` is:
  - `{"result": "ok", "pack_payload_hash": …}`: the pack loads, and its payload
    hash (§4) is this;
  - `{"result": "error", "refusal": …}`: the pack is refused. A loader that
    reports identifiers reports this one, from §3's table, which the file's
    `refusals` repeats.
- **One rule broken per refused text,** since v0.1 fixes no order among the
  other refusals. The exceptions are the texts §3's two fixed orders decide:
  - the four nested 128 levels deep: `error-nesting-128-levels`, and the same
    text after a byte order mark, after a byte that is not UTF-8, and after a
    syntax error. A text can nest 128 levels only inside a member the format
    lacks, so each breaks refusal 2 as well, and §3 decides refusal 12 first;
  - `error-size-and-nesting-128-levels`, which breaks refusals 1, 2 and 12,
    and §3 decides refusal 1 first.
- **73 cases: 12 load and 61 are refused,** at least one for each of the 12
  refusals. The packs that load:
  - one per rule type;
  - a signed pack (a loader does not check a signature);
  - a pretty-printed pack, with its JCS form's payload hash;
  - `minimum_chain_length` 2^53 − 1;
  - a pack padded to exactly 1 MiB;
  - a pack whose description holds a quotation mark and 200 `[`: inside a
    string, no bracket counts toward refusal 12.

  The refused packs:
  - refusal 2 twenty-seven ways, among them 127 levels of nesting, which is
    read and refused for its member, a lone surrogate escape in a value and in
    a rule, and a rule of each type that has a required parameter, without
    it: `error-structure-missing-document`, and, appended later with no earlier case changed,
    `error-structure-missing-allowed-jurisdictions`,
    `error-structure-missing-restricted-list` and
    `error-structure-missing-minimum-level`;
  - among those, ten objects written as the array of their values, appended
    on 2026-09-14 (policy-pack format §3 and §10), with no earlier case changed. Each is
    written in the order of the schema's `properties` (the order in which a
    parser that reads a record from the array of its fields takes them):
    - the pack itself: `error-structure-pack-as-array`;
    - its authority: `error-structure-authority-as-array`;
    - its signature section: `error-structure-signature-as-array`;
    - a rule of each of the seven types, as its `type` followed by its
      members' values: `error-structure-data-residency-rule-as-array`,
      `-source-screening-`, `-export-control-`, `-audit-integrity-`,
      `-execution-integrity-`, `-attestation-level-` and
      `-documentation-declared-rule-as-array`;
  - a duplicate member at the top, in a rule, and written once as an escape;
  - `1.0`, `1e0`, `-0` and `-1`, then 2^53 and 2^64; `1e400`, `-1e400` and an
    integer of 400 digits, which no double holds, by how they are written;
  - eight broken value rules, `severity` and a `document` outside its enum
    among them;
  - two jurisdictions;
  - three rules that ask for nothing;
  - refusal 12 four ways, and refusal 1 over refusal 12 once (above).
- **Texts.** Every text is in JCS form, unless its case needs a spelling JCS
  does not write, and the case's `description` says which. No text holds a
  byte order mark or another invisible character raw: those bytes are given
  as `hex`.
- **The replays.** vmr-policy's vector test loads every case. vmr-cli's
  cross-implementation test runs every case through `vmr record
  verify --policy-pack` with the conformance record, in both builds: a
  refused pack exits 1 and names its identifier.
- **Growth.** New cases go at the end of the generator's list. The seventh
  rule type, `documentation_declared`, reached these
  vectors after nine cases had followed the section of one loading case per
  rule type, so its loading case and its two refusals come last, and no
  earlier case moved.

## The pack-signature vectors

[`pack-signature.json`](pack-signature.json) holds the reference verifier's
check of a pack's authority signature: `../../trust-store-format-v0.1.md`
§4.2.

- **A case** gives:
  - `pack.text`, in JCS form;
  - `trust_store.text`: the conformance record's issuer with key A, and the
    case's `policy_authorities` when it has any;
  - `authority_store`: `{"text": …}`, or `null`;
  - `evaluation_time`, and `require_signed_pack`.
- **`expected`:**
  - `exit_code`, 0 or 1. **It is not part of the conformance contract** (the
    owner, 2026-09-16): it records what this repository's reference CLI
    exits with, so another implementation's exit status is its own business
    and the conformance runner strips it before comparing
    (`specs/conformance/run.py`, the `policy_pack.signature` operation). It
    is what `vmr record verify --record <FILE>
    --trust-store … --at … --policy-pack …` exits with, plus
    `--authority-store` and `--require-signed-pack` when the case has them.
    `<FILE>` is the conformance record: the `record` member of
    `../record/example-v0.1.json`, written to a file of its own. That file
    wraps the record with its `description` and `expected`, so given whole
    it is not a record, and the command exits 3. The conformance record
    passes the pack's one rule;
  - `pack_payload_hash`, the pack's payload hash (policy-pack format §4), or
    `null` for a pack text that format's §3 refuses, which loads no pack;
  - for exit 0, `pack_signature`: `unsigned`; `not_checked` with
    `signing_key_id`; or `valid` with `signing_key_id`, `authority_id` and the
    store's `authority_name`;
  - for exit 1, `refusal`: one of §4.2's identifiers. For a store the loader
    refuses (§4.2's steps 1 and 2) it is the store's kind
    (trust-store format §3), and for a pack (step 3) its refusal (policy-pack
    format §3).
- **40 cases: 12 evaluated, 28 refused.**
  - **Evaluated:** 2 `unsigned`, 4 `not_checked` and 6 `valid`.
  - **Refused:** each of the nine identifiers of §4.2, and
    `trust_store.structure` and `policy_pack.structure`.
  - **What they cover:**
    - every state and refusal, with and without `--require-signed-pack`;
    - authorities from the trust store and from an authority store;
    - an authority store that holds a key the trust store trusts for the
      record's issuer, alone and beside the key that signed the pack;
    - the window at T: `valid_from` at T and one second after it,
      `valid_until` one second after T and at T, and no `valid_until`;
    - one case for each pair of neighbouring steps of §4.2, breaking both,
      the authority store's two refusals included;
    - appended on 2026-09-14, with no earlier case
      changed, eight cases where an object is written as the array of its
      values:
      - a policy authority and its key, in the trust store
        (`structure-trust-store-authority-as-array`, `-authority-key-`) and
        in an authority store (`structure-authority-store-authority-as-array`,
        `-authority-key-`), and the authority store itself
        (`structure-authority-store-as-array`): `trust_store.structure`;
      - the pack's signature section (`structure-pack-signature-as-array`)
        and its `authority`, signed over that text
        (`structure-pack-authority-as-array`): `policy_pack.structure`;
      - an authority store and a pack both so written
        (`order-authority-store-structure-before-pack-structure`): the store
        is refused first.
- **The replays.**
  - vmr-cli's pack-signature vector test replays every case through the
    libraries, in §4.2's order: vmr-policy for the pack, vmr-verify for the
    stores and the key.
  - vmr-cli's cross-implementation test replays every case through the
    binary, in both builds.

## The records

- **The conformance record** is `../record/example-v0.1.json`, an initial
  record signed with key A. Variants change or remove one member, and each
  case's `description` says which.
- **The chains** are built from it. Each successor names its predecessor by
  id and by the predecessor's recomputed signed payload hash (record format
  §6.5), and each record of a chain is signed with key A. The generator
  builds:
  - the second record of a chain, a training update;
  - a third, following it;
  - a deployment that keeps the learned state;
  - a policy change and a training update that carry another learned state
    (with `model_hash` equal to it).
- **The demo record** is the payload of a record the authors' engine build
  emits from the demo inputs, read from that record when the cases are
  generated.
  - A re-emission of the demo fails the reproducibility test until these
    cases are regenerated, in their own commit.
  - vmr-cli's cross-implementation test compares a record the
    engine emits from the same inputs with these cases, hash for hash.

## The keys (test-only)

Every key is derived, never generated: the secret scalar is the SHA-256 of a
label. Each is worthless outside tests. Signatures are deterministic
(RFC 6979, then low-s), so the files regenerate byte for byte on any machine.

- **The signed pack's key:** the label is
  `khalm v0.1 policy-vector pack authority key (test-only)`.
- **Key A**, the records' key: the label is
  `khalm v0.1 test-vector signing key`. It is the conformance record's
  key (record format §9), and `ts-basic` trusts it for
  `did:web:factory-operator.ph` at `software`. In `pack-signature.json` it
  also signs one pack, to show that an issuer's key never vouches for a pack.
- **Keys P and Q**, `pack-signature.json`'s authority keys: the labels are
  `khalm v0.1 trust-store-vector policy authority key P` and `… key Q`,
  the keys P and Q of the trust-store loader vectors. The signed pack of
  `pack-loader.json` uses the signed pack's key above.

## How the expected values were produced

- **Statuses by hand.** Every rule's status and every case's overall status
  are written by hand in the generator, from the format document. The
  generator checks each declared overall status against §8's aggregation of
  the declared rule statuses.
- **Hashes computed independently of the evaluator.** The generator computes
  every evidence hash and payload hash by §7 and §4, with its own table of
  the pointers each rule type reads, its own context slot, and the record
  format's JCS and SHA-256. It does not go through vmr-policy's evidence or
  signing code. The evidence is computed from the record text as written,
  parsed back.
- **Held to the file.** vmr-policy's vector test holds the evaluator to
  this file, and checks the signed pack's signature under its key. vmr-cli's
  `cross_impl` test target replays the verifiable cases through the `vmr`
  binary, in the engine build and in the verify-only build.
- **Independent replay.** An evaluator written from the format document alone,
  not from this implementation, replayed the 147 cases of 2026-09-15 with no
  disagreement; the cases task 10.12a changed and added have not been
  replayed independently yet.

## Regenerating

The files are written only by their generators, never by hand:

```
cd vmr
VMR_WRITE_VECTORS=1 cargo test -p vmr-policy --test vectors -- --ignored
cargo test -p vmr-policy --test vectors      # cases.json and pack-loader.json, reproducible
VMR_WRITE_VECTORS=1 cargo test -p vmr-cli --test pack_signature_vectors -- --ignored
cargo test -p vmr-cli --test pack_signature_vectors      # pack-signature.json, reproducible
```

- **The generators.**
  - `cases.json` and `pack-loader.json`:
    vmr-policy's generator (the first command above).
  - `pack-signature.json`:
    vmr-cli's generator (the third command above). It lives in
    vmr-cli, where vmr-policy's signature check and vmr-verify's trust decision
    meet: neither crate may depend on the other.
- **By hand, and computed.** Every refusal identifier, signature state and
  exit code is written by hand in its generator. Payload hashes, key ids and
  signatures are computed there with the format crate's JCS, SHA-256 and
  ES256, never through the code under test.
- **Each regeneration gets its own commit.** A regeneration that changes any
  byte belongs in a commit of its own, listing every changed case. A change to
  a reference pack moves its cases' payload hashes and, if a rule changed,
  their results.
- **Line endings.** `.gitattributes` keeps `specs/test-vectors/**` at LF.
