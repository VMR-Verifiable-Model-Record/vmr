# VMR Policy Pack — Format v0.1

**Status:** normative. v0.1 published 2026-09-16 at tag `v0.1.0` of the public
repository; its bytes do not change from here. An editorial correction that
changes no normative rule is published as v0.1.1; anything that changes a
rule, as v0.2. This text is that first editorial correction, v0.1.1: no
normative rule changed. This document states how a policy pack is loaded, what
its authority signs, and how it is evaluated against a Verifiable Model Record
(`record-format-v0.1.md`). The reference implementation is KHALM-VMR's crate
`vmr-policy`; where it and this document disagree, that is a defect to report,
not a choice for the reader.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119
and RFC 8174 when they appear in capitals.

## 1. Scope

A **policy pack** is a JSON document an authority publishes: a regulator, a
standards body, an enterprise or a consortium. **Evaluating** it against a
record answers each of its rules with `pass`, `fail` or `indeterminate`, and
the pack as a whole with one overall status. Two evaluators given the same
pack, the same record, the same evaluation time and the same verification
context (§5) MUST produce the same evaluation, including every
`evidence_hash`, byte for byte.

What is normative where:

| Subject | Where |
|---|---|
| The pack's structure: members, types, patterns, bounds, closed objects | `policy-pack-schema/v0.1.json` |
| What a loader refuses, including what the schema cannot express | §3 |
| What an authority signs, and how a signature is checked | §4 |
| Evaluation: inputs, the verification context, types of members, the seven rule types, evidence | §5–§7 |
| The overall status, and the record's `policy_compliance` section built from an evaluation | §8 |
| Conformance | §9 |

Not defined here:

- **Whether to trust a record.** That is verification (record format §6).
  An evaluator SHOULD evaluate only a verified record: evaluating an
  unverified one evaluates claims nobody has vouched for.
- **Which keys may sign a pack.** That is the checker's trust decision. The
  reference verifier's is stated in `trust-store-format-v0.1.md` §4.2: the
  policy authorities an operator trusts, in a trust store.
- **What a result means to a reader.** A pack is its author's reading of the
  text it cites, and an evaluation reads the record and nothing else, so a
  pass says which claims were made, never that they are true. KHALM-VMR's
  `docs/POLICY_PACKS.md` states that for readers, with the reference packs as
  its examples; it is explanatory, not normative.

## 2. The document

- **Encoding.** UTF-8 JSON, without a byte order mark. The reference loader
  reads at most 1 MiB (1 048 576 bytes).
- **Members.** `version` (`"0.1"`), `pack_id`, `pack_version` (`N.N.N`, each
  part `0` or digits without a leading zero), `jurisdiction`, `description`,
  `disclaimer`, `authority` (`authority_id`, `authority_name`), `rules` (at
  least one), and an optional `signature` (§4).
- **What names a pack's text.** `pack_version` is its author's name for a
  revision, and nothing checks that a changed text has a new one. A pack's
  payload hash (§4), not its version, names its text: two texts under one
  `pack_version` have two payload hashes, so a party that must know which text
  was applied pins the payload hash.
- **Every rule** carries `type` (one of the seven of §6), `rule_id`,
  `description`, `severity` (`mandatory`, `recommended` or `informational`)
  and `reference` (the clause it encodes), plus the parameters of its type
  (§6).
- **Parameter defaults.** An absent boolean parameter is `false`; an absent
  `minimum_chain_length` is `0`; an absent `withheld` is `fail` (§6.4) and
  an absent `compare` is `model_hash` (§6.5). A pack that states a default
  explicitly evaluates the same and hashes differently: the pack's text
  changed, so its payload hash did (§4).
- **Parameter bounds.**
  - `minimum_chain_length` is an integer from 0 to 2^53 − 1, written with
    one spelling: digits only, no `-0`, fraction or exponent. 2^53 − 1 is the
    largest integer the JCS form a pack is signed over (§4) writes exactly.
  - Each entry of `allowed_jurisdictions` is two upper-case ASCII letters,
    the form a record's `data_residency` takes.
  - `withheld` is one of `fail` and `indeterminate`; `compare` is one of
    `model_hash` and `learned_state_hash`. Anything else is refused by the
    schema, as an unknown member is.
- **Strictness.** Every object is closed: an unknown member is refused at
  every level, as in a record. An optional member is omitted, never `null`.

## 3. Loading

A loader MUST refuse a pack in each case below, and a refused pack MUST NOT be
evaluated in part.

- **Identifiers.** Each refusal has a stable identifier, which a loader SHOULD
  report and the loader vectors name (`test-vectors/policy/pack-loader.json`,
  §9).
- **The schema column** says whether `policy-pack-schema/v0.1.json` can
  express the rule. Where it cannot, this table is the only place the rule is
  published.
- **The reference error** is given for orientation. Whichever error carries a
  refusal, `vmr_policy::Error::refusal_id` names its identifier.
- **Numbers.** Refusals 4 and 5 go by how `minimum_chain_length` is written,
  never by the value a parser makes of it. `1e400` and `-1e400` are refusal
  4, and an integer written with 400 digits is refusal 5, although no double
  holds either: a text that holds one is JSON, and breaks no other rule.
- **Wording is not part of v0.1.** Neither is the order in which a loader
  reports several refusals, with two exceptions:
  1. **Refusal 1 is decided first,** on the document's size.
  2. **Refusal 12 is decided next,** before any other, on the document's
     bytes, in one pass from the first byte to the last. Outside a string,
     `[` and `{` raise the depth by one, `]` and `}` lower it by one, never
     below 0, and `"` opens a string. Inside a string, `\` skips the byte
     after it, and `"` closes the string. A document whose depth reaches 128
     is refused as 12, whatever it holds before or after that point: a byte
     order mark, bytes that are not UTF-8, or any other syntax error.

  Every other refusal follows, in no fixed order. For a document that is
  JSON, the count is the depth of its arrays and objects, the outermost
  counting as the first. Such a document can reach 128 levels only in a
  member the format lacks, or in one of the wrong type, so it breaks refusal
  2 as well.

| # | Identifier | Refused when | In the schema | Reference error (`vmr_policy::Error`) |
|---|---|---|---|---|
| 1 | `policy_pack.size` | The document is larger than the loader's bound (1 MiB in the reference loader) | no | `PackTooLarge` |
| 2 | `policy_pack.structure` | It is not JSON; or a member is unknown, missing, `null` or of the wrong JSON type, at any level (an object written as a JSON array, of its values in any order or of anything else, included: the pack itself, its `authority`, its `signature`, a rule); or a rule's `type` is not one of the seven; or a string anywhere, member name or value, holds a `\u` escape of an unpaired surrogate, which RFC 8259 admits but which denotes no Unicode scalar value (as in a record, `record-format-v0.1.md` §2 rule 1) | yes | `PackParse` |
| 3 | `policy_pack.duplicate_member` | A member name appears twice in one object, names compared after their escapes are decoded | no: the schema sees a parsed object | `PackParse` |
| 4 | `policy_pack.integer_spelling` | `minimum_chain_length` is negative, or is not written as a plain integer (`-0`, `1.0`, `1e0`, `1e400`), whatever the size of the number it writes | in part: `minimum` refuses a negative value, but the schema's `integer` admits `1.0` | `PackParse` |
| 5 | `policy_pack.integer_range` | `minimum_chain_length` is written as a plain integer above 2^53 − 1, however many digits it has | yes (`maximum`) | `PackSchema`, naming the member's JSON pointer; `PackParse` for an integer above 2^64 − 1, which the reference parser does not read as an integer, and for one beyond a double's range, which it refuses as it reads the document |
| 6 | `policy_pack.version` | `version` is not `"0.1"` | yes (`const`) | `UnsupportedVersion` |
| 7 | `policy_pack.value` | A value rule of the schema is broken: an empty string where the schema sets `minLength`, a `pack_version` that is not `N.N.N` or has a leading zero, an empty `allowed_jurisdictions` or `restricted_list`, a `severity`, a `minimum_level` or a `document` outside its enum, a malformed `signature` member | yes | `PackSchema`, naming the member's JSON pointer; `PackParse` for a `severity` outside its enum |
| 8 | `policy_pack.jurisdiction` | An `allowed_jurisdictions` entry is not two upper-case ASCII letters | yes (`pattern`) | `PackSchema`, naming the member's JSON pointer |
| 9 | `policy_pack.empty_rules` | `rules` is empty | yes (`minItems`) | `PackEmpty` |
| 10 | `policy_pack.duplicate_rule_id` | Two rules share a `rule_id` | no | `DuplicateRuleId` |
| 11 | `policy_pack.no_requirement` | A rule states no requirement a record can fail: an `export_control` rule with neither `require_air_gapped` nor `require_egress_denied`; an `audit_integrity` rule with `minimum_chain_length` 0 and none of `require_tamper_evident`, `require_input_committed` and `require_ordered_record` (so one whose only setting is `require_verified_lineage`, which never fails, is refused too); an `execution_integrity` rule with none of its four requirements; an `attestation_level` rule whose `minimum_level` is `self`, which every record that declares a level meets | no | `RuleWithoutRequirement` |
| 12 | `policy_pack.nesting` | Its depth, counted over its bytes as the list above says, reaches 128: for a document that is JSON, it nests arrays and objects more than 127 levels deep, the outermost counting as the first | no | `PackParse` |

## 4. What an authority signs

- **The signed payload** is the document as received, parsed as JSON, with its
  top-level `signature` member removed, serialized in the JCS form of RFC 8785
  exactly as a record's payload is (record format §3).
- **The payload hash** is `sha256:` followed by the lower-case hex of the
  SHA-256 of the signed payload's UTF-8 bytes. It is defined for every pack
  that loads (§3), signed or not, and names the pack's content independently
  of its layout. A pack text §3 refuses has no payload hash. A signed pack and
  the same pack without its `signature` have the same payload hash.
- **The `signature` section** holds `algorithm` (`ES256`), `signature`
  (`base64url:` and the unpadded base64url of the 64-byte `r ‖ s`, low-s:
  record format §4.2), `signed_payload_hash` (the payload hash) and
  `signing_key_id` (the RFC 7638 thumbprint URN of the signing key: record
  format §5).
- **What is signed differs from a record.** A pack has no COSE envelope:
  the ES256 signature is over the signed payload's bytes themselves. A
  signature over any other bytes does not verify. That includes the document
  with its `signature` member, a re-serialisation of a typed model of the
  pack, and a COSE `Sig_structure`.
- **Checking a signature under a key** takes these steps in order, each a
  refusal of its own:
  1. the `signature` section is present;
  2. `algorithm` is `ES256`;
  3. `signing_key_id` is the key id of the key it is checked against;
  4. `signed_payload_hash` is the recomputed payload hash;
  5. `signature` decodes to 64 bytes;
  6. the signature verifies under the key, with a low `s`.

  A checker SHOULD report a failure of step 1 as `pack_signature.unsigned`,
  of step 4 as `pack_signature.payload_hash`, and of any other step as
  `pack_signature.invalid`. Steps 2 and 5 cannot fail for a pack that loaded,
  since §3 refusal 7 covers both.

  Which key an authority may use is the checker's trust decision, not part of
  this format. A loader does not check a signature. The reference verifier's
  decision is `trust-store-format-v0.1.md` §4.2: the key is looked up by
  `signing_key_id` among the policy authorities an operator trusts, and it
  must be trusted for the pack's `authority.authority_id`, unrevoked, and
  valid at the evaluation time, since a pack carries no signed time.
- **A section that does not match its pack.** Step 4 needs no key. A pack
  whose `signed_payload_hash` is not its recomputed payload hash was changed
  after it was signed, or carries another pack's section. Whoever holds such
  a pack, with or without a key for the authority, MUST NOT report it as
  signed by the key its section names.
- **The stores first.** A verifier that checks a pack's signature against the
  keys it trusts MUST load and check its stores before the pack's signature,
  in the order `trust-store-format-v0.1.md` §4.2 gives: the trust store, then
  an authority store when one is given, then the pack (§3), then the
  signature. The first refusal stops it. The pack-signature vector
  `order-authority-store-before-payload-hash` pins the authority store before
  the signature.

**Identifiers.** A checker SHOULD report a refused signature, or a refused
authority store, with one of the identifiers below. `trust-store-format-v0.1.md`
§4.2 lists the same identifiers, with the same meanings, in the same order:
the order in which the reference verifier decides them, by the steps of that
section. A pack the loader refuses is named by §3, between the authority store
and step 1.

| Step (trust-store format §4.2) | Identifier | Refused when |
|---|---|---|
| — | `authority_store.issuers` | a file given as an authority store lists issuers |
| — | `authority_store.issuer_key` | a file given as an authority store holds a key the trust store lists under `issuers` |
| 1 | `pack_signature.unsigned` | the pack is unsigned, and the checker refuses every unsigned pack it checks (the reference CLI reports the state `unsigned` instead) |
| 1 | `pack_signature.unsigned_refused` | a signature is required, and the pack is unsigned |
| 2 | `pack_signature.payload_hash` | the section's `signed_payload_hash` is not the pack's payload hash |
| 3 | `pack_signature.not_checked_refused` | a signature is required, and no authority key has the pack's key id |
| 4 | `pack_signature.invalid` | the signature does not verify under the trusted key |
| 5 | `pack_signature.other_authority` | the key is trusted for another authority than the pack names |
| 6 | `pack_signature.revoked` | the key is revoked |
| 7 | `pack_signature.outside_validity` | the evaluation time is outside the key's window |

## 5. Evaluating a pack

**Inputs.**

1. A loaded pack.
2. The record as a JSON value: its JSON document (record format §2),
   whichever form it was received in. Only the members named in §6 are read.
   Record *text* is read into a value by record format §2 rule 1: a text
   with a duplicate member name, or with a `\u` escape of an unpaired
   surrogate, is not a record document, and it is not evaluated. Neither is
   a text that nests arrays and objects more than 127 levels deep, the
   outermost counting as the first: an evaluator MUST refuse it, as the
   reference parser does (a pack text likewise, §3 refusal 12). An evaluator
   MUST likewise refuse a verification context whose predecessor text
   (input 4, §9) nests more than 127 levels, and the refusal refuses the
   whole evaluation, not that predecessor alone. (Informative, KHALM-VMR's
   behaviour: `vmr-policy` is given each predecessor already
   parsed, `VerifiedPredecessor::record`; the vectors' replay reads a
   predecessor's text with the record text's parser and stops on such a
   case; and through
   a verifier such a text is never a verified predecessor: it fails
   verification, record format §2 rule 13, and the record after it is
   not evaluated.) A verified record nests at most four levels. The
   128-level rule of "Nesting" below applies to a record value an evaluator
   is given already parsed, or built in code.
3. The evaluation time, in the record's UTC-seconds timestamp profile. It is
   an input: an evaluator MUST NOT read a clock.
4. Optionally, a **verification context**: what a verifier established about
   the record's lineage (record format §6.5).
   - **The lineage outcome:** `initial`, `complete`, `partial` or
     `not_checked`. A broken lineage fails verification and has no outcome
     here. These are the only lineage outcomes: an evaluator MUST treat only
     these four as a verification context's outcome, and MUST refuse a
     context carrying any other value before evaluation, evaluating neither
     in that context nor without one. (Informative, KHALM-VMR's
     behaviour: `vmr-policy` cannot be given such a context, as
     `LineageOutcome` has exactly the four words and `evaluate_in_context`
     takes only an `EvaluationContext`; the vectors' replay stops on a case
     that gives one.)
   - **The verified predecessors,** immediate predecessor first: for each
     predecessor whose link verified, its signed payload hash as the verifier
     recomputed it (record format §3, §6.5), and its record as a JSON
     value.

   **An evaluator takes a context as given.** Only a context a verifier
   produced, from the predecessors it verified, carries meaning; an
   evaluator does not verify it again. A context that contradicts its own
   predecessors (`complete` or `partial` with no predecessor, `not_checked`
   with some), which no verifier produces, is evaluated as written:
   `require_verified_lineage` passes on `complete` whatever the predecessors
   (§6.4 step 6), and `require_state_kept` is `indeterminate` with no
   predecessor (§6.5 step 4).

   **A context applies to a record** when its outcome is not `initial` and
   the record's `/lineage/lineage_chain_length` is a count (below) of 2 or
   more. A context that does not apply is neither read nor hashed: the
   evaluation is the one without context. On every verified record a chain
   of 1 is exactly an initial record (record format §6.5,
   `lineage.consistency`), so a verifier's context applies exactly to the
   records with predecessors, and an initial record gets the same
   evaluation from an issuer, from an evaluator without context and from a
   verifier.

**Output.** An evaluation holds:

- the pack's `pack_id` and `pack_version`;
- `evaluated_at`, the evaluation time;
- one result per rule, in the pack's order: its `rule_id`, `rule_type` (the
  rule's `type`), `severity`, `reference`, `status` and `evidence_hash` (§7),
  with a reason whose wording is each implementation's own;
- the `indeterminate` list: the ids of the rules whose status is
  `indeterminate`, in the pack's order;
- the overall status (§8).

**Independence.** A rule's status depends only on that rule, the record and
a context that applies; its evidence hash only on the rule's type, the
record and a context that applies. Neither depends on:

- the evaluation time;
- the other rules or their order;
- how the record was written down (member order, whitespace, escapes).

**Terms used in §6.**

- **The value at a pointer.** The JSON value an RFC 6901 pointer resolves to
  in the record. The pointer is *absent* when it resolves to nothing,
  including when a member on its path is missing or is not an object.
- **Nesting.** A value at a read that nests arrays and objects more than 128
  levels deep (the value itself is the first level when it is an array or an
  object) is not read. A rule any of whose reads holds such a value is
  `indeterminate`, whatever its parameters, and that read contributes `null`
  to the evidence (§7). No verified record holds such a value: in the
  record schema every member §6 reads is at most two levels deep. The rule
  fixes the answer for a value that is not a verified record's. It covers
  the record's own reads. A verified predecessor's `model_hash`
  nested more than 128 levels is not read either: the context slot holds
  `null` (§7), and §6.5 step 4 is `indeterminate`. It does not make a rule's
  other settings indeterminate. Parsed record text never holds such a
  value, since text nested past 127 levels is refused (input 2): the rule is
  for a value given to the evaluator already parsed, or built in code.
- **A declared string.** The value is a JSON string and is not empty.
  Anything else counts as not declared: absent, `null`, the empty string, or
  any other JSON type.
- **A string.** The value is a JSON string, the empty string included. This
  term is used only for `training_software`, `software_hash` and
  `tee_measurement`, the required members in which an issuer signs `""` to
  say "none" (record format §2 rules 3 and 9).
- **A boolean, an array.** The value is of that JSON type; anything else is
  not declared.
- **A count.** The value is a JSON integer from 0 to 2^53 − 1, written as an
  integer: no fraction, exponent or minus sign, so `1.0`, `1e0` and `-0` are
  not counts. An integer above 2^53 − 1 is not a count either: RFC 8785 writes
  it as the nearest double, so two different values would share one evidence
  hash (§7) and compare differently. Anything else is not declared, including
  a string of digits.

  Whether a value is a count therefore depends on how its number is written,
  not only on the number: `1.0` and `-0` are not counts although they equal
  `1` and `0`. An implementation whose JSON parser reads them as the same
  number, as ECMAScript's `JSON.parse` does, needs a tokenizer that keeps the
  spelling. The vectors' `audit-integrity-chain-length-float-spelling` and
  `-0` cases pin it.
- **A hash.** A string made of `sha256:`, in lower case, and exactly 64
  ASCII hexadecimal digits (`0`–`9`, `a`–`f`, `A`–`F`), each in either case,
  and nothing else, white space included; one hash may mix cases. Two hashes
  are equal when they denote the same 32 bytes. The record schema admits
  only lower-case digits, so a verified record never shows the difference.
- **A timestamp.** A declared string in the record's UTC-seconds profile
  (record format §2 rule 7), a valid calendar date included. Timestamps
  compare as instants.
- **The root of the empty tree.** The hash of the SHA-256 of the single byte
  `0x02` (record format §8).
- **Equality of strings** is exact and case-sensitive, except that hashes
  compare as above.
- **Order of steps.** A rule's steps run in the order written. The first step
  that yields a status ends the rule, and a rule that reaches its last step
  passes.

**What each status means.**

- **`fail`** means the record declares something checkable that
  contradicts the rule, including a signed empty string in a member the rule
  requires (§6.5), and a record object without the optional documentation
  member a `documentation_declared` rule names (§6.7).
- **`indeterminate`** means a member the rule needs is not declared, or the
  verification context a step needs is missing or does not reach far enough.
  It is never `fail`: a record that did not say has not said the wrong
  thing. Missing context is never `pass` either. The one member whose
  absence does say something is an optional documentation member (§6.7).

**Members of the wrong JSON type.** A read that is not of the type its step
needs is not declared, so that step yields `indeterminate`, never `fail`.
This is the case whether the member is absent, `null` or of another type,
with one exception: an optional documentation member absent from a record
object fails the `documentation_declared` rule that names it (§6.7), while
the same member present as `null` or of another type is `indeterminate`.
`fail` requires a member of the needed type whose value contradicts the rule,
or that exception:

- a string that is not a hash;
- a count below a minimum, a count of 0 training inputs, or a size of 0;
- a declared boundary that is not `air-gapped`;
- `egress_allowed` that is `true`, or destinations that are not empty;
- times out of order;
- an empty `training_software`, `software_hash` or `tee_measurement` that a
  requirement needs;
- a declared `training_input_disclosure` where a requirement needs the
  training input committed (§6.4);
- a declared country that is not allowed, or is restricted (§6.1, §6.2);
- a `model_hash` that differs from the verified immediate predecessor's;
- a level below the minimum;
- a record object without the documentation member a rule names.

These cases are easy to read otherwise, and all are `indeterminate`:

- an `attestation_level` that is not one of the three levels;
- a learned-state component with no `hash`, or an element that is not an
  object;
- a verified predecessor whose `model_hash` is not declared or is not a
  hash: that is the predecessor's claim, not this record's;
- a `data_residency_countries` array that is empty or holds an element that
  is not a declared string, even beside a declared `data_residency` (§6.1).

What each read must be:

| Read | Needed as |
|---|---|
| `data_residency`, `source_type`, the boundary `type`, `lineage_type`, `training_input_disclosure` | a declared string |
| `data_residency_countries` | an array, or not declared; then not empty, with every element a declared string, or `indeterminate` |
| `egress_allowed` | a boolean |
| `allowed_egress_destinations` | an array |
| `lineage_chain_length`, `training_input_count` | a count |
| `previous_record_hash`, `training_input_merkle_root`, `learned_state_hash`, `model_hash` | a declared string; then a hash, or `fail` |
| `training_software` | a string; then not empty, or `fail` |
| `software_hash`, `tee_measurement` | a string; then not empty, or `fail`; then a hash, or `fail` |
| `training_started_at`, `training_ended_at`, `collection_period/start`, `collection_period/end`, `issued_at` | a timestamp |
| `learned_state_components` | a non-empty array whose every element has a `hash` that is a declared string (then a hash, or `fail`) and a `size_bytes` that is a count (then not 0, or `fail`) |
| `attestation_level` | a declared string that is one of the three levels |
| the verified immediate predecessor's `model_hash` | a declared string that is a hash, or `indeterminate` |
| `data_governance`, `human_oversight`, the one a `documentation_declared` rule names | a member of the record object, or `fail`; then an object whose `documentation_hash` is a declared string, or `indeterminate`; then a hash, or `fail` |

## 6. The rule types

Each rule type reads a fixed list of record members, its **reads**, in the
order given. The same list is what its evidence hash is taken over (§7).
`audit_integrity` and `execution_integrity` may also read the verification
context, and their evidence ends with a **context slot** for it (§7).

### 6.1 `data_residency`

- **Parameters.** `allowed_jurisdictions`: a non-empty list of two-letter
  codes (§2).
- **Reads.**
  1. `/learning_provenance/training_input_provenance/data_residency`
  2. `/learning_provenance/training_input_provenance/data_residency_countries`
- **Steps.**
  1. If read 2 is an array, and it is empty or one of its elements is not a
     declared string: `indeterminate`.
  2. The declared countries are read 1, when it is a declared string, and
     each element of read 2, when it is an array. If there is none:
     `indeterminate`.
  3. If every declared country equals an entry of `allowed_jurisdictions`:
     `pass`. Otherwise: `fail`.
- **Several countries, or none stated.** A record whose training data
  resides in several countries names them in `data_residency_countries`
  (record format §8.5), and each must be allowed. A record that does not
  state its residency names none, and is `indeterminate`: never a false
  pass. A verified record never declares both reads; a record given to the
  evaluator with both has the countries of both read. A read 2 that is not
  an array is not declared (§5).

### 6.2 `source_screening`

- **Parameters.** `restricted_list`: a non-empty list of strings. An entry
  matches only if it is equal to a declared value; an entry that no record
  could declare never matches.
- **Reads.**
  1. `/learning_provenance/training_input_provenance/source_type`
  2. `/learning_provenance/training_input_provenance/data_residency`
  3. `/learning_provenance/training_input_provenance/data_residency_countries`
- **Steps.**
  1. If read 1 is not a declared string: `indeterminate`.
  2. The declared countries are found from reads 2 and 3 as §6.1 steps 1 and
     2 find them from its reads 1 and 2, with the same `indeterminate`
     answers.
  3. If read 1 or a declared country equals an entry of `restricted_list`:
     `fail`. Otherwise: `pass`.
- **Not read.** `source_description` is free text and is never matched.

### 6.3 `export_control`

- **Parameters.** `require_air_gapped` and `require_egress_denied`, booleans;
  at least one is `true` (§3, refusal 11).
- **Reads.**
  1. `/deployment_context/inference_boundary/type`
  2. `/deployment_context/inference_boundary/egress_allowed`
  3. `/deployment_context/inference_boundary/allowed_egress_destinations`
- **Steps.**
  1. If `require_air_gapped`:
     - if read 1 is not a declared string: `indeterminate`;
     - if read 1 is not `air-gapped`: `fail`.
  2. If `require_egress_denied`:
     - if read 2 is not a boolean: `indeterminate`;
     - if read 2 is `true`: `fail`;
     - if read 3 is not an array: `indeterminate`;
     - if read 3 is not empty: `fail`. A denial with an exception list is not
       a denial.
  3. `pass`.
- **No deployment.** A record for a model its issuer does not deploy has no
  `deployment_context` (record format §7.6), so the reads are absent and a
  stated requirement is `indeterminate`.

### 6.4 `audit_integrity`

- **Parameters.** `minimum_chain_length` (§2), the booleans
  `require_tamper_evident`, `require_input_committed`,
  `require_ordered_record` and `require_verified_lineage`, and `withheld`,
  one of `fail` and `indeterminate`, `fail` when it is absent. At least one
  requirement other than `require_verified_lineage` is stated (§3,
  refusal 11).
- **Reads.**
  1. `/lineage/lineage_chain_length`
  2. `/lineage/previous_record_hash`
  3. `/learning_provenance/training_input_merkle_root`
  4. `/learning_provenance/training_input_count`
  5. `/learning_provenance/training_started_at`
  6. `/learning_provenance/training_ended_at`
  7. `/learning_provenance/training_input_provenance/collection_period/start`
  8. `/learning_provenance/training_input_provenance/collection_period/end`
  9. `/issued_at`
  10. `/learning_provenance/training_input_disclosure`

  and the verification context, when it applies (§5): its outcome.
- **Steps.**
  1. If read 1 is not a count: `indeterminate`. This step runs even when
     `minimum_chain_length` is 0.
  2. If read 1 is less than `minimum_chain_length`: `fail`.
  3. If `require_tamper_evident`, the commitment and the link to the
     predecessor are both read, and a status from either ends the rule; when
     both answer, the statuses are reported together, `fail` if either is
     `fail`, and the reasons joined by `"; "`.
     - the commitment: if read 10 is a declared string, the status is
       `withheld`. The record declares that it commits to no training input
       (record format §8.4), and reads 3 and 4 are not read further.
       Otherwise: if read 3 is not a declared string, `indeterminate`; if
       read 3 is not a hash, `fail`;
     - the link: if read 1 is greater than 1:
       - if read 2 is not a declared string: `indeterminate`;
       - if read 2 is not a hash: `fail`.
  4. If `require_input_committed`:
     - if read 10 is a declared string: the status is `withheld`, as in
       step 3;
     - if read 4 is not a count: `indeterminate`;
     - if read 3 is not a declared string: `indeterminate`;
     - if read 3 is not a hash: `fail`;
     - if read 4 is 0: `fail`. The record commits to no training input;
     - if read 3 is the root of the empty tree: `fail`. A root over nothing
       contradicts a count of 1 or more.
  5. If `require_ordered_record`:
     - if any of reads 5 to 9 is not a timestamp: `indeterminate`;
     - if read 6 is before read 5: `fail`. Training cannot end before it
       starts;
     - if read 8 is before read 7: `fail`. A collection period cannot end
       before it starts;
     - if read 6 is after read 9: `fail`. The record records training that
       had not ended when it was issued.
  6. If `require_verified_lineage`:
     - with a context that applies: if its outcome is `partial` or
       `not_checked`, `indeterminate`. A lineage not shown to its origin did
       not say; it did not say the wrong thing;
     - without one: if read 1 is not 1, `indeterminate`.
  7. `pass`.

- **Notes.**
  - A chain of one record has no predecessor, so an absent
    `previous_record_hash` is not held against it (record format §6.5).
  - `require_verified_lineage` passes on an applicable context whose outcome
    is `complete`, and without one on a chain of 1. It reads no
    `lineage_type`, and needs none: on a verified record a chain of 1 is
    exactly an initial record.
  - Step 5's contradictions are ones the reference builder refuses to sign,
    and no verification check covers them, so a record can carry one and
    still verify.
  - A record that commits to no training records (record format §8.4)
    declares `training_input_disclosure`, `not-held` or `not-disclosed`,
    with `training_input_digest` and `training_input_merkle_root` `""` and
    `training_input_count` 0. The disclosure is a signed statement that
    nothing is committed, so the record answers `require_input_committed`
    and `require_tamper_evident` at read 10, with the status `withheld`
    names. `fail` is the default, as a signed `""` fails an environment
    requirement (§6.5). A read 10 that is not a declared string declares
    nothing, and the root and the count decide. The record does not say that
    the model had no training input.
  - **`withheld`** is for a pack whose author wants a commitment when one
    exists and tolerates a withheld one: `indeterminate` reads a declared
    disclosure as "the record did not say", not as a wrong answer, so a
    model whose corpus is not published is not made non-compliant by the
    withholding alone. `fail` is the default and what a pack that requires
    the commitment states, whether it names `withheld` or not; the five
    reference packs of §9 leave it absent and therefore fail. `withheld`
    moves no other step: a chain longer than one record is still held to
    its `previous_record_hash` under `require_tamper_evident`, and a record
    that both withholds and breaks its link reports both reasons.
  - A record that does not state its training times or its collection
    period (record format §2 rule 3) lacks reads 5 to 8, so step 5 makes
    `require_ordered_record` `indeterminate`.

### 6.5 `execution_integrity`

- **Parameters.** `require_learned_state_components`,
  `require_environment_pinned`, `require_tee` and `require_state_kept`,
  booleans; at least one is `true` (§3, refusal 11). And `compare`, one of
  `model_hash` and `learned_state_hash`, `model_hash` when it is absent:
  the member step 4 compares. It is read only when `require_state_kept` is
  `true`.
- **Reads.**
  1. `/model_identity/learned_state_hash`
  2. `/model_identity/learned_state_components`
  3. `/learning_provenance/training_environment/training_software`
  4. `/learning_provenance/training_environment/software_hash`
  5. `/learning_provenance/training_environment/tee_measurement`
  6. `/lineage/lineage_type`
  7. `/model_identity/model_hash`

  and the verification context, when it applies (§5): the verified immediate
  predecessor's `/model_identity/model_hash`.
- **Steps.**
  1. If `require_learned_state_components`:
     - if read 1 is not a declared string: `indeterminate`;
     - if read 1 is not a hash: `fail`;
     - if read 2 is not an array, or is an empty array: `indeterminate`;
     - then, for each element of read 2 in order:
       - if its `hash` member is not a declared string: `indeterminate`;
       - if its `hash` is not a hash: `fail`;
       - if its `size_bytes` member is not a count: `indeterminate`;
       - if its `size_bytes` is 0: `fail`.

       An element that is not an object has no members, so it is
       `indeterminate`.
  2. If `require_environment_pinned`:
     - if read 3 is not a string: `indeterminate`;
     - if read 3 is empty: `fail`;
     - if read 4 is not a string: `indeterminate`;
     - if read 4 is empty: `fail`;
     - if read 4 is not a hash: `fail`.

     A non-empty `training_software` may be any string.
  3. If `require_tee`:
     - if read 5 is not a string: `indeterminate`;
     - if read 5 is empty: `fail`;
     - if read 5 is not a hash: `fail`.
  4. If `require_state_kept`, over the **compared read**: read 7 when
     `compare` is `model_hash`, read 1 when it is `learned_state_hash`.
     - if read 6 is not a declared string: `indeterminate`;
     - if read 6 is neither `deployment` nor `policy-change`, this step ends
       without a status. The other lineage types may change the model;
     - if the compared read is not a declared string: `indeterminate`;
     - if it is not a hash: `fail`;
     - if no context applies, or it has no verified predecessor:
       `indeterminate`;
     - if the verified immediate predecessor's value at the same member is
       not a declared string that is a hash: `indeterminate`;
     - if the two are not equal: `fail`.
  5. `pass`.

- **The empty string.** `software_hash` and `tee_measurement` are required
  members whose value is a hash or the empty string (record format §2
  rule 9), and `training_software` is a required string. The empty string is
  what an issuer signs to say "none": a requirement for such a member fails
  on it. A record emitted without a TEE therefore fails `require_tee`. A
  member that is absent, `null` or of another JSON type still said nothing,
  and is `indeterminate`.
- **Any model.** `training_software` names the training software as the
  issuer names it, whatever it is (record format §8.5). In a record of the
  general description the components are the model's issuer-named byte
  strings, normally its files, and `learned_state_hash` is their named-set
  digest (record format §7.3). Step 1 reads them as it reads the engine
  profile's. A component of 0 bytes, such as an empty file, fails
  `require_learned_state_components`. Step 4 compares `model_hash`, the
  model's identity, by default: `learned_state_hash` follows each issuer's
  choice of components (record format §7.3), so a deployment record that
  lists other components of the same model keeps it. In the engine profile
  the two are equal (record format §7.4).
- **`compare`** (QA QR-05, the owner, 2026-09-16). `model_hash` is a
  declared string that only a holder of the model's files can check;
  `learned_state_hash` is the components' named-set digest, which a holder
  of the components recomputes, and which a verifier has already checked
  against them at `format.consistency` (record format §7.3). A pack whose
  reader wants the kept state checked against something it can recompute
  states `compare: "learned_state_hash"`; a pack that wants the model's
  identity, whatever components each record lists, leaves it absent. The
  five reference packs of §9 leave it absent. Both members are already
  reads of this rule, so `compare` changes no evidence hash (§7).
- **Keeping the state is policy, not verification.** Record format §6.5
  leaves out of v0.1 any rule that ties a `lineage_type` to what changed
  between two records. `require_state_kept` is that rule, asked by a pack.

### 6.6 `attestation_level`

- **Parameters.** `minimum_level`: `software` or `hardware`. The schema's
  enum admits `self`, and a loader refuses it (§3, refusal 11).
- **Reads.**
  1. `/issuer/attestation_level`
- **Steps.** The levels are ordered `self` < `software` < `hardware`.
  1. If read 1 is not a declared string: `indeterminate`.
  2. If read 1 is not one of the three levels: `indeterminate`.
  3. If read 1 is at least `minimum_level`: `pass`. Otherwise: `fail`.
- **What it reads is a claim.** The level is the issuer's own. What the trust
  store grants the signing key is checked by verification (record format
  §6.2, `trust.attestation`), before any pack is evaluated.

### 6.7 `documentation_declared`

- **Parameters.** `document`: `data_governance` or `human_oversight`, the
  record's two optional documentation members (record format §2
  rule 3). Required.
- **Reads.**
  1. `/data_governance`
  2. `/human_oversight`

  Both, whichever one `document` names: a type's read list is fixed (§7),
  so two rules naming different documents carry one evidence hash. The
  steps look only at *the member*, the one `document` names. §5's nesting
  rule applies first, to both reads: a read nested too deep makes the rule
  `indeterminate`, whatever `document` names.
- **Steps.**
  1. If the record is not a JSON object: `indeterminate`.
  2. If the record object has no member named by `document`: `fail`.
  3. If the member is not an object, or its `documentation_hash` is not a
     declared string: `indeterminate`. No member of the object other than
     `documentation_hash` is read: the closed object is the record
     format's rule (§2 rule 2), which verification checks, not this step.
  4. If that `documentation_hash` is not a hash: `fail`.
  5. `pass`.
- **Why an absent member fails.**
  - **Every other type** answers a member that is not declared with
    `indeterminate` (§5), because only a document that is not a record
    lacks a required member.
  - **These two members are optional:** a record without them is well
    formed, and absence is its only signed way to say that it pins no such
    document, as a signed `""` says "none" in a required member (§6.5).
  - **`indeterminate` would give a rule that no record can fail.**
  - **A member present as `null`** is of the wrong type, not absent: step 3
    makes it `indeterminate`. It hashes as an absent member does (§7): the
    same evidence with another status.
  - **A `documentation_hash` that is `""`** is a malformed member, not the
    signed "none": for these two members only absence says "none" (record
    format §2 rule 3). Step 3 makes it `indeterminate`.
- **What a pass shows.** It shows which document the issuer relied on, by
  its hash. It does not show that the document exists, that anyone can
  obtain it, what it says, or that it meets a requirement: nothing reads the
  document.

## 7. Evidence

Every result carries an `evidence_hash`, so a third party can check what the
rule looked at.

- **The evidence value.**
  - When a rule type has one read and no context slot, it is the value at
    that pointer.
  - Otherwise it is the JSON array of the values of its reads, in the order
    §6 lists them, with exactly one element per read, followed for
    `audit_integrity` and `execution_integrity` by the context slot.
  - A pointer that is absent contributes `null`. It is not left out of the
    array, and nothing else stands in for it.
  - A member present with the value `null` contributes `null` too, so it
    hashes as an absent member. A verified record never holds a `null`
    (record format §2).
  - A value nested too deep to read (§5) contributes `null`.

  The value is taken as it stands, whatever its type: the terms of §5 play no
  part here. In particular a number is written as JCS writes it, whether or
  not it is a count: `9007199254740993` is written `9007199254740992`, and
  `1e21` is written `1e+21`.
- **The context slot.** It is `null` when no verification context applies to
  the record (§5), whatever context was given. When one applies:
  - for `audit_integrity`, it is the array of the outcome word followed by
    each verified predecessor's signed payload hash, immediate predecessor
    first: `["not_checked"]`, or `["complete","sha256:…"]`;
  - for `execution_integrity`, it is the value at
    `/model_identity/model_hash` in the verified immediate
    predecessor, taken as it stands, or `null` when there is no verified
    predecessor, the pointer is absent there, or its value nests more than
    128 levels (§5).
- **The reads are the whole list, whatever the rule's parameters.** An
  `execution_integrity` rule that requires only a TEE still hashes all seven
  reads and the slot, including members its steps never look at. With a
  verification context, an `execution_integrity` rule's evidence also
  depends on `/lineage/lineage_chain_length`, which is not among its reads:
  that member decides whether the context applies (§5), and so whether the
  slot is filled.
- **The evidence hash** is `sha256:` followed by the lower-case hex of the
  SHA-256 of the UTF-8 bytes of the evidence value in its JCS form (RFC 8785;
  record format §3).
- **What it depends on.** Only the record, the rule's type, and a context
  that applies. Neither the rule's parameters, nor its severity, nor its
  status, nor the evaluation time enters it, so two rules of the same type
  evaluated against one record in one context carry the same evidence hash.
  Because JCS is canonical, the hash does not depend on how the record was
  written down.
- **Readings that are not this format.** Each of these gives another hash
  and does not conform:
  - hashing only the members a rule's steps looked at;
  - leaving an absent member out of the array;
  - hashing an object that maps pointers to the values of the members
    present;
  - filling the context slot for a context that does not apply, for example
    `["initial"]` for an initial record;
  - serialising the value in a form other than JCS: with member names sorted
    by code point rather than by UTF-16 code unit, non-ASCII characters
    escaped, or numbers written as their source text.
- **The read lists are fixed.** They are part of this format: changing one
  changes every evidence hash a rule of that type has produced.

Examples of evidence values, from the conformance record
(`test-vectors/record/example-v0.1.json`), an initial record:

- an `export_control` rule's value is `["air-gapped",false,[]]`;
- a `documentation_declared` rule's value is `[null,null]`, whichever
  document it names: the record declares neither optional member;
- an `audit_integrity` rule's value is
  `[1,null,"sha256:37d4…",16,"2026-09-01T00:00:00Z","2026-09-08T00:00:00Z","2026-08-01T00:00:00Z","2026-08-31T00:00:00Z","2026-09-10T00:00:00Z",null,null]`.
  The first `null` is the absent `previous_record_hash`, the second the
  absent `training_input_disclosure` of a record that commits its input, and
  the last the context slot, `null` for an initial record in every context.
  Every initial record that commits its input has this shape,
  `[1,null,<root>,<count>,<five times>,null,null]`, with its own values;
- the same rule on the second record of that chain, evaluated with the
  context a verifier gives when the conformance record is supplied as its
  predecessor, has the value
  `[2,"sha256:2eca…","sha256:37d4…",16,…,null,["complete","sha256:2eca…"]]`.

## 8. The overall status, and the record's `policy_compliance`

**The overall status** is computed from the `mandatory` rules only:

1. if any of them is `fail`, the overall status is `fail`;
2. otherwise, if any is `indeterminate`, it is `indeterminate`;
3. otherwise, it is `pass`.

A pack with no mandatory rule is therefore `pass`. `recommended` and
`informational` results are reported and never move the overall status.

**The record's `policy_compliance` section** is built from an evaluation as
follows:

| Member | Value |
|---|---|
| `policy_pack_id` | the pack's `pack_id` |
| `evaluated_at` | the evaluation time |
| `results` | for each rule in the pack's order whose status is `pass` or `fail`: `rule_id`, `status` (`pass` or `fail`), `evidence_hash`. A rule that is `indeterminate` is omitted, because the record's `status` has no word for it; the evaluation keeps it in its `indeterminate` list |
| `overall_status` | `pass` → `compliant`, `fail` → `non-compliant`, `indeterminate` → `indeterminate` |

- **An issuer that embeds the section** evaluates at a time not later than the
  record's `issued_at`. Record format §6.2 check 19,
  `time.policy_not_after_issued`, holds it to that.
- **A verifier that re-evaluates** stamps its own evaluation time and never
  compares that time with `issued_at`.
- **The declaration stays the issuer's.** A verifier reports its own
  evaluation beside the declaration, never in place of it (record format
  §6.6).
- **`deployment_context.policy_pack_id`** is the issuer's own statement, and
  this mapping does not set it.

## 9. Conformance

`test-vectors/policy/cases.json` holds evaluation cases. Each gives a pack's
text, a record's text and an evaluation time. A case whose evaluation reads
a verification context also gives it, as `context`: the lineage outcome, and
for each verified predecessor, immediate predecessor first, its signed
payload hash and its record's text. A case without `context` is evaluated
without one. An evaluator conforms if, for every case, it reproduces:

- the pack's payload hash (§4);
- for every rule in the pack's order: `rule_id`, `rule_type`, `severity`,
  `status` and `evidence_hash`;
- the `indeterminate` list and the overall status;
- the `policy_compliance` section (§8).

The wording of a rule's reason is each implementation's own. The vectors'
README describes the cases, how a verifier replays them (with the
predecessors as its supplied predecessors), and how they are regenerated. No
case holds record text that §5 does not evaluate.

Two more files hold the loading and signature cases:

- **`test-vectors/policy/pack-loader.json`: loading (§3).** A loader conforms
  if it loads each `ok` pack text, whose payload hash (§4) must be the case's,
  and refuses each `error` pack text. When it reports identifiers, it reports
  the case's.
- **`test-vectors/policy/pack-signature.json`: the reference verifier's check
  of a pack's signature** (`trust-store-format-v0.1.md` §4.2). Each case gives
  a pack's text, a trust store, an authority store when there is one, an
  evaluation time and whether a signature is required. A conforming checker
  reproduces the case's signature state, or the identifier of its refusal,
  and the case's `pack_payload_hash`: the payload hash (§4) of a pack that
  loads, or `null` when §3 refuses its text.

## 10. Revision history

v0.1 published 2026-09-16 at tag `v0.1.0`; `version` stayed `"0.1"` through
this revision history.

- **2026-09-13 — first written** (KHALM-TLM Phase 7, task 7.0). This document
  records the loading, signing and evaluation Phase 6 implemented. No
  behaviour changed.
- **2026-09-13 — the points the Phase 6 QA's finding Q6-02 lists, settled the
  same day.** The document now states:
  - the rule for members of the wrong JSON type (§5);
  - that an absent pointer contributes `null` and a `null` member hashes as
    an absent one, with the readings that do not conform (§7);
  - that the evidence covers a rule type's whole read list, whatever the
    rule's parameters (§7);
  - which loader refusals the schema cannot express (§3);
  - that a signed and an unsigned copy of a pack share one payload hash (§4).

  Each point records the reference implementation's behaviour at the time.
  No evidence-hash rule changed.
- **2026-09-13 — the Phase 6 fixes, and the Phase 7 QA's findings Q7-04 and
  Q7-05.** Behaviour changed, and so did evidence hashes.
  - **Evidence-hash changes.**
    - `audit_integrity` reads nine members instead of three
      (`training_input_count`, the four training and collection times and
      `issued_at` are added), and its value ends with the context slot. Its
      value on the conformance passport went from `[1,null,"sha256:37d4…"]`
      to the ten-element value of §7. Every `audit_integrity` evidence hash
      ever produced changes.
    - `execution_integrity` reads six members instead of five
      (`lineage_type` is added), and its value ends with the context slot.
      Every `execution_integrity` evidence hash ever produced changes.
    - The context slot is `null` unless a verification context applies
      (§5), so an initial passport's evidence does not depend on context.
    - A value nested more than 128 levels deep contributes `null` (§5). No
      verified passport holds one, and the reference implementation's JSON
      parser reads no document nested deeper than 127 levels, so no evidence
      hash it produced for a parsed passport changes with this rule.
    - No other rule type's evidence changes.
  - **Behaviour changes.**
    - A signed empty `engine_version`, `software_hash` or `tee_measurement`
      fails a requirement for that member; before, it was `indeterminate`
      (§6.5).
    - New settings: `require_input_committed`, `require_ordered_record` and
      `require_verified_lineage` (§6.4), and `require_state_kept`, whose
      state-keeping lineage types are `deployment` and `policy-change`
      (§6.5). Rules that read context, and missing context, are
      `indeterminate`, never `pass` (§5).
    - A count is at most 2^53 − 1; a larger integer is `indeterminate`
      wherever a count is needed (§5, QA Q7-05 S2). Its evidence is
      unchanged.
    - Loading refuses `minimum_level` `self` and an `audit_integrity` rule
      whose only setting is `require_verified_lineage` (§3, refusal 11). The
      bounds on `minimum_chain_length` and `allowed_jurisdictions` are in the
      schema and in force (§2, §3).
    - A pack whose `signed_payload_hash` does not match its content is not
      reported as signed (§4).
  - **Stated for the first time** (QA Q7-05, S1 to S6): what a count and a
    hash are (§5); a pointer through a member that is not an object is
    absent (§5); how passport text is read, and that a duplicate member name
    or an unpaired surrogate is not evaluated (§5); the result's member is
    named `rule_type`, as the vectors name it (§5, §9); the verification
    context as an input (§5, §9).
  - The policy vectors were regenerated to these rules
    (`test-vectors/policy/README.md`).
- **2026-09-13 — the Phase 7 QA's findings Q7-12 and Q7-13, stated.** No
  behaviour changed and no evidence-hash rule changed; the policy vectors
  gained cases that pin these points (`test-vectors/policy/README.md`). The
  document now states:
  - that the depth rule covers a verified predecessor's `learned_state_hash`
    in the `execution_integrity` context slot, and that beyond the passport's
    own reads it covers only that (§5, §7; S8);
  - that passport or pack text nesting more than 127 levels is refused, as a
    rule of this format and not only of the reference parser, and that the
    128-level rule applies to a value given already parsed, or built in code
    (§3 refusal 12, §5; S9);
  - that the four lineage outcomes are the only ones, and that an evaluator
    takes a verification context as given, even one that contradicts its own
    predecessors (§5; S10);
  - that whether a value is a count depends on how its number is written, as
    for `1.0` and `-0` (§5; S11);
  - that with a verification context an `execution_integrity` rule's
    evidence also depends on `lineage_chain_length`, which is not among its
    reads (§7; S12).
- **2026-09-13 — S13 and S14, stated (the spec pass before Phase 9).** No
  behaviour changed, and no evidence-hash rule or vector changed. The
  document now states, as requirements on an evaluator (the reference's
  behaviour behind each is an informative note):
  - that an evaluator MUST treat only the four lineage outcomes as a
    verification context's outcome, and MUST refuse a context carrying any
    other value before evaluation, evaluating neither in that context nor
    without one (§5 input 4; S13);
  - that an evaluator MUST refuse a verification context whose predecessor
    text nests more than 127 levels, as it refuses such passport text, and
    that the refusal refuses the whole evaluation, not that predecessor
    alone (§5 input 2; S14).
- **2026-09-13 — task 10.11a: the `documentation_declared` rule type**
  (`docs/dev/task-10.11a.md` D11-4, approved by the reviewer the same day).
  Behaviour was added. No existing rule type's behaviour or evidence-hash
  rule changed.
  - **The new type.** §6.7 reads the passport's two optional documentation
    members (passport format §2 rule 3). It is the one type that fails on an
    absent member, for the reason §6.7 gives.
  - **Counts and refusals.** §1, §2 and §3 refusal 2 count seven types, and
    §3 refusal 7 covers a `document` outside its enum.
  - **§5** states the exception three times: in what each status means,
    among the members of the wrong JSON type, and in the table of reads.
  - **§7's examples** give the new type's evidence value on the conformance
    passport.
  - **Vectors.** The EU AI Act reference pack gains two recommended rules of
    the type, and the policy vectors were regenerated
    (`test-vectors/policy/README.md`).
- **2026-09-13 — pack authorities** (`docs/TASKS.md` 6.16;
  `docs/dev/phase6.md` P6-14 and P6-16). No behaviour of this format changed,
  and no evidence hash moved. §1 and §4 now point to the reference
  verifier's trust decision for a pack's signature, which
  `trust-store-format-v0.1.md` §4.2 states.
  - **2026-09-14, the same task: refusal identifiers and loader vectors**
    (`docs/dev/task-6.16.md` A16-20 to A16-24). No behaviour changed: the
    same texts are refused, and no evidence hash moved.
  - **§3** gains an identifier for each of its twelve refusals. It now states
    the one order v0.1 fixes, refusal 12 before the members. Its
    reference-error column notes where the reference loader's error differs
    from the refusal: a `severity` outside its enum, and an integer above
    2^64 − 1.
  - **§4** names the signature check's failures.
  - **§9** points to the two new vector files, `pack-loader.json` and
    `pack-signature.json` (`test-vectors/policy/README.md`).
  - **2026-09-14, the same task: the QA's findings QA16-02 to QA16-04**
    (`QA/QA_REPORT_TASK_6_16.md`; `docs/dev/task-6.16.md` A16-21, A16-25).
    - **§3, refusal 12's order.** Refusal 1 is decided first, then refusal 12
      by a count over the bytes, strings skipped, whatever else the text
      breaks. The reference library already counted so; the reference CLI
      refused a byte order mark and bytes that are not UTF-8 before counting,
      and now counts first.
    - **§3, numbers.** Refusals 4 and 5 go by how `minimum_chain_length` is
      written, whatever its size. **Behaviour changed:** `1e400`, `-1e400`
      and an integer of 400 digits were refusal 2 in the reference loader,
      and are now 4, 4 and 5.
    - **§3, row 2** names a `\u` escape of an unpaired surrogate, which the
      reference loader already refused as refusal 2.
    - **§4** states that the stores are checked before the signature, and
      lists the identifiers of `trust-store-format-v0.1.md` §4.2, with
      `authority_store.issuer_key` and `pack_signature.unsigned`.
    - The pack-loader vectors gained nine cases, and the pack-signature
      vectors four; no existing case changed.
- **2026-09-14 — the task 10.11a QA's finding QT-04, stated**
  (`QA/QA_REPORT_TASK_10_11A.md`). Wording only: no rule, status, evidence
  rule, schema or vector changed. The document now states, where the text
  left each point to another section:
  - that the digits of "A hash" are ASCII, and that nothing else is part of
    it, white space included (§5; S16);
  - that §5's nesting rule applies before §6.7's steps, to both reads
    (§6.7; S15);
  - that §6.7 step 3 reads no member of the object other than
    `documentation_hash` (§6.7; S17);
  - that a `""` `documentation_hash` is a malformed member, not the signed
    "none" (§6.7, "Why an absent member fails"; S18).
- **2026-09-14 — the task 10.11a QA's finding QT-03: cases added.** No
  behaviour, status or evidence-hash rule changed. The policy vectors gained
  eight unverifiable `documentation_declared` cases, after every earlier
  case, and no existing case changed (`test-vectors/policy/README.md`):
  - "A hash" at its edges, each a fail:
    `documentation-declared-hash-prefix-upper-case`, `-hash-63-digits`,
    `-hash-65-digits`, `-hash-trailing-newline`, `-hash-leading-space`,
    `-hash-fullwidth-digits`;
  - mixed-case hex, a pass: `documentation-declared-mixed-case-hash`;
  - a hash beside another member, a pass because step 3 reads no other
    member: `documentation-declared-extra-member`.
- **2026-09-14 — the task 10.11a QA's finding QT-01**
  (`QA/QA_REPORT_TASK_10_11A.md`; `docs/dev/fix-json-object-shape.md`), before
  any pack was published.
  - **Wording only.** §3 refusal 2 now names an object written as a JSON
    array, of its values in any order or of anything else, among the members
    of the wrong JSON type. Its words "of the wrong JSON type, at any level"
    already covered it. No refusal, identifier, order, evaluation or
    evidence-hash rule changed, and no pack that loads changed.
  - **The reference loader's behaviour changed.** It read a pack, its
    `authority` or its `signature` written as the array of its values in the
    order of its own struct's members, and a rule written as its `type`
    followed by its members' values, and loaded the pack. It now refuses each
    as `policy_pack.structure`. The reference CLI did the same after a store
    written that way: see `trust-store-format-v0.1.md` §7.
  - **Vectors.** No existing case changed.
    - The pack-loader vectors gained ten cases, each `policy_pack.structure`:
      `error-structure-pack-as-array`, `error-structure-authority-as-array`,
      `error-structure-signature-as-array`, and
      `error-structure-<type>-rule-as-array` for each of the seven types.
    - The pack-signature vectors gained eight
      (`test-vectors/policy/README.md`).
- **2026-09-14 — the QT-01 fix's QA, finding QJ-06** (`QA/QA_REPORT_QT01.md`),
  before any pack was published. Wording only: no refusal, identifier, order,
  evaluation or evidence-hash rule changed, and no vector case changed.
  - **§4** said the payload hash "is defined for every pack". It is defined
    for a pack that loads; a pack text §3 refuses has none.
  - **§9** now names a pack-signature case's `pack_payload_hash`: the payload
    hash of a pack that loads, or `null` when §3 refuses the pack's text, as
    those vectors have given since the QT-01 fix. The file's `description`
    says the same.
- **2026-09-14 — task 10.11b: passports of any kind of model**
  (`docs/dev/task-10.11b.md`; passport format §7, §8 and §10), before any pack
  was published. Notes only: no rule type, parameter, read list, step,
  refusal, identifier or evidence-hash rule changed.
  - **§6.1 and §6.2:** a passport that names several residency countries, or
    none, has no `data_residency`, and is `indeterminate`.
  - **§6.3:** a passport without `deployment_context` is `indeterminate` for
    a stated requirement.
  - **§6.4:** a passport that commits to no training records is
    `indeterminate` under `require_input_committed` and
    `require_tamper_evident`, because its `""` Merkle root is not a declared
    string (§5). One that does not state its training times or collection
    period is `indeterminate` under `require_ordered_record`.
  - **§6.5:** `engine_version` names any training software, and a general
    passport's components and `learned_state_hash` are read as the engine
    profile's are. A 0-byte component fails
    `require_learned_state_components`.

  The policy vectors gained ten cases, and no existing case changed:
  `general-not-held-input-committed`, `general-not-held-tamper-evident`,
  `general-not-held-ordered-record`, `general-learned-state-components`,
  `general-not-held-environment-pinned`,
  `general-residency-countries-data-residency`,
  `general-residency-countries-source-screening`,
  `general-no-deployment-export-control`, `general-deployment-state-kept` and
  `reference-eu-ai-act-2026-general-passport`.
- **2026-09-15 — the Verifiable Model Record** (tasks 10.11c and 10.11d),
  before any pack was published. Wording only: the format is the VMR policy-pack
  format, a pack is evaluated against a record, and the read
  `/lineage/previous_passport_hash` is `/lineage/previous_record_hash`, the same
  member renamed. No rule type, step, status or refusal changed. An evidence
  value holds the values a rule reads, so an evidence hash moves only where a
  read value moved: in the lineage cases of the policy vectors, whose
  `previous_record_hash` and predecessor hashes are those of records re-signed
  under the new member names (the conformance record's
  `sha256:66583b8b…24825c36` became `sha256:ed510301…969e4106`). §7's example
  shows the new hash. The five reference packs say "record" and name the VMR
  policy-pack format; their rules are unchanged, and their payload hashes move
  with their prose.
- **2026-09-15 — KHALM-VMR** (task 10.11f), before any pack was published.
  Wording only: the reference implementation's software is named KHALM-VMR;
  where it and this document disagree, that is still a defect to report, not
  a choice for the reader. No rule, step, status, refusal or byte changed.
- **2026-09-16 — rules for any model** (task 10.12a), before any pack was
  published.
  - **§6.1, §6.2.** `data_residency` and `source_screening` read
    `data_residency_countries`: every declared country must be allowed, and
    none restricted. A list that is empty or holds a value that is not a
    declared string is `indeterminate`.
  - **§6.4.** Read 10, `training_input_disclosure`: a declared `not-held` or
    `not-disclosed` fails `require_input_committed` and
    `require_tamper_evident`, which it left `indeterminate` before.
  - **§6.5.** Read 3 is `training_software` (the record format's new name for
    `engine_version`), and read 7 `model_hash`. `require_state_kept` compares
    `model_hash` with the verified immediate predecessor's, the model's
    identity, instead of `learned_state_hash`, which follows each issuer's
    choice of components; the context slot holds that `model_hash` (§7).
  - **Evidence.** The read lists of those four types changed, so every
    evidence hash they produce moves (§7).
  - **Vectors.** Regenerated by their generators: 155 policy cases, 8
    appended, and 4 ids renamed `execution-integrity-training-software-*`.
    Four statuses changed, as decided: `general-residency-countries-data-residency`
    passes, and `general-not-held-input-committed`,
    `general-not-held-tamper-evident` and record keeping in
    `reference-eu-ai-act-2026-general-record` fail. No other status changed,
    and every evidence and payload hash recomputes from its case. The five
    reference packs name their author KHALM and state these rules; their
    payload hashes move with their prose.
- **2026-09-16 — two pack parameters** (the owner, after the release QA's
  QR-04 and QR-05), before any pack was published.
  - **§6.4.** `withheld`, `fail` or `indeterminate`, `fail` when absent:
    what a declared `training_input_disclosure` does to
    `require_tamper_evident` and `require_input_committed`. The default is
    the behaviour of the revision above, and the five reference packs leave
    it absent, so no reference evaluation changed.
  - **§6.4 step 3.** A withheld training input no longer ends the step
    before its lineage-linkage check: a record that both withholds and
    breaks its link reports both reasons, at `fail` if either is `fail`.
  - **§6.5.** `compare`, `model_hash` or `learned_state_hash`, `model_hash`
    when absent: the member `require_state_kept` compares in the record and
    in the verified immediate predecessor. Both are already reads of the
    rule, so no evidence hash moved.
  - **Vectors and packs.** No existing case's status changed, and the five
    reference packs' texts and payload hashes are unchanged. The vectors
    gained four cases for the two parameters and 132 general-description
    copies (291 in all), so a pack is
    exercised against a record that is in no registered profile as well as
    against the engine's (record format §7.1).
