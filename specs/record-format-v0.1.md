# Verifiable Model Record (VMR) — Format v0.1

**Status:** normative. v0.1 published 2026-09-16 at tag `v0.1.0` of the public
repository; its bytes do not change from here. An editorial correction that
changes no normative rule is published as v0.1.1; anything that changes a
rule, as v0.2. This text is that first editorial correction, v0.1.1: no
normative rule changed.
**Structure:** [`record-schema/v0.1.json`](record-schema/v0.1.json) (JSON
Schema 2020-12).
**Bytes:** this document.
**Conformance vector:**
[`test-vectors/record/example-v0.1.json`](test-vectors/record/example-v0.1.json).
**Verification vectors:** [`test-vectors/verify/`](test-vectors/verify/) (§6).
**Trust store:** [`trust-store-format-v0.1.md`](trust-store-format-v0.1.md).
**Reference implementation:** KHALM-VMR's crates `vmr-record` (the format,
§2–§5, §7–§8), `vmr-builder` (a record of a model's files) and `vmr-verify`
(the verifier, §6).

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in
RFC 2119 / RFC 8174. A *verifier* is any party checking a record; an
*issuer* produces one.

## 1. Two representations, one signature

A record exists as a **JSON document** (the object the schema describes)
and as a **COSE_Sign1 envelope** (RFC 9052). Both carry the same 64 signature
bytes over the same signed bytes (§4). Converting between them never
re-signs.

## 2. The JSON document

1. UTF-8 JSON (RFC 8259) with member names unique in every object. A
   verifier MUST reject duplicate member names. Strings — member names and
   values — are sequences of Unicode scalar values (RFC 8785 §3.1: string
   data MUST be expressible as Unicode). A `\u` escape that denotes an
   unpaired surrogate (`"\ud800"`, a high surrogate followed by anything
   but a low one, a low surrogate on its own) is valid RFC 8259 syntax, but
   a verifier MUST reject it at check `json.structure`, not `json.syntax`.
   Bytes that are not UTF-8 — surrogates encoded as three UTF-8-style bytes
   (CESU-8) included — fail `json.syntax`. **Noncharacters** (U+FDD0–U+FDEF,
   and U+xFFFE and U+xFFFF of every plane) are scalar values and are
   permitted, written raw or escaped: a verifier MUST NOT reject them. (The
   stricter I-JSON rule, RFC 7493 §2.1, which also excludes noncharacters, is
   not adopted.)
2. **Closed objects.** Every object at every level has exactly the members the
   schema defines (`additionalProperties: false` throughout). A verifier MUST
   reject a record carrying any other member. (Reason: the signed payload is
   re-derived from the parsed document; a member a parser silently dropped
   would sit in the file unsigned.) An object is written as a JSON object and
   only so: its members' values written as a JSON array, in the order of the
   schema's `properties` or in any other, are an array where the schema has an
   object, and a verifier MUST reject them at check `json.structure` (in a
   COSE payload, `cose.payload`), at every level below the record itself. A
   JSON record that is itself written as an array fails earlier, at check
   2, `input.form`, since its first byte that is not whitespace is not `{`
   (§6.2); a COSE payload that is an array fails `cose.payload`, as at every
   other level. (Reason: some parsers read a record from the array of its
   fields' values, and the signed payload re-derived from such a text is the
   one the object form signs, so one signed record would get two verdicts.)
3. **Optional members.** Only these are optional:
   - `lineage.previous_record_id` and `lineage.previous_record_hash`;
   - `data_governance`, `human_oversight` and `deployment_context`;
   - in `model_identity`: `parameter_count` (required in the profile
     `snn-compact-v1`, §7.4), `derived_from` and `statement_references`;
   - in `learning_provenance`: `training_epochs`, `training_started_at`,
     `training_ended_at`, `training_input_format` and
     `training_input_disclosure`;
   - `training_environment.accelerator_software` and
     `training_environment.accelerator`;
   - in `training_input_provenance`: `data_residency`,
     `data_residency_countries` and `collection_period`.

   When absent they are omitted, never `null`. Every other member — the
   `signature` section included — is required. An absent optional member says
   that the issuer does not state it (§7.6).
   `data_governance` and `human_oversight` each hold exactly one member,
   `documentation_hash`: the hash string (rule 5) of the document the issuer
   names as its data governance documentation, or as its human oversight
   documentation. It has no empty form, unlike the optional hashes of rule 9:
   an absent member is how a record says that it pins no such document.
4. **Integers** (`parameter_count`, `size_bytes`, `training_input_count`,
   `training_epochs`, `lineage_chain_length`) are JSON integers in
   `0 ..= 2^53 − 1` (`lineage_chain_length ≥ 1`). An issuer MUST NOT emit and
   a verifier MUST reject a larger value: beyond 2^53 − 1 an IEEE-754 double
   (and therefore JCS, §3) cannot represent the value exactly. An integer is
   written as `0` or as a non-zero digit followed by digits — the spelling
   JCS produces — with no minus sign, no fraction and no exponent. `-0`,
   `12.0`, `0.0`, `1e1`, `1E1` and `0e0` are valid RFC 8259 numbers, but a
   verifier MUST reject each of them (check `json.structure`), even when the
   value is in range. (Reason: anyone can respell a signed record without
   the key; if verifiers disagreed about a respelling, one signed record
   would get two verdicts.)
5. **Hash strings** are `sha256:` followed by 64 lowercase hex digits of a
   SHA-256 digest.
6. **base64url** means RFC 4648 §5 without padding, canonical only: no `=`,
   no characters outside `A–Z a–z 0–9 - _`, and zero trailing bits. A verifier
   MUST reject anything else.
7. **Timestamps** (`issued_at`, `training_started_at`, `training_ended_at`,
   `collection_period.start` / `.end`, `deployed_at`, `evaluated_at`) use the
   UTC-seconds profile of RFC 3339: exactly `YYYY-MM-DDTHH:MM:SSZ` — 20
   characters, a date of the proleptic Gregorian calendar (years 0000–9999;
   each month's real length; 29 February only in leap years), hour 00–23,
   minute and second 00–59 (no leap second 60), upper-case `T` and `Z`, no
   fraction, no offset. Within the profile, lexical order is chronological
   order. The schema carries the profile as a `pattern` (a JSON Schema
   `format` is only an annotation); calendar validity is this rule's.
8. **Identifiers** (`record_id`, `deployment_context.deployment_id`,
   `lineage.previous_record_id`, `lineage.root_record_id`) are canonical
   UUID URNs: `urn:uuid:` followed by lower-case hex in the 8-4-4-4-12 form.
9. **Optional hashes** are a hash string (rule 5) or the empty string. The
   term means only these eight members:
   - `hardware_id`, `tee_measurement` and `software_hash`, in both
     `training_environment` and `deployment_context`: `""` when the value is
     not attested;
   - `training_input_digest` and `training_input_merkle_root`: `""` when the
     record commits to no training records (§8.4).

   `documentation_hash` (rule 3), `derived_from[].model_hash` (§7.5) and
   `statement_references[].digest` (§7.7) are not optional hashes: each is a
   hash string, and `""` is refused there.
10. **DIDs** (`issuer.issuer_id`, `deployment_context.deployed_by`) follow the
    W3C DID Core syntax, ASCII only: `did:`, a method name of `a–z 0–9`, `:`,
    and a method-specific id of `A–Z a–z 0–9 . - _ :` and `%HH` escapes that
    does not end in `:`. (A look-alike Unicode letter in the field people read
    as the issuer's identity is refused, not displayed.)
11. Every schema `pattern` matches the **whole** string (ECMA-262 semantics:
    `$` is the end of the string, not a line end). A verifier MUST reject a
    record that breaks any `const`, `enum`, `pattern`, `format`, `minimum`,
    `maximum`, `minItems`, `maxItems` or `minLength` rule of the schema, and the calendar
    rule 7 (checks `format.schema` and, for the `signature` section, the
    `signature.*` checks of §6).
12. `lineage.previous_record_hash`, when present, is the `signed_payload_hash`
    (§3) of the record's immediate predecessor (§6.5).
13. **Nesting.** A record's arrays and objects nest at most **four** levels
    deep, the outermost object counting as the first: every member has one
    JSON type (rules 2–4), and the deepest objects, such as the elements of
    `model_identity.learned_state_components`, are at level four. A text that
    nests deeper is not a record, however deep it nests. A verifier MUST
    reject it at check `json.structure` (in a COSE payload, `cose.payload`),
    never at `json.syntax`. RFC 8259 sets no depth limit: its §9 lets a
    parser limit the nesting depth but names no limit, so a deep text is
    valid JSON, and this format assigns its failure to `json.structure`. A
    text within the 1 MiB of §6.1 therefore passes `json.syntax` at any depth
    when it is otherwise well formed. A syntax error anywhere in such a text,
    before or after its
    deepest point, still fails `json.syntax`, which reads the whole text
    first. A verifier whose JSON parser stops at some depth MUST therefore
    check syntax without that limit (iteratively, for instance) and report
    the depth at `json.structure`. The rule binds every predecessor (§6.5);
    the COSE envelope's own CBOR has its subset and depth in §4.4. (Reason:
    the first failing check is part of the verification vectors' contract, and
    without this rule one text would fail `json.syntax` under one parser and
    `json.structure` under another.)

## 3. The canonical signed payload

The **signed payload** is the record object **with the `signature` member
removed**, serialized with the JSON Canonicalization Scheme (RFC 8785):

- no whitespace between tokens;
- object members sorted by name, comparing names as sequences of **UTF-16
  code units** (RFC 8785 §3.2.3) — not code points and not UTF-8 bytes. All
  v0.1 member names are ASCII, where the orders coincide; the rule matters
  for any non-ASCII name;
- strings escaped as ECMAScript `JSON.stringify` does: `\"`, `\\`, `\b`,
  `\f`, `\n`, `\r`, `\t`, other code points below U+0020 as `\u00xx`
  (lowercase hex); everything else literal;
- numbers formatted as ECMAScript `Number.prototype.toString` (RFC 8785
  §3.2.2.3). v0.1 records contain only integers within ±(2^53 − 1), which
  print as plain decimal digits;
- the result encoded as UTF-8.

`signature.signed_payload_hash` = `sha256:` + hex(SHA-256(signed payload)).

## 4. The signature

### 4.1 Algorithm and signed bytes

The algorithm is **ES256**: ECDSA over P-256 with SHA-256 (RFC 7518 §3.4,
RFC 9053 §2.1). The bytes signed are the COSE_Sign1 **Sig_structure**
(RFC 9052 §4.4), deterministically encoded CBOR (RFC 8949 §4.2.1):

```
Sig_structure = [ "Signature1", protected, external_aad, payload ]
protected     = bstr .cbor { 1: -7, 4: kid }   ; alg ES256, kid
external_aad  = h''                             ; empty
payload       = bstr containing the signed payload (§3)
kid           = the UTF-8 bytes of signature.signing_key_id
```

With a v0.1 key id (88 bytes, §5) the protected header is the 94 bytes
`a2 01 26 04 58 58` ‖ kid, and the Sig_structure begins
`84 6a 5369676e617475726531 58 5e` ‖ protected ‖ `40` ‖ (payload's bstr head)
‖ payload. ES256 hashes the whole Sig_structure with SHA-256.

### 4.2 Signature value

The signature is the fixed-width **`r ‖ s`: 64 bytes**, each value 32 bytes
big-endian (RFC 9052 §8.1) — **never DER**. It MUST be **low-s**:
`s ≤ n/2`, n the P-256 group order. `(r, s)` and `(r, n − s)` both satisfy the
ECDSA equation; requiring low-s leaves one valid signature per signed object.
An issuer MUST emit low-s (and SHOULD sign deterministically, RFC 6979, as the
reference implementation does). A verifier MUST reject a signature that is not
exactly 64 bytes, has `r` or `s` outside `1 .. n−1`, or is high-s.

### 4.3 The JSON form's `signature` section

| Member | Value |
|---|---|
| `algorithm` | exactly `"ES256"` |
| `signature` | `"base64url:"` + base64url of the 64-byte `r ‖ s` (86 characters) |
| `signed_payload_hash` | §3 |
| `signing_key_id` | the key id (§5); equal to `issuer.key_id` |

The section is excluded from the signed payload. `signing_key_id` is bound by
the signature through the protected header's `kid`; `algorithm` and
`signed_payload_hash` are bound by the verification rules (§6).

### 4.4 The COSE form

An untagged COSE_Sign1 array `[protected, unprotected, payload, signature]`:
`protected` as in §4.1, `unprotected` the empty map, `payload` the signed
payload bytes, `signature` the 64 bytes of §4.2. The payload MUST be
byte-identical to the canonical signed payload of the record it encodes
(no `signature` member, no other encoding of the same content); a verifier
MUST reject any other payload. The JSON form is recovered from the payload
plus: `algorithm` from `alg`, `signature` from the signature bytes,
`signed_payload_hash` from the payload, `signing_key_id` from `kid` (which
MUST be non-empty, valid UTF-8).

**One envelope per record.** The whole envelope is deterministically
encoded CBOR (RFC 8949 §4.2.1: shortest-form argument encodings, definite
lengths), so a record has exactly one COSE form: for a v0.1 key id it
begins `84 58 5e a2 01 26 04 58 58` ‖ kid ‖ `a0` ‖ (payload's bstr head). A
verifier MUST reject every other envelope — a CBOR tag (including COSE_Sign1's
tag 18), any protected parameter besides `alg` and `kid`, any unprotected
parameter, a nil (detached) payload, a non-preferred or indefinite length,
bytes after the array — even when its signature would verify: anything keyed
on envelope bytes (deduplication, caches, audit logs) must see one record
once, and unsigned header data must never ride inside a verified envelope.

**The envelope's CBOR.** A verifier reads the envelope head by head before it
decodes anything, and MUST fail `cose.structure` unless the envelope is exactly
one CBOR data item of this subset, nesting at most **16** levels, with nothing
after it:

- **Items.** Unsigned and negative integers (major types 0 and 1), byte
  strings and text strings (2 and 3; a text string is valid UTF-8), arrays
  and maps (4 and 5), and `null` (`0xf6`). Nothing else, anywhere among the
  envelope's own data items, the unprotected map included: no tag (major
  type 6, bignums among them), no other simple value (`false`, `true`,
  `undefined`, the one-byte simple values), no float and no break. The
  bytes inside the protected and the payload bstrs are not the envelope's
  own data items (below).
- **Arguments.** An integer's value, a string's length and an array's or a
  map's count are given in the item's first byte or in the 1, 2 or 4 bytes
  after it (additional information 0–26), in preferred form or not. An 8-byte
  argument (27), reserved additional information (28–30) and an indefinite
  length (31) are outside the subset.
- **Depth.** The envelope's array is level 1, and an array or map is one
  level deeper than the array or map holding it, as a key or as a value.
  Only arrays and maps count: a tag is outside the subset and fails whatever
  its depth. An array or map at level 17 fails.

Truncated input, and a length or count larger than the bytes that follow,
fail `cose.structure` too. The subset is what a COSE_Sign1 envelope needs: the
canonical envelope is a four-element array of byte strings (their lengths in
1, 2 or 4 bytes) around an empty map, two levels deep; integers, text strings
and `null` are what a header label and a detached payload may be (RFC 9052 §3,
§4.2), so an unprotected parameter within the subset and depth of §4.4 still
fails `cose.unprotected_header`, and a detached payload `cose.payload`.
Within the subset and the depth, a
non-preferred length is `cose.canonical`'s. The bytes inside the protected
header's bstr and the payload's bstr are not read here: whatever the protected
bstr holds is `cose.protected_header`'s, and the payload is a JSON text under
§2 rule 13. (Reason: which check a malformed envelope fails must follow from
this text alone, not from a CBOR decoder's own limits and readings. 16 levels
are comfortably more than the canonical envelope's two, and few enough for any
decoder, recursive or not; 4-byte arguments cover every length in a record
of at most 1 MiB, §6.1.)

## 5. Keys and key ids

`issuer.public_key` is the signing key as a JWK (RFC 7517/7518): `kty` `"EC"`,
`crv` `"P-256"`, and `x`, `y` the 32-byte big-endian affine coordinates in
base64url (43 characters each). Every P-256 key has exactly one such JWK.

The **key id** is the RFC 7638 SHA-256 thumbprint of that JWK in RFC 9278 URN
form:

```
thumbprint input = {"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}   (exactly these
                   bytes: required members only, lexicographic order, no whitespace)
key id           = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"
                   + base64url(SHA-256(thumbprint input))            (43 characters)
```

`issuer.key_id` MUST be the key id of `issuer.public_key`, and
`signature.signing_key_id` MUST equal `issuer.key_id`. An issuer MUST sign
with the key `issuer.public_key` describes.

## 6. Verification

A verifier answers one question: *is this a well-formed v0.1 record,
signed by a key that the verifier's trust store trusts for the issuer the
record names?* It answers it offline — no network, no contact with the
issuer, no key taken from the record.

### 6.1 Inputs

The result is a function of exactly these inputs and nothing else (no
clock, time zone, locale, file system, network or randomness):

- the record bytes, in the JSON (§2) or the COSE (§4.4) form;
- a trust store (`trust-store-format-v0.1.md`), provisioned beforehand, out
  of band;
- an **evaluation time** `T`, a rule-7 timestamp supplied by the caller — a
  verifier never reads a clock to obtain it;
- the record's predecessors, if the caller supplies any, in order,
  immediate predecessor first (§6.5);
- whether the caller requires a complete lineage (§6.5).

The verifier — the code that runs the checks of §6.2, a library — never
reads a clock; a caller such as a command-line tool may supply its own
current time as `T`, and must then say that it did.

A v0.1 record is at most **1 MiB** (1 048 576 bytes) in either form, and a
verifier walks at most **1 024** supplied predecessors.

### 6.2 The checks, in order

A verifier MUST run these checks in this order. The first failure decides
the result and ends the run; later checks are not run (a report lists them as
skipped). The check ids are stable: the verification vectors
(`test-vectors/verify/`) state the expected verdict and, for a failure, the
id of the first failing check.

| # | Check id | Passes when |
|---|---|---|
| 1 | `input.size` | the input is at most 1 MiB |
| 2 | `input.form` | JSON form: the first byte that is not JSON whitespace is `{`. COSE form: the first byte is `0x84` (an untagged 4-element array). Empty input, a byte order mark, a CBOR tag (e.g. `0xD2`, tag 18) or anything else fails |
| 3j | `json.syntax` | UTF-8, RFC 8259 syntax, nothing but whitespace after the top-level value, at any nesting depth (§2 rule 13) |
| 4j | `json.structure` | §2 rules 1–4 and 13: exactly the schema's members at every level — unknown, duplicate, missing (including `signature`) and `null` members fail — with the schema's JSON types (an object written as an array, of its values or of anything else, fails here; the record itself written as an array has already failed check 2); strings of Unicode scalar values (a `\u` escape of an unpaired surrogate fails here; noncharacters pass); integers in `0 ..= 2^53 − 1`, written `0` or a non-zero digit followed by digits (so `-0`, `12.0`, `0.0` and `1e1` fail); a text nesting arrays and objects deeper than four levels fails here, however deep |
| 3c | `cose.structure` | one CBOR data item of the subset of §4.4, nesting at most 16 levels, a COSE_Sign1 array `[bstr, map, bstr / nil, bstr]`, nothing after it. A tag, a simple value other than `null`, a float, an indefinite length, an 8-byte argument, reserved additional information or a text string that is not UTF-8 anywhere among the envelope's own data items, the unprotected map included, fails here. Only these items: the bytes inside the protected and the payload bstrs are not read here (what the protected bstr holds is 4c's, the payload 7c's); what the map holds, within that subset and depth, is 5c's |
| 4c | `cose.protected_header` | the protected bstr holds exactly the deterministic encoding of `{1: -7, 4: kid}` (§4.1); `kid` is non-empty UTF-8. Anything else inside the bstr fails here — content that is not one well-formed CBOR map, a tag, a duplicate label, another parameter, an empty `kid` |
| 5c | `cose.unprotected_header` | the empty map (a map holding anything within the subset and depth of §4.4 fails here, whether or not it is a valid COSE header; anything outside them is 3c's) |
| 6c | `cose.signature_encoding` | 64 bytes `r ‖ s`, `r` and `s` in `1 ..= n−1` (§4.2) |
| 7c | `cose.payload` | present (not nil); a record without its `signature` section under the rules of 3j–4j, nesting included (§2 rule 13); byte-identical to that record's canonical signed payload (§3) |
| 8c | `cose.canonical` | the envelope is byte-identical to the canonical envelope of the record it carries (§4.4) |
| 5 | `format.schema` | every value rule of §2 rule 11 outside the `signature` section, including calendar-valid timestamps (rule 7) |
| 6 | `format.consistency` | the model rules §7.1 selects (§7.3, or the profile of §7.4), then the rules of §7.5, §7.7, §8.2, §8.4 and §8.5 that relate members to each other |
| 7 | `signature.algorithm` | `signature.algorithm` is `ES256` |
| 8 | `signature.encoding` | `signature.signature` is `base64url:` + the canonical base64url (§2 rule 6) of 64 bytes `r ‖ s` with `r`, `s` in `1 ..= n−1` |
| 9 | `signature.low_s` | `s ≤ n/2` (§4.2) |
| 10 | `signature.payload_hash` | `signature.signed_payload_hash` equals the hash of the recomputed signed payload (§3) |
| 11 | `key.binding` | `issuer.public_key` is a P-256 JWK naming a point on the curve (§5); `issuer.key_id` is its key id; `signature.signing_key_id` equals `issuer.key_id` |
| 12 | `trust.key_known` | the trust store has a key whose `key_id` equals `signature.signing_key_id` |
| 13 | `signature.valid` | that trusted key's JWK equals `issuer.public_key`, and the signature over the Sig_structure (§4.1) verifies under the **trusted** key; for the COSE form, a standard COSE_Sign1 verification (RFC 9052 §4.4) of the envelope as received also succeeds under that key |
| 14 | `trust.issuer` | the trusted key's issuer entry has `issuer_id` equal to `issuer.issuer_id` (exact string) |
| 15 | `trust.key_not_revoked` | the trusted key is not revoked |
| 16 | `trust.key_validity` | `valid_from ≤ issued_at`, and `issued_at < valid_until` when the key has one |
| 17 | `trust.attestation` | `issuer.attestation_level` is at most the key's trust-store level (`self` < `software` < `hardware`) |
| 18 | `time.not_future` | `issued_at ≤ T` |
| 19 | `time.policy_not_after_issued` | `policy_compliance.evaluated_at ≤ issued_at` |
| 20 | `lineage.consistency` | the record's own lineage members obey §6.5 |
| 21 | `lineage.chain` | the supplied predecessors verify and link (§6.5); may be *not evaluated* |

A JSON record runs checks 1, 2, 3j, 4j and 5–21 (21 checks); a COSE
record runs 1, 2, 3c–8c and 5–21 (25 checks), where checks 7 and 8 pass by
construction (the COSE decoding already required them).

A record **verifies** (verdict *pass*) when every check passes, except that
`lineage.chain` may be *not evaluated* as §6.5 allows. Every other outcome is
a *fail*, and the first failing check is its reason.

### 6.3 Trust: what a pass proves

The key the signature is verified with comes from the trust store, found by
`signature.signing_key_id` — **never** from the record. Checks 7–11 look at
the record alone and run before the trust lookup; the signature is verified
immediately after it (13), so every later trust judgement (14–17) is about a
document the trusted key really signed.

A pass proves: the record is well-formed and internally consistent, and it
was signed — over exactly these bytes — by the holder of a key that this
trust store trusts for the issuer the record names, within that key's
signing window, with that key not revoked, not claiming more attestation than
the store grants, and not dated after `T`. It does not prove that the
record's claims (data residency, TEE measurements, policy results, …) are
true: they are the issuer's statements, now authenticated as the issuer's.
For `data_governance` and `human_oversight` it proves which document hashes
the issuer pinned. It does not prove that such a document exists, that anyone
can obtain it, what it says, or that it is adequate: a verifier never fetches
or hashes a document. For `statement_references` it proves which other signed
statements the issuer named, each by its format and digest (§7.7). It does
not prove that such a statement exists, that it verifies, or what it says
about the model: a verifier checks each reference's form and never fetches or
reads the statement.

A verifier never sees the model or its training data. A pass shows which
hashes the issuer signed for them. It does not show that the issuer held the
model or the data, or that the model in front of the reader is the one
named. A holder of the model's files can check that by recomputing
`model_hash` (§7.2, §7.3), but only over the issuer's list of files. That
list is carried only when the components are every file, and then
`model_hash` equals `learned_state_hash`; otherwise a mismatch does not show
which file differs, or whether a file was added. A record whose claims fit
the rules it selects verifies even when they are false, and the signature
makes them its issuer's statements.

**Integrity alone is not trust.** Checks 7–11 plus an ES256 verification
against the record's own `issuer.public_key` prove only that the record
is internally consistent and was signed by the holder of *that* key's private
key. They do not prove the record comes from the issuer its `issuer_id`
names: anyone can generate a key, embed it and sign, and such a record
verifies against its own embedded key. A verifier MUST NOT report such a
check as verification.

### 6.4 Time

- `T` is an input (§6.1). Only `time.not_future` uses it: an issuer cannot
  date a record after the moment it is checked. A verifier applies no clock
  skew itself; tolerating issuer clocks up to `s` seconds ahead is expressed
  by passing `T + s`.
- `time.policy_not_after_issued` uses no `T`: it relates two of the
  record's own claims. `policy_compliance` is inside the signed payload
  (§3), so an `evaluated_at` later than `issued_at` would be a result the
  signature over it could not have covered. Equal is allowed. The check says
  nothing about whether the declared results are true (§6.6).
- The key's window bounds what it may **sign**, judged against `issued_at`:
  records outlive their key's expiry, and rotating keys never breaks an old
  lineage link. Revocation is absolute (`trust-store-format-v0.1.md` §4.1).
- Timestamps compare as instants; in the rule-7 profile that is also their
  lexical order.

### 6.5 Lineage

- **The link hash.** `lineage.previous_record_hash` is the predecessor's
  `signed_payload_hash`: the SHA-256 of its canonical signed payload (§3),
  which the verifier **recomputes** from the predecessor — it never reads it
  from the predecessor's `signature` section. The JSON and COSE forms of a
  predecessor give the same hash.
- **`lineage.consistency`** (the record's own members):
  `previous_record_id` and `previous_record_hash` are both present or both
  absent. `lineage_type` `initial` requires both absent,
  `lineage_chain_length` 1 and `root_record_id` equal to `record_id`. Every
  other type requires both present, `lineage_chain_length ≥ 2`,
  `root_record_id` different from `record_id`, and `previous_record_id`
  different from `record_id`.
- **Where predecessors come from.** The caller supplies them, as bytes, in
  order: the immediate predecessor first. A verifier never fetches one and
  keeps no registry. A predecessor is bound by the nesting rules (§2 rule 13,
  §4.4) as the record is: one that breaks them fails its own verification,
  so `lineage.chain` fails.
- **`lineage.chain`.** Walking from the record to its supplied predecessors,
  for every predecessor `P` of a successor `S`: `P` verifies in full on its own
  (same trust store, same `T`, no predecessors of its own, no complete-lineage
  requirement); `S.previous_record_id` is `P.record_id`;
  `S.previous_record_hash` is `P`'s recomputed `signed_payload_hash`; both
  have the same `root_record_id`; `S.lineage_chain_length` is
  `P.lineage_chain_length + 1`; and `P.issued_at ≤ S.issued_at`.
- **Outcomes.** *initial* — the record is `initial` and nothing is supplied:
  `lineage.chain` passes. *complete* — the walk ends at an `initial`
  predecessor: passes. *partial* — every supplied link is good but the walk
  ends at a non-initial predecessor; *not checked* — the record is not
  `initial` and nothing is supplied: in both cases `lineage.chain` is **not
  evaluated** and the record still verifies, unless the caller requires a
  complete lineage, in which case `lineage.chain` fails. *broken* — any rule
  above fails, predecessors are supplied for an `initial` record, more
  predecessors follow an `initial` one, or more than 1 024 are supplied:
  `lineage.chain` fails. When `lineage.consistency` fails, the lineage
  outcome is *broken* as well; the run still ends at that check (§6.2), so
  `lineage.chain` is skipped, not run.
- Not in v0.1: rules that tie a `lineage_type` to what changed between two
  records (e.g. that a `deployment` keeps the `learned_state_hash`).

### 6.6 Policy: declared, not evaluated

`policy_compliance` is the issuer's own declaration. A verifier reports it as
declared and MUST NOT present it as its own evaluation; a record that
declares `non-compliant` still verifies (verification is about authenticity,
the declaration is content). Evaluating a policy pack against a verified
record is a separate result that never changes the verdict. How
`overall_status` aggregates `results` is not defined in v0.1:
the section is the issuer's statement. When an issuer builds it by evaluating
a VMR policy pack, `policy-pack-format-v0.1.md` defines the evaluation,
the `evidence_hash` (§7) and the aggregation and mapping (§8).

## 7. The model (`model_identity`)

### 7.1 Two descriptions, chosen by `model_format`

`model_format` names the format of the model the record describes, and
selects the rules its `model_identity` follows:

- a **registered profile identifier** selects that profile's rules. v0.1
  registers one: `snn-compact-v1`, the learned state of the KHALM engine
  (§7.4);
- **any other value** selects the **general description** (§7.3).

A verifier MUST compare `model_format` with the registered identifiers as
exact strings, with no case folding, trimming or normalisation, and MUST
check the selected rules at `format.consistency` (§6.2). The registered
profiles are part of `record_version` `"0.1"`: a profile registered later
comes with a new `record_version`. An issuer MUST NOT use a registered
identifier for a model that is not in that profile's format. A party that
relies on a profile's guarantees MUST check that `model_format` names that
profile.

**Supporting a profile is not a condition of conformance.** An
implementation that implements no registered profile can still be a
conforming verifier, issuer or policy-evaluator of this version (the
specification's owner, 2026-09-16). Given a record whose `model_format`
names a registered profile it does not implement, such an implementation
MUST report the record as **unsupported** — it cannot check the profile's
rules — and MUST NOT report it as invalid: not checking a rule is not the
same as failing it. It MUST still check every rule of §1 to §6 and §8, which
do not depend on `model_format`. An implementation that does implement a
profile says so where it makes its claim (`specs/conformance/README.md`).

(Reason: the rules follow from one signed value, never from a record's
shape. Editing `model_format` after signing fails the signature, and an
issuer can sign a description that satisfies both rule sets: what its hashes
mean follows only from `model_format`, never from its shape.)

### 7.2 Names, and the named-set digest

A model's files (§7.3), its components (§7.3) and training records (§8.2) are
sets of named byte strings.

- **Names.** A name is one or more segments joined by `/` (U+002F). No
  segment is empty, `.` or `..`, so a name neither starts nor ends with `/`
  and holds no `//`. A file's name is its path relative to the root directory
  of the model (or of the data set), with `/` as the separator on every
  operating system. A tool given one file names it by its own name, with no
  directory; a tool given a folder names every file by its path in that
  folder, even when the folder holds one file. Names are compared exactly, as
  sequences of Unicode scalar values: no case folding and no Unicode
  normalisation. So a tool that names a model's files:
  - on a system whose path separator is `\`, MUST convert that separator to
    `/`; a `\` that is part of a file's name, on a system where it is a name
    character, stays;
  - MUST take each name as the file system stores it, and MUST NOT normalise
    its Unicode form or fold its case;
  - MUST refuse a folder that holds a file whose name is not a sequence of
    Unicode scalar values (bytes that are not UTF-8, an unpaired surrogate in
    an NTFS name).
- **Refusing a name, and refusing a set.** A tool that reports *why* it
  refused a name or a set reports one of these five reasons, spelled exactly:
  `empty` (the name has no characters), `empty-segment` (a segment between
  two `/` is empty, which covers a leading or trailing `/`), `dot-segment` (a
  segment is `.`), `dotdot-segment` (a segment is `..`) and `not-ascending`
  (a set's names do not ascend, repeats included). With `not-ascending` it
  reports `refused_at`, the zero-based index of the first name that does not
  come after the one before it. These are the names the conformance suite
  compares (`specs/conformance/README.md`, the `model_hash` operation); a
  tool that reports no reason is not held to them.
- **Order.** A set is written in ascending order of name, comparing Unicode
  scalar values, which is the order of the names' UTF-8 bytes, and no name
  appears twice. This is not the order §3 gives member names, which compares
  UTF-16 code units: of the one-character names U+FF5E and U+1F600, U+FF5E
  comes first here and U+1F600 first under §3.
- **The member encoding** of a member named `n` with bytes `b` is

  ```
  E(n, b) = u64be(len(UTF-8(n))) ‖ UTF-8(n) ‖ SHA-256(b)
  ```

  eight bytes of the name's byte length, most significant first, then the
  name's UTF-8 bytes, then the 32 bytes of the member's SHA-256.
- **The named-set digest** of members `(n_1, b_1) … (n_k, b_k)`, in the order
  above, is

  ```
  "sha256:" + hex( SHA-256( E(n_1, b_1) ‖ E(n_2, b_2) ‖ … ‖ E(n_k, b_k) ) )
  ```

  Renaming a member changes the digest, and so does moving content from one
  name to another. The digest of no members is
  `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- **Files.** A model's files are the regular files it is distributed as. A
  directory is not an entry, so an empty directory contributes nothing; an
  empty file is an entry. A link is not a regular file: a link is a symbolic
  link, or any other entry the file system resolves to another path (on
  Windows, a directory junction or another name-surrogate reparse point). A
  tool MUST hash a link that resolves to a regular file as that file, under
  the link's own name, and MUST refuse the folder when a link resolves to a
  directory, to nothing, or through a loop. This format excludes no file by
  name: which files a model is distributed as is its issuer's statement,
  which the components show when they list every file (§7.3).
- **One folder, one `model_hash`.** The same model folder gives the same
  `model_hash`, and the same name, hash and size for each file, when it holds
  the same names and the same bytes. The rest of a record is the issuer's: its
  choice of components (§7.3), `parameter_count`, its ids, times and
  signature. `model_hash` follows the names and bytes of the files, so a copy
  that changes them describes another set of files, even when it holds the
  same model:
  - a file system or tool that rewrites names (macOS HFS+ stores names in
    NFD; an archive whose entries use `\` unpacks to different names on
    different systems);
  - a case-insensitive file system, which cannot hold two names that differ
    only in case;
  - files a tool or an operating system adds to a folder (a clone's `.git`, a
    download cache, `desktop.ini`, `.DS_Store`).

  A file's bytes are those its publisher distributes: a checkout that
  converts line endings (for instance `core.autocrlf`) changes them, and a
  checkout that cannot create links writes each link as a small file holding
  its target (Git for Windows' default, `core.symlinks=false`), which is
  another file. A tool SHOULD show the issuer every name it hashes before
  signing.
- **Example.** A model distributed as `config.json`, the two bytes `{}`
  (SHA-256 `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`),
  and `weights.bin`, four zero bytes (SHA-256
  `df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119`), has the
  named-set digest
  `sha256:bcd9ed61d08e582e69d37afb23dbf37c69b14a3e26d1751a7d6ac6f12803c6d3`.
  A model of `weights.bin` alone has
  `sha256:c32b0039edc7ed971446e62f8701b5a835f9c15b3fbac208f318e2626b9650ea`,
  which is not the SHA-256 of the file: a one-file model follows the same rule
  as any other, and its component's `hash` is the file's own SHA-256.

*Informative.* The root digest of an OpenSSF Model Signing (OMS) manifest is
not a named-set digest: it does not hash the names. From an OMS manifest of
the `files` method with `sha256`:
- the names and digests give the named-set digest of the files it lists;
- a converter re-sorts the names by the order above, since OMS's library
  orders them by path parts (`tokenizer/vocab.txt` before `tokenizer.json`,
  which this order puts first);
- OMS leaves out a top-level `.git`, `.gitignore`, `.gitattributes` and
  `.github`, and its signature file, and, unless `allow_symlinks` is set,
  every symbolic link, while a tool that follows this section hashes each
  link to a file and refuses a folder holding any other link;
- other OMS methods and digests do not convert.

`test-vectors/model-hash/` holds named-set digests, refused names and sets,
and records' digests and roots (§9).

### 7.3 The general description

- **`learned_state_components`** lists one or more components of the model:
  each a byte string of the model, named by the issuer (§7.2), with the
  SHA-256 of its bytes (`hash`) and their number (`size_bytes`), in the order
  of §7.2. Components SHOULD be the model's files, named by their paths, and
  SHOULD be all of them when they fit in a record (§6.1): a holder of the
  files can then check each one, and can check `model_hash`, and a
  `derived_from` entry (§7.5) that names this model, because the components
  then list the files `model_hash` covers. An issuer MAY list only the files
  it names as the model's learned state, for instance its weights and not its
  tokenizer.
- **`learned_state_hash`** is the named-set digest (§7.2) of the components,
  each a member named by its `name` whose SHA-256 is its `hash`.
- **`model_hash`** is the named-set digest of every file the model is
  distributed as. When the components are every file, it equals
  `learned_state_hash`.
- **`parameter_count`**, optional, is the issuer's count of the model's
  learned parameters: for a model of tensors, the number of elements of its
  weight tensors, every expert of a mixture included. Absent, the issuer does
  not state it; `0` states a model with no learned parameters.
  **`architecture`** is the issuer's description, for instance
  `transformer`, `decoder-only`, `bfloat16`, or `gradient-boosted-trees`,
  `ensemble`, `float32`. Neither is checked.
- A verifier MUST check, at `format.consistency`, that every component's name
  follows §7.2, that the names ascend with none repeated, and that
  `learned_state_hash` is the named-set digest of the components.
  `model_hash` covers files a record need not carry: only a holder of
  exactly those files, knowing which they are, can check it.
  `learned_state_hash` follows the issuer's choice of components, so two
  issuers describing one model can differ in it; only `model_hash` is the
  model's identity.

### 7.4 The KHALM engine profile, `snn-compact-v1`

- A record in this profile describes **one agent**. `learned_state_hash` is
  the SHA-256 of the exact bytes the engine's `serialize_state(agent)` returns
  for that agent: a 48-byte header followed by that one agent's payload. The
  header is fixed-width and little-endian. This profile reads four of its
  fields; its other bytes are hashed, not read:

  | Offset | Type | Field | Value |
  |---|---|---|---|
  | 12 | u32 | `num_agents` | the engine's population size |
  | 16 | u32 | `input_bits` | the afferent line count |
  | 20 | u32 | `hidden_neurons` | the hidden population |
  | 40 | u64 | `payload_bytes` | the byte count of the agent's payload |

  A multi-agent population gets one record per agent; describing a
  whole population in one record is not defined in v0.1, and the reference
  builder refuses it.
- With `I` = `input_bits`, `H` = `hidden_neurons` from the header, the payload
  splits into three `learned_state_components`, in this order:
  `afferent_H` (bytes `[48, 48+I·H)`), `recurrent_H` (next `H·H` bytes),
  `thresholds` (next `4·H` bytes). Each carries the SHA-256 of its bytes and
  its `size_bytes`; the sizes sum to the header's `payload_bytes`.
- `parameter_count`, required in this profile, = `I·H + H·H + H` (every H
  entry plus one threshold per hidden neuron).
- In this profile `model_hash` equals `learned_state_hash` (there is no
  separate model artifact).
- A verifier MUST check what the record alone can show of these rules
  (check `format.consistency`, §6.2): exactly the three components
  `afferent_H`, `recurrent_H`, `thresholds`, in that order;
  `thresholds.size_bytes` = `4·H` for some `H ≥ 1`;
  `recurrent_H.size_bytes` = `H·H`; `afferent_H.size_bytes` a multiple of `H`
  (that multiple is `I`); `parameter_count` is present (it is optional only
  in the general description, §7.3) and = `I·H + H·H + H`;
  `model_hash` = `learned_state_hash`; and
  `learning_provenance.training_input_format` is absent (§8.2). (That the
  hashes are those of the real state is what the signature vouches for, not
  what a verifier can recompute.)
- **What no verifier can check.** Another model's bytes can be fitted to this
  layout, for instance with one hidden neuron, and pass these rules: a
  verifier never sees the model. Such a record is its issuer's signed false
  statement that the model is KHALM engine state. The reference implementation
  makes a record in this profile only from an engine's own state; another model
  is described in general (§7.3).

### 7.5 Derived models (`derived_from`)

Optional. A model made from one or more other models lists them. Each entry's
`model_hash` is that base model's `model_hash` (§7.3, or its profile's);
`name` is the issuer's label for it, which nothing checks and which may be
`""`; and `relation` is `fine-tune`, `adapter`, `merge`, `quantization`,
`distillation` or `other`. Entries ascend by `model_hash`, none repeated, and
none is the model's own `model_hash`: a model is not made from itself. The
list is what the issuer states it built from; a base model needs no record.
When a base model has one, the record MAY also name it as its predecessor
(§6.5), whoever issued it. A verifier checks, at `format.consistency`, the
entries' order and that no entry is the model's own `model_hash`, and
nothing else about the bases.

### 7.6 Who can truthfully issue what

- **The model.** A record can describe any AI model, from any vendor, whose
  weights its issuer holds. Only a party that holds a model's files (or, in a
  profile, its state) can compute its hashes. For a model reachable only
  through a service, that is the party operating it. Anyone else who signs a
  `model_identity` for it signs what it cannot know.
- **Training.** `learning_provenance` states the training the model went
  through at its issuer's hands, or of which its issuer holds records. For a
  derived model (§7.5) it is the training that derived it, its added data
  included, not its base model's. An issuer that did not train the model and
  holds no record of its training says so (§8.4) and omits what it does not
  know (§2 rule 3).
- **Deployment.** `deployment_context` is stated by the party deploying the
  model. A record for a model its issuer does not deploy omits it.
- **Policy.** `policy_compliance` is the issuer's declaration (§6.6). An issuer
  that evaluated no pack SHOULD declare `overall_status` `indeterminate` with
  no `results`.
- **What a pass shows** about each of these: §6.3.

### 7.7 Other signed statements about the model (`statement_references`)

Optional. `model_identity.statement_references` names other signed statements
about the same model, for instance an OpenSSF Model Signing (OMS) bundle that
signs the model's files. Each entry holds exactly `format` and `digest`:

- **`format`** names the kind of statement, and which of its bytes `digest`
  hashes. It is one or more segments of lower-case ASCII letters, digits and
  `-`, joined by `.`, each segment starting with a letter or a digit (the
  schema's pattern).
  - A value without `.` is a **registered format**. v0.1 registers two,
    `oms-v1` and `vmr-audit-checkpoint-v1`, and a verifier refuses any other
    value without `.`. The registered formats are part of `record_version`
    `"0.1"`: a format registered later comes with a new `record_version`.
  - A value with `.` is the **issuer's own format**. It SHOULD be a
    reverse-DNS name under a domain the issuer controls, and the issuer
    SHOULD pin its definition (for instance in the document of
    `data_governance`). A registered name has no `.`, so an issuer's name
    never collides with a later registration. A value with `.` is never a
    registered format, whatever its segments: `oms-v1.x` and
    `org.openssf.oms-v1` are issuer formats, not `oms-v1`, and neither says
    who defined it.
- **`digest`** is a hash string (§2 rule 5) of the bytes `format` names.
  - **`oms-v1`:** the SHA-256 of the bundle's DSSE envelope payload after
    base64 decoding, which is its in-toto Statement. The entry names the
    statement, not one signature over it: two bundles that sign the same
    payload share one reference.
  - **`vmr-audit-checkpoint-v1`:** the SHA-256 of an audit-log checkpoint's
    signed payload: the checkpoint, a JSON object, with its top-level
    `signature` member removed, in the JCS form of RFC 8785. The checkpoint
    follows the VMR audit-log format. The entry names the state of a log that
    the checkpoint's key signed, for instance the audit log of an enforcer
    that guards the model. It names that state as it was when the issuer
    signed: a successor that repeats `model_identity` repeats the reference,
    which then names an earlier state of the log.

Entries ascend by `digest`, none repeated: one byte string is one statement,
listed once. No entry says where a statement is: a verifier never fetches
(§6.1).

A verifier MUST check, at `format.consistency`, that every `format` without
`.` is registered and that the entries ascend by `digest` with none repeated,
and nothing else: not that a statement exists, verifies, or says anything
about this model (§6.3). Checking a statement against the model description,
for instance an OMS bundle's `files` manifest against `model_hash` (§7.2), is
a separate result, like a policy evaluation (§6.6), and never changes the
verdict. A party or tool that relies on a registered format MUST compare
`format` with it as an exact string, as §7.1 requires of a profile.

## 8. Training input (`learning_provenance`)

### 8.1 What the section states

The training of §7.6. `training_input_count`, `training_input_digest` and
`training_input_merkle_root` commit to its training records (§8.2), unless
§8.4 applies. `training_epochs`, `training_started_at` and `training_ended_at`
are
absent when the issuer does not state them.

### 8.2 Training records, and their format

A training record is one unit of training input as the issuer names it: a
document, a file or a shard. `training_input_format` names how training records
are defined and ordered:

| `training_input_format` | Training records | `training_input_digest` | Leaf data (§8.3) |
|---|---|---|---|
| absent, in the profile `snn-compact-v1` | the frames of a `KHALMTRN` stream | the SHA-256 of the stream | the frame's u32 words, little-endian |
| `khalmtrn-frame-v1` | the same, outside that profile | the same | the same |
| `named-set-v1` | named byte strings (§7.2), in its order | their named-set digest | the training record's member encoding `E(n, b)` (§7.2) |
| any other value | defined by the issuer, who SHOULD pin the definition (for instance in the document of `data_governance`) | the issuer's | the issuer's |

`training_input_count` is the number of training records. Outside the profile
a record that commits training records MUST carry `training_input_format`,
which is not `""`; in the profile it MUST NOT. A model trained on no input commits the
empty set: count 0, the empty root (§8.3), and its format's digest of nothing.
A verifier does not check that a `training_input_count` of 0 goes with the
empty tree's root, or that a count of 1 or more goes with another root, so a
record can carry either contradiction and still verify. A policy rule that
requires committed input fails both (`policy-pack-format-v0.1.md` §6.4, step
4): of the records that commit training records, it fails every one whose
count is 0 and every one whose root is the empty tree's, while a record that
commits none (§8.4) is `indeterminate` under it (§6.4, its note).

A `KHALMTRN` stream is a 32-byte header followed by every frame's u32 words,
all fixed-width and little-endian. The header holds the magic `"KHALMTRN"`
(bytes 0 to 7), the version 1 (a u32 at 8), the frame count (a u32 at 12), the
words per frame (a u32 at 16) and three zero words (bytes 20 to 31).

### 8.3 The Merkle tree

`training_input_merkle_root` is the Merkle root over one leaf per training
record, with the leaf data of §8.2:

```
leaf(d)    = SHA-256(0x00 ‖ d)
node(l, r) = SHA-256(0x01 ‖ l ‖ r)
empty root = SHA-256(0x02)
```

Each level pairs nodes left to right; an odd trailing node is promoted
unchanged to the next level; the last remaining node is the root.

- **Inclusion proofs** (not part of the record; the format for later audit
  use): `(index, leaf_count, siblings)`, where `siblings` holds, bottom-up,
  exactly one 32-byte hash per level at which the leaf's node has a sibling
  (levels where it is promoted contribute none). A verifier MUST take
  `leaf_count` from a trusted source together with the root — for a record,
  `training_input_count` — because the root does not commit to the count; it
  MUST require the proof's `leaf_count` to equal it and `index < leaf_count`,
  derive each level's shape from `(index, leaf_count)`, and consume
  `siblings` exactly. Exactly one proof then verifies per leaf.
- *Informative: streaming.* The root needs no more than one held node per
  level. For each leaf in order, carry it up: while a node is held at the
  carried node's level, replace both by `node(held, carried)` one level
  higher. At the end, take the held nodes from the lowest level up: the carry
  starts as the lowest, and each higher node `h` makes it `node(h, carry)`. The
  last carry is the root, and the empty root when there was no leaf. This is
  the root of the level-by-level construction above, in which an odd trailing
  node is promoted. Neither the digest nor the root needs the training records
  held in memory: a tool's limits are not this format's.

### 8.4 Not disclosed, not held

`training_input_disclosure`, optional, is `not-disclosed` when the issuer
holds the training records and does not commit to them in this record, and
`not-held` when the issuer does not hold them (for instance, it describes a
model another party trained). When it is present, `training_input_digest` and
`training_input_merkle_root` are `""`, `training_input_count` is `0`, and
`training_input_format` is absent. When it is absent, both are hash strings. A
count of `0` beside `""` counts the training records committed, which are
none; it does
not say that the model had no training input. A policy rule that requires
committed input fails such a record, which declares that nothing is
committed (`policy-pack-format-v0.1.md` §6.4). A verifier checks
these relations at `format.consistency`.

### 8.5 Environment and provenance

- `training_software` is the training software and its version as the
  issuer names it (in the profile, the engine's), `""` when not stated.
  `accelerator_software`, optional and not `""`, is the accelerator's
  software and its version as the issuer names it, for instance a GPU
  toolkit's. `accelerator`, optional and not `""`, is the accelerator
  hardware as the issuer names it: vendor, model and count.
- `hardware_id`, `tee_measurement` and `software_hash`, here and in
  `deployment_context`, are each the SHA-256 of a byte string the issuer names:
  a statement of the hardware's identity, the TEE's measurement as its TEE
  family encodes it, or a description of the software (for instance a
  document of versions); `""` when not attested (§2 rule 9).
- `source_type` and `source_description` are strings, `""` when not stated.
- `data_residency`, optional, is one two-letter code (ISO 3166-1 alpha-2) when
  all the training data resides in one country. `data_residency_countries`,
  optional, holds two or more such codes in ascending order, none repeated,
  when it resides in several; `data_residency` is then absent. When both are
  absent the residency is not stated. A verifier checks these relations at
  `format.consistency`.
- `collection_period`, optional, spans all of the data's collection.

## 9. Conformance vector

`test-vectors/record/example-v0.1.json` holds a record, its
`expected.signed_payload` (the exact §3 string) and
`expected.signed_payload_hash`. Its signing key is derived, never generated:
secret scalar = SHA-256(`"khalm v0.1 test-vector signing key"`) —
test-only. An implementation conforms if it reproduces the payload
byte-for-byte, the hash, the key id (§5) of the embedded JWK, and verifies the
signature under §6. See the vector's README for how it was generated.

`test-vectors/record/example-general-v0.1.json` does the same for the
general description (§7.3): a model of four synthetic files, described by a
party that holds them and deploys the model, and that does not hold its
training records (§8.4). It gives each file's text, and it is signed with the
same test-only key. `test-vectors/model-hash/` holds named-set digests (§7.2),
refused names and sets, and the digest and Merkle root of `named-set-v1`
training records (§8.2, §8.3), each with the expected result.

`test-vectors/verify/` holds the verification vectors: records (valid, and
invalid one check at a time), trust stores, evaluation times and predecessor
lists, each with the expected verdict and — for a failure — the id of the
first failing check (§6.2). `test-vectors/trust-store/` holds trust stores
with the loader result each must produce (`trust-store-format-v0.1.md` §3). A
verifier conforms if it reproduces every expected verdict and check id; the
wording of its reasons is its own.

## 10. Revision history

v0.1 published 2026-09-16 at tag `v0.1.0`; `record_version` stayed `"0.1"`
through this revision history.

- **2026-09-10** — initial format (Phase 3).
- **2026-09-11 — pre-publication revision** after the independent Phase 3 QA
  (`QA/QA_REPORT_PHASE3.md`), before any passport was issued:
  - the signature is the raw 64-byte `r ‖ s` in the COSE envelope (RFC 9052
    §8.1) **and** in the JSON `signature` field, which was DER (P3-02);
  - signatures are low-s; high-s is rejected (P3-04);
  - key ids are RFC 7638 thumbprint URNs of `issuer.public_key`, checked by
    the builder and by verification; the vector's key id had been a literal
    placeholder (P3-07);
  - every object is closed; unknown members are rejected (P3-01); a COSE
    payload must be exactly the canonical signed payload;
  - verification checks `algorithm` and `signed_payload_hash` (P3-05);
  - JCS member order is by UTF-16 code units (P3-03; no v0.1 byte changes,
    all names are ASCII);
  - integers are limited to 2^53 − 1 (P3-10);
  - one agent per passport (P3-06); canonical Merkle proofs (P3-08; the root
    construction is unchanged).

  The conformance vector changed accordingly: `signed_payload_hash`
  `sha256:3319afcd02846211bc037722857b64b05f51a1a2d19f42d303d66337e80b9ce0`
  → `sha256:6b3e0cca76512d111657a337739bff952257bcf03853fed397128fed5843578c`
  (only `issuer.key_id` changed inside the payload), plus the new signature
  encoding, key ids and signature value.
- **2026-09-11 — Phase 4 revision** (the verifier; `docs/dev/phase4.md`,
  decisions D1 and D4–D7 approved by the project lead the same day), before
  any passport was issued:
  - string rules tightened (D4): timestamps use the UTC-seconds profile with
    calendar validity (§2 rule 7), identifiers are canonical lower-case UUID
    URNs (rule 8), the six hardware/TEE/software fields are a hash or `""`
    (rule 9), DIDs follow DID Core syntax in ASCII (rule 10); the schema
    carries each as a `pattern` and requires exactly three state components;
    the §7 consistency rules become a verifier check;
  - the JSON form requires its `signature` member, and the optional lineage
    members are never `null` (§2 rule 3 is now enforced by the parser);
  - the COSE form is exactly one envelope per passport (§4.4): tags, extra
    protected parameters, unprotected parameters, detached payloads and any
    non-deterministic encoding are rejected;
  - verification (§6) is the ordered check sequence with stable ids, the
    key comes from a trust store (`trust-store-format-v0.1.md`, new), an
    evaluation time is an explicit input, and lineage is defined (§2 rule
    12, §6.5).

  The conformance vector did **not** change: every value in it already
  satisfies the tightened rules (`signed_payload_hash` stays
  `sha256:6b3e0cca76512d111657a337739bff952257bcf03853fed397128fed5843578c`).
- **2026-09-11 — Phase 4 QA revision** after the independent Phase 4 QA
  (`QA/QA_REPORT_PHASE4.md`), before any passport was issued. Each item
  settles a point where a verifier written from this document could reach a
  different verdict or first failing check than the vectors:
  - an integer has one spelling: `0` or a non-zero digit followed by
    digits; `-0`, fractions (`12.0`, `0.0`) and exponents (`1e1`, `1E1`,
    `0e0`) fail `json.structure` (§2 rule 4, check 4j; P4-01). The
    reference verifier already rejected them there.
  - `cose.structure` (3c) judges only the envelope's outer shape; whatever
    is wrong inside the protected bstr (a tag where the `kid`'s bstr
    belongs, an empty `kid`, CBOR that does not decode, a duplicate label)
    is `cose.protected_header` (4c), and whatever the unprotected map holds
    is `cose.unprotected_header` (5c). The `kid` is non-empty (§4.4, checks
    3c–5c; P4-02). The reference verifier reported the protected-header
    cases, and a malformed unprotected map, as 3c; it now follows this
    text. Verdicts do not change, only the first failing check.
  - strings are sequences of Unicode scalar values: a `\u` escape of an
    unpaired surrogate fails `json.structure` (not `json.syntax`: it is
    valid RFC 8259); raw bytes that are not UTF-8, CESU-8 surrogates
    included, still fail `json.syntax`; noncharacters are permitted, raw or
    escaped (§2 rule 1, check 4j; P4-03). The reference verifier already
    behaved so; the builder cannot emit an unpaired surrogate (a Rust string
    cannot hold one).
  - when `lineage.consistency` fails, the lineage outcome is *broken*, and
    the run still ends there, with `lineage.chain` skipped (§6.5; P4-04).
    §6.2 ("the first failure ... ends the run") and §6.5 ("*broken* — any
    rule above fails") read as disagreeing; the reference verifier and the
    vectors (`fail-lineage-initial-with-previous`,
    `fail-lineage-non-initial-without-previous`,
    `fail-lineage-length-1-non-initial`) already did both.

  `passport_version` stays `"0.1"`. The conformance vector did **not**
  change (`signed_payload_hash` stays
  `sha256:6b3e0cca76512d111657a337739bff952257bcf03853fed397128fed5843578c`).
  The verification vectors gained 15 cases for these items (94 in all);
  no existing case changed.
- **2026-09-11 — Phase 5 QA clarification** (`QA/QA_REPORT_PHASE5.md`,
  P5-10), wording only: §6.1 now says who may read a clock. The verifier
  (the library running §6.2) never does; a caller such as a command-line
  tool may supply its own current time as `T` and must say that it did —
  `tlm passport verify` without `--at` does exactly that, labelled
  `(current time)`, and the report records `T`. The result is still a
  function of the §6.1 inputs, `T` among them. No check, verdict, check id
  or vector changed; `passport_version` stays `"0.1"`, and the conformance
  vector's `signed_payload_hash` stays
  `sha256:6b3e0cca76512d111657a337739bff952257bcf03853fed397128fed5843578c`.
- **2026-09-12 — the example policy pack is neutral (owner decision).** A
  test vector names no real authority, and no jurisdiction's pack is the
  reference: the policy-pack format is jurisdiction-agnostic, with several
  reference packs (`docs/TASKS.md`, Phase 6). The conformance vector
  declared a corridor-specific pack, `pax-silica-baseline-v1`, and rule ids
  taken from it. It now declares the neutral `example-policy-pack-v1`, in
  `policy_compliance` and in `deployment_context.policy_pack_id`, still
  `compliant`, with four illustrative results whose rule ids name no
  jurisdiction: `example-data-residency`, `example-source-screening`,
  `example-export-control`, `example-audit-trail` (statuses and evidence
  hashes unchanged). No rule, check, check id or schema changed;
  `passport_version` stays `"0.1"`.

  The conformance vector changed: `signed_payload_hash`
  `sha256:6b3e0cca76512d111657a337739bff952257bcf03853fed397128fed5843578c`
  → `sha256:66583b8bb599ed8070bd2cbf546100c6079677d75cb648ed341f470a24825c36`
  (inside the payload only the two pack ids and the four rule ids changed),
  with its signature value and its top-level description. The verification
  vectors, which all start from it, were regenerated; no case's expected
  verdict, check id or lineage outcome changed.
- **2026-09-12 — Phase 6 revision: check 19, `time.policy_not_after_issued`**
  (`docs/dev/phase6.md` P6-6; the fourth time case the owner deferred from
  QA P5-08), before any passport was issued. `policy_compliance.evaluated_at` must not be later than
  `issued_at`: the evaluation is inside the signed payload (§3), so a later
  value claims a result the signature over it could not have covered. Equal
  is allowed. The check uses no evaluation time `T` (§6.4) and says nothing
  about whether the declared results are true (§6.6). It runs after the
  trust checks, so a passport nobody trusts still fails earlier. The
  lineage checks move to 20 and 21; a JSON passport now runs 21 checks and a
  COSE passport 25. `vmr-provenance` refuses to sign such a passport as well
  (issuer-side, next to the three P5-08 relations that are still not
  verifier rules).

  The conformance vector did **not** change: it declares
  `evaluated_at` `2026-09-10T00:00:00Z` and `issued_at`
  `2026-09-10T00:00:00Z` (`signed_payload_hash` stays
  `sha256:66583b8bb599ed8070bd2cbf546100c6079677d75cb648ed341f470a24825c36`).
  The verification vectors gained two cases,
  `fail-policy-evaluated-after-issued` and
  `pass-policy-evaluated-before-issued`; one existing case,
  `fail-chain-issued-before-predecessor`, moves its declared
  `evaluated_at` with the `issued_at` it backdates, so that it still fails
  at `lineage.chain`. No other case's expected verdict, check id or lineage
  outcome changed. `passport_version` stays `"0.1"`.
- **2026-09-13 — Phase 7, wording only** (`docs/dev/phase7.md` P7-5): §6.6
  points to `policy-pack-format-v0.1.md`, which now states how a policy pack
  is evaluated against a passport, what `evidence_hash` is taken over, and how
  an evaluation becomes `policy_compliance`. No rule, check, check id, schema
  or vector of this format changed; `passport_version` stays `"0.1"`.
- **2026-09-13 — the nesting bound, and the envelope's CBOR** (the spec pass
  before Phase 9, `docs/STATE.md`; the envelope's rule is the reviewer's
  decision of the same day), before any passport was issued. The format stated
  no bound on nesting, so a verifier whose parser stops at some depth could
  name another first failing check than the reference, and it left the
  envelope's CBOR to whatever a decoder reads.
  - **JSON: stated; the reference did not change.** A passport nests at most
    four levels, the outermost object counting as the first. A deeper text
    fails `json.structure` (in a COSE payload, `cose.payload`) at any depth,
    never `json.syntax`, and a syntax error anywhere in it still fails
    `json.syntax` first (§2 rule 13; checks 3j, 4j and 7c). The reference's
    syntax pass reads any depth, and its typed parse refuses a member of the
    wrong type before descending into it, so its JSON parser's own limit
    (serde_json refuses 128 levels) is never reached.
  - **The envelope: a stated subset and depth; the reference changed.** The
    envelope is one CBOR data item of the subset of §4.4 (integers, byte and
    text strings, arrays, maps and `null`, every argument in at most 4 bytes),
    nesting at most 16 levels; anything else fails `cose.structure` (§4.4;
    checks 3c and 5c). The reference used to hand the envelope to its CBOR
    library first, so its first failing check followed that library. For an
    envelope wrong in only one of these ways:
    - an unprotected map holding a tag, `false`, `true`, `undefined`, a
      float, an indefinite length or an 8-byte argument, or nesting 17 to 256
      levels, failed `cose.unprotected_header`;
    - an indefinite length or an 8-byte argument in the envelope's own items
      failed `cose.canonical`;
    - an unassigned simple value, a negative bignum below −2^127 or nesting
      past 256 levels already failed `cose.structure`, for the library's
      reasons.

    The library read the first two kinds, and each failed the first of
    checks 4c–8c that objected, so an envelope with a second defect could
    fail another check first: the spec pass's QA observed
    `cose.protected_header`, `cose.signature_encoding` and `cose.payload`
    (`QA/QA_REPORT_SPEC_PASS.md` QS-03). Each now fails `cose.structure`, by
    the rule: `tlm-passport` reads the
    envelope head by head before any decoder does. No verdict changed, and no
    earlier verification vector's expected result.
  - Both bind every predecessor (§6.5).

  The verification vectors gained twenty-nine cases (125 in all; 141 with
  task 10.11a's sixteen, below), and no earlier case changed:
  - JSON: `fail-nesting-5-levels`, `fail-nesting-127-levels`,
    `fail-nesting-128-levels`, `fail-nesting-10000-levels`,
    `fail-nesting-100000-levels` and `fail-nesting-128-levels-unclosed`;
  - the COSE payload: `fail-cose-nesting-5-levels`,
    `fail-cose-nesting-127-levels` and `fail-cose-nesting-128-levels`;
  - the envelope's CBOR: `fail-cose-nesting-16-cbor-levels`,
    `fail-cose-nesting-17-cbor-levels`, `fail-cose-cbor-null-in-unprotected-map`,
    `fail-cose-cbor-simple-value`, `fail-cose-cbor-true`, `fail-cose-cbor-float`,
    `fail-cose-cbor-bignum`, `fail-cose-cbor-indefinite-length`,
    `fail-cose-cbor-8-byte-argument`, `fail-cose-cbor-indefinite-payload`,
    `fail-cose-nesting-16-cbor-levels-in-a-key`,
    `fail-cose-nesting-17-cbor-levels-in-a-key`, `fail-cose-cbor-text-not-utf8`,
    `fail-cose-cbor-4-byte-argument`, `fail-cose-non-preferred-4-byte-length`,
    `fail-cose-cbor-8-byte-signature-length`, `fail-cose-cbor-undefined`,
    `fail-cose-cbor-reserved-additional-information` and
    `fail-cose-cbor-double-float`;
  - lineage: `fail-chain-predecessor-nesting-128-levels`.

  After the spec pass's QA (`QA/QA_REPORT_SPEC_PASS.md` QS-02), the wording
  of §2 rule 13, §4.4 and §6.2 row 3c was tightened: only arrays and maps
  count toward the envelope's depth, a map's keys as well as its values;
  "anywhere in the envelope" means its own data items, not the bytes inside
  its protected and payload bstrs; and RFC 8259 §9's latitude to limit depth
  is named. No rule, check or vector changed by it.

  `passport_version` stays `"0.1"`, and the conformance vector did not change
  (`signed_payload_hash` stays
  `sha256:66583b8bb599ed8070bd2cbf546100c6079677d75cb648ed341f470a24825c36`).
- **2026-09-13 — task 10.11a: optional documentation members**
  (`docs/dev/task-10.11a.md` D11-1 to D11-3, approved by the reviewer the same
  day), before any passport was issued.
  - **The change.** Two optional top-level members, `data_governance` and
    `human_oversight`, each a closed object with one `documentation_hash`
    (§2 rule 3). A policy pack can then ask whether a passport pins its
    issuer's documentation of data governance and of human oversight: the
    subjects of Art. 10 and Art. 14 of the EU AI Act, or any other
    authority's equivalent. A hash names a document; it does not show the
    document exists or is adequate (§6.3).
  - **No check changed.** The members are judged by the existing checks
    `json.structure` (for COSE, `cose.payload`) and `format.schema`. No
    check, check id, check count or verdict rule changed.
  - **No signed payload moved.** A passport without the members serialises
    exactly as before, because §3 sorts members by name.

  The conformance vector did **not** change (`signed_payload_hash` stays
  `sha256:66583b8bb599ed8070bd2cbf546100c6079677d75cb648ed341f470a24825c36`).
  The verification vectors gained nine cases, and no existing case changed:
  - `pass-documentation-declared`, `pass-documentation-declared-cose`;
  - `fail-documentation-hash-edited`, `fail-documentation-hash-uppercase`,
    `fail-documentation-hash-empty`;
  - `fail-documentation-null`, `fail-documentation-unknown-member`,
    `fail-documentation-missing-hash`, `fail-documentation-not-an-object`.

  `passport_version` stays `"0.1"`.
- **2026-09-14 — the task 10.11a QA's findings QT-02 and QT-04**
  (`QA/QA_REPORT_TASK_10_11A.md`), before any passport was issued.
  - **Vectors.** Each failing documentation case above set one member only.
    The verification vectors gained seven cases, each an earlier case's edit
    made on the other member, and no existing case changed:
    - `fail-documentation-governance-hash-edited`;
    - `fail-documentation-oversight-hash-uppercase`,
      `fail-documentation-governance-hash-empty`;
    - `fail-documentation-oversight-null`,
      `fail-documentation-governance-unknown-member`,
      `fail-documentation-oversight-missing-hash`,
      `fail-documentation-governance-not-an-object`.

    A member written as a JSON array (QA QT-01) is not among them: that
    finding is fixed in its own lane.
  - **Wording only.** §2 rule 9 says that its term "optional hashes" means
    only its six members, and that `documentation_hash` is not one, so `""`
    is refused there; rule 3 points to rule 9. No rule, check, check id,
    schema or verdict changed.

  `passport_version` stays `"0.1"`.
- **2026-09-14 — the task 10.11a QA's finding QT-01**
  (`QA/QA_REPORT_TASK_10_11A.md`; `docs/dev/fix-json-object-shape.md`), before
  any passport was issued.
  - **Wording only.** §2 rule 2 and check 4j now say that an object's values
    written as a JSON array, in any order, fail `json.structure` (in a COSE
    payload, `cose.payload`). Rules 2, 4 and 13 and check 4j already required
    the schema's JSON types. The reference implementation read such an array
    as the object, in the order of the schema's `properties`, so a signed
    passport respelled that way verified. No rule, check, check id, schema or
    verdict rule changed.
  - **Vectors.** The verification vectors gained eighteen cases, and no
    existing case changed. Each writes one object of a signed passport, after
    signing, as the array of its values in the order of the schema's
    `properties`:
    - `json.structure`: `fail-issuer-as-array`, `fail-public-key-as-array`,
      `fail-model-identity-as-array`, `fail-architecture-as-array`,
      `fail-state-component-as-array`, `fail-learning-provenance-as-array`,
      `fail-training-environment-as-array`,
      `fail-training-input-provenance-as-array`,
      `fail-collection-period-as-array`, `fail-deployment-context-as-array`,
      `fail-inference-boundary-as-array`, `fail-policy-compliance-as-array`,
      `fail-policy-result-as-array`, `fail-lineage-as-array`,
      `fail-signature-section-as-array`,
      `fail-documentation-governance-as-array` and
      `fail-documentation-oversight-as-array`;
    - `lineage.chain`: `fail-chain-predecessor-public-key-as-array`, a
      predecessor so written.

  `passport_version` stays `"0.1"`, and the conformance vector did not change
  (`signed_payload_hash` stays
  `sha256:66583b8bb599ed8070bd2cbf546100c6079677d75cb648ed341f470a24825c36`).
- **2026-09-14 — the QT-01 fix's QA, finding QJ-04** (`QA/QA_REPORT_QT01.md`),
  before any passport was issued.
  - **Wording only.** §2 rule 2 said that an object written as an array fails
    `json.structure` "at every level". For the JSON form's outermost value
    that was not so: check 2, `input.form`, fails first, and every
    implementation reported it. Rule 2 and check 4j now say so. No rule,
    check, check id, order or verdict changed.
  - **Vectors.** The verification vectors gained one case, and no existing
    case changed: `fail-passport-as-array`, the vector written, after
    signing, as the array of its values in the order of the schema's
    `properties`, fails `input.form`.

  `passport_version` stays `"0.1"`.
- **2026-09-14 — task 10.11b: a truthful passport for any kind of model**
  (`docs/dev/task-10.11b.md`, approved by the reviewer the same day), before
  any passport was issued.
  - **Why.** The format could describe only the KHALM engine's learned state:
    three named components with fixed size formulas, a fixed parameter count,
    `model_hash` equal to `learned_state_hash`, and a `KHALMTRN` training
    stream. Another model got no truthful passport, and bytes fitted to that
    layout still verified.
  - **The model (§7).**
    - `model_format` selects the description (§7.1). The one registered
      profile, `snn-compact-v1`, keeps the former §7 rules word for word
      (§7.4). Every other value selects the general description (§7.3).
    - In the general description the issuer names its model's components,
      and `learned_state_hash` is their named-set digest (§7.2), which binds
      each name and which a verifier checks. `model_hash` is the named-set
      digest of every file the model is distributed as.
    - A model names what it was made from in `derived_from` (§7.5).
    - §7.6 says who can truthfully issue what.
  - **Training (§8).**
    - Records have a named format (§8.2), and `named-set-v1` is defined.
    - A passport can commit to no records and say whether they are not
      disclosed or not held (§8.4).
    - The environment names no vendor in a required member (§8.5), and
      residency may be several countries or not stated.
    - `deployment_context` and the members an issuer may not know are
      optional (§2 rule 3).
  - **The schema.**
    - `learned_state_components` has `minItems` 1 and no name enum.
    - `training_input_digest` and `training_input_merkle_root` may be `""`
      (§2 rule 9).
    - Sixteen members are optional, twelve of them since this revision (five
      new members and seven that were required), and one keyword,
      `minLength`, is new (§2 rule 11).
  - **No check changed.** No check id, check count, check order or verdict
    rule changed. `format.consistency` (§6.2) checks the model rules §7.1
    selects and the new relations between members. For a profile passport its
    rules, and the reference verifier's detail, are the former ones.
  - **No existing passport moved.** Every earlier passport names
    `snn-compact-v1`, and every new member is omitted when absent, so no
    signed payload, verdict, first failing check, evidence hash or report
    changed.

  The conformance vector did **not** change (`signed_payload_hash` stays
  `sha256:66583b8bb599ed8070bd2cbf546100c6079677d75cb648ed341f470a24825c36`).
  New vector files: `test-vectors/record/example-general-v0.1.json` and
  `test-vectors/model-hash/` (§9). The verification vectors gained forty-three
  cases (203 in all), and no existing case changed:
  - passing: `pass-general-open-weights-not-held`,
    `pass-general-open-weights-not-held-cose`,
    `pass-general-fine-tune-unpassported-base`,
    `pass-general-fine-tune-chain-across-issuers`,
    `pass-general-diffusion-weights-only`,
    `pass-general-classical-one-file-not-disclosed`,
    `pass-vector-without-deployment-and-cuda`;
  - the profile and fitted bytes, at `format.consistency`:
    `fail-profile-extra-component`, `fail-profile-model-hash-of-files`,
    `fail-profile-identifier-dropped`, `fail-profile-identifier-added`,
    `fail-profile-byte-fitted-under-general-format`,
    `fail-profile-training-input-format`;
  - the general description: `fail-general-state-hash-not-digest`,
    `fail-general-components-unordered`,
    `fail-general-component-name-repeated`,
    `fail-general-component-name-dot-segment`,
    `fail-general-component-name-leading-slash`,
    `fail-general-component-name-empty`,
    `fail-general-component-hash-edited`,
    `fail-general-training-format-missing` (`format.consistency`) and
    `fail-general-no-components` (`format.schema`);
  - the commitment: `fail-not-held-with-digest`,
    `fail-not-held-count-not-zero`, `fail-not-held-with-format`,
    `fail-committed-root-empty` (`format.consistency`),
    `fail-disclosure-outside-enum` (`format.schema`) and
    `fail-disclosure-edited` (`signature.payload_hash`);
  - residency: `fail-residency-countries-with-residency`,
    `fail-residency-countries-unordered` (`format.consistency`),
    `fail-residency-countries-one` and `fail-residency-countries-lowercase`
    (`format.schema`);
  - derived models, empty strings and structure:
    `fail-derived-from-unordered` (`format.consistency`);
    `fail-derived-from-relation-outside-enum`, `fail-derived-from-empty`,
    `fail-general-training-format-empty`, `fail-accelerator-empty`
    (`format.schema`); `fail-derived-from-null`,
    `fail-deployment-context-null`, `fail-training-epochs-null`,
    `fail-accelerator-not-a-string`, `fail-derived-from-entry-unknown-member`
    and `fail-derived-from-entry-as-array` (`json.structure`).

  `passport_version` stays `"0.1"`.
- **2026-09-14 — the task 10.11b QA's findings, and task 10.11e**
  (`QA/QA_REPORT_TASK_10_11B.md`, with the reviewer's decisions;
  `docs/dev/task-10.11e.md`, D11e-1 to D11e-9), before any record was issued.
  - **One model folder (QB-01): rules for tools.** Where §7.2 left a tool a
    choice, it now says what a tool does: a model distributed as one file is
    named by that file's own name; a `\` separator becomes `/`, while a `\`
    inside a name stays; a name is taken as stored, never normalised or
    case-folded; a name that is not a sequence of Unicode scalar values makes
    the tool refuse the folder; a link to a file is hashed under the link's
    own name, and any other link makes the tool refuse the folder. The same
    model folder gives the same record when it holds the same names and the
    same bytes, and §7.2 names what changes them. The informative OMS note
    says which manifests convert, and how. No verifier rule changed with
    these.
  - **Wording (QB-02, QB-05).** §6.3: `model_hash` can be checked only over the
    issuer's list of files. §7.1's reason no longer says that editing
    `model_format` alone moves no record: an edit breaks the signature, and a
    record can be issued that meets both rule sets. §7.3 says why components
    should be every file, and that only `model_hash` is the model's identity.
    The count of optional members in the entry above is corrected (sixteen,
    twelve of them since that revision).
  - **§8.2's empty root (QB-04), wording only.** §8.2 now says that a
    verifier does not check that a count of 0 goes with the empty tree's
    root, or a count of 1 or more with another root, and that a policy rule
    requiring committed input fails either contradiction. A verifier rule
    was not adopted: it would stop two existing verifiable policy cases,
    `audit-integrity-input-committed-fail-no-input` and
    `audit-integrity-input-committed-fail-empty-tree-root`, from verifying.
    No check, case or verdict changed.
  - **Rules, all at `format.consistency` (§6.2 row 6 names §7.7).**
    - §7.5: no `derived_from` entry is the model's own `model_hash`.
    - §2 rule 3, §7.3, §7.4: `parameter_count` is optional in the general
      description, and required in the profile `snn-compact-v1`.
    - §7.7, new: `model_identity.statement_references` names other signed
      statements about the model, each by `format` and `digest`. A format
      without `.` is registered (v0.1: `oms-v1` only), and one with `.` is the
      issuer's own; entries ascend by `digest`, none repeated. A verifier
      checks their form only (§6.3). §2 rules 3 and 9 name the member; the
      schema gains it, with a `pattern` for `format`.
  - **No check changed.** No check id, check count, check order or verdict
    rule changed. A record without `statement_references` and with its
    `parameter_count` serialises as before, so no signed payload moved.
  - **First failing checks that move, for inputs no earlier vector held:**
    - a general record without `parameter_count`: from `json.structure` (in
      COSE, `cose.payload`) to a pass;
    - a profile record without it: from `json.structure` (`cose.payload`) to
      `format.consistency`; `null` stays at `json.structure`;
    - a record carrying `statement_references`: from `json.structure`
      (`cose.payload`) to the checks above;
    - a record whose `derived_from` names its own `model_hash`: from a pass
      to `format.consistency`.

  Neither conformance vector changed (`example-v0.1.json`'s
  `signed_payload_hash` stays
  `sha256:66583b8bb599ed8070bd2cbf546100c6079677d75cb648ed341f470a24825c36`).
  The verification vectors gained fifty cases (253 in all), and no existing
  case changed:
  - names as stored (QB-01): `pass-general-component-name-backslash`,
    `pass-general-component-names-nfc-and-nfd`,
    `pass-general-component-names-case-twins`;
  - the name rules and the order, each broken with the digest recomputed
    (QB-03): `fail-general-component-name-empty-digest-kept`,
    `fail-general-component-name-dot-segment-digest-kept`,
    `fail-general-component-name-dotdot-segment-digest-kept`,
    `fail-general-component-name-leading-slash-digest-kept`,
    `fail-general-component-name-trailing-slash-digest-kept`,
    `fail-general-component-name-double-slash-digest-kept`,
    `fail-general-component-name-repeated-digest-kept`,
    `fail-general-components-unordered-digest-kept`,
    `fail-general-component-names-utf16-order`,
    `fail-general-component-names-case-insensitive-order`,
    `pass-general-component-names-utf8-order` and
    `pass-general-component-names-capitals-first`;
  - the identifier compared exactly, the commitment, residency and bases
    (QB-03): `fail-profile-identifier-case`, `pass-general-profile-look-alike`,
    `pass-general-profile-look-alike-fullwidth`,
    `pass-general-empty-model-format`, `fail-not-held-with-root`,
    `fail-committed-digest-empty`, `fail-residency-countries-repeated`,
    `fail-derived-from-repeated` and `pass-general-empty-file-component`;
  - shape selects nothing (QB-05): `pass-general-profile-shaped-components`;
  - settled by the text (QB-08): `pass-profile-not-held`,
    `pass-profile-derived-from`, `pass-general-file-and-directory-names`,
    `pass-general-component-name-with-controls`, and
    `fail-derived-from-itself`;
  - `parameter_count` (QB-09): `pass-general-parameter-count-not-stated`,
    `pass-general-parameter-count-not-stated-cose`,
    `fail-profile-parameter-count-absent` and
    `fail-general-parameter-count-null`;
  - `statement_references`: `pass-statement-references-oms-v1`,
    `pass-statement-references-issuer-format`,
    `pass-statement-references-issuer-format-cose`,
    `fail-statement-references-dotless-unregistered`,
    `fail-statement-references-unordered`,
    `fail-statement-references-repeated` (`format.consistency`);
    `fail-statement-references-empty`,
    `fail-statement-references-digest-uppercase`,
    `fail-statement-references-digest-empty`,
    `fail-statement-references-format-uppercase`,
    `fail-statement-references-format-look-alike` (`format.schema`);
    `fail-statement-references-null`,
    `fail-statement-references-entry-member-repeated`,
    `fail-statement-references-entry-unknown-member`,
    `fail-statement-references-entry-as-array` and
    `fail-statement-references-format-not-a-string` (`json.structure`).

  `test-vectors/model-hash/` gained six cases (33 in all), and no existing
  case changed: `name-accepted-backslash`, `name-accepted-nfd`,
  `digest-nfc-versus-nfd`, `digest-case-twins`, `digest-separator-order` and
  `set-refused-path-part-order`.

  `passport_version` stays `"0.1"`.
- **2026-09-14 — the task 10.11e QA's findings** (`QA/QA_REPORT_TASK_10_11E.md`,
  QE-02 to QE-06), before any record was issued.
  - **Wording only.** No rule, check, check id, check count, schema or verdict
    changed.
    - §8.2 (QE-03): a policy rule that requires committed input fails the two
      contradictions for records that commit training records; a record that
      commits none (§8.4) is `indeterminate` under it.
    - §7.2 (QE-04): a link is a symbolic link or any other entry the file
      system resolves to another path, a Windows directory junction
      included, under the same rules; a tool given one file names it by its
      own name, and a tool given a folder names each file by its path in it;
      a checkout that cannot create links writes another file; the OMS note
      says which links a tool hashes.
    - §7.2 (QE-05): the same folder gives the same `model_hash`, and the same
      name, hash and size for each file, not the same record. Where the
      entry above says "the same record", read the same `model_hash`.
    - §7.7 (QE-06): a value with `.` is never a registered format, whatever
      its segments, and a party or tool that relies on a registered format
      compares `format` with it as an exact string.
  - **Vectors (QE-02).** The verification vectors gained nine cases (262 in
    all), and no existing case changed:
    `fail-statement-references-dotless-oms-v2` and
    `fail-derived-from-own-model-hash-differs-from-state-hash`
    (`format.consistency`); `fail-statement-references-format-fullwidth`
    (`format.schema`); `pass-statement-references-registered-name-as-segment`,
    `pass-statement-references-two-of-one-format`,
    `pass-profile-statement-references` and its `-cose` form,
    `pass-derived-from-learned-state-hash` and
    `pass-general-parameter-count-zero`.

  Neither conformance vector changed (`example-v0.1.json`'s
  `signed_payload_hash` stays
  `sha256:66583b8bb599ed8070bd2cbf546100c6079677d75cb648ed341f470a24825c36`).
  `passport_version` stays `"0.1"`.
- **2026-09-15 — the Verifiable Model Record** (tasks 10.11c and 10.11d; the
  owner's decisions of 2026-09-14 and 2026-09-15), before any record was
  issued.
  - **The name.** The format is the Verifiable Model Record (VMR); this
    document is `record-format-v0.1.md`, its schema `record-schema/v0.1.json`
    with the `$id` `https://verifiablemodel.org/schemas/record/v0.1.json`, and
    its vectors `test-vectors/record/`, each holding its record in `record`.
  - **The members.** `record_id`, `record_version`, `lineage.previous_record_id`,
    `lineage.previous_record_hash` and `lineage.root_record_id` replace the five
    members that named the passport. Their types, rules and checks are
    unchanged, and so is every check id.
  - **A second registered statement format** (§7.7), `vmr-audit-checkpoint-v1`:
    an audit-log checkpoint, by the SHA-256 of its signed payload. A verifier
    checks the reference's form only. §7.7 states that payload in this
    document's terms (the checkpoint with its top-level `signature` member
    removed, in the JCS form of RFC 8785), names the checkpoint's format as the
    VMR audit-log format, and says that a successor repeating `model_identity`
    repeats the reference.
  - **Wording.** §7.4 states the four fields of the engine's state header the
    profile reads, and §8.2 the layout of a `KHALMTRN` stream, in place; a unit
    of training input is a training record, and §8.2's heading says so.
  - **Vectors.** Every file is regenerated by its generator. The verification
    vectors gained four cases (266 in all), and no other case's expected
    result changed. The conformance vector's `signed_payload_hash` is
    `sha256:ed51030187a1720103f70be6781aace68724825fe440f87cdddb25bd969e4106`,
    the general conformance vector's
    `sha256:5d7172cf0d5931868cbe337b951751e7249a78b62c8a8f68c5b5287638ec6f0e`;
    neither vector's `model_hash` moved.

  `record_version` stays `"0.1"`.
- **2026-09-15 — KHALM-VMR** (task 10.11f), before any record was issued.
  Wording only: the reference implementation's software is named KHALM-VMR,
  a reference implementation of this standard, never the standard's own
  tool; no crate, member, check or byte changed.
- **2026-09-16 — general environment members** (task 10.12a), before any
  record was issued.
  - **Members.** `training_environment.cuda_version`, one vendor's toolkit,
    becomes the optional `accelerator_software`: the accelerator's software
    and its version as the issuer names it, never `""`, like `accelerator`
    (§2 rule 3, §8.5). `engine_version` becomes `training_software`, which
    §8.5 already defined as any training software. The schema follows.
  - **Wording.** §8.4 says that a policy rule requiring committed input fails
    a record that withholds it (policy-pack format §6.4). §9 names the test
    key's label `khalm v0.1 test-vector signing key`.
  - **Vectors.** Every file is regenerated by its generator. The verification
    vectors gained `fail-accelerator-software-empty` (267 in all), and
    `pass-vector-without-deployment-and-cuda` is
    `pass-vector-without-deployment-and-accelerator-software`; no other case's
    expected result changed. The conformance vector's `signed_payload_hash` is
    `sha256:2eca0dd33554f5113d03ef96bc01deb56fafd8484bbf95f04bd308ee6c075967`,
    the general conformance vector's
    `sha256:2d1081356f7f9c7c571707be849c20db67313e0008f1f467385eb18999507466`;
    neither vector's `model_hash` moved.

  `record_version` stays `"0.1"`.

- **2026-09-16 — the registered profiles are optional** (the specification's
  owner, after the release QA's QR-08 and QR-09), before v0.1 was published.
  - **§7.1.** Supporting a registered profile is not a condition of
    conformance. An implementation that implements none reports a record in a
    profile it does not support as unsupported, never as invalid, and still
    checks every rule of §1 to §6 and §8.
  - **§7.2.** The five reasons a tool reports for a refused name or set —
    `empty`, `empty-segment`, `dot-segment`, `dotdot-segment`,
    `not-ascending` — and `refused_at`, which the conformance suite compares
    and which were defined only in a test-vectors README before.
  - **Vectors.** No committed case changed. The verification vectors gained
    161 general-description copies (428 in all) and the policy vectors 132
    (287), so a profile-blind implementation is held to every general rule an
    engine-record case tests. No signed byte of any earlier case moved.

  `record_version` stays `"0.1"`.
