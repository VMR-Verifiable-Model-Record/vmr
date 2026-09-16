# VMR Trust Store — Format v0.1

**Status:** normative, pre-publication.
**Structure:** [`trust-store-schema/v0.1.json`](trust-store-schema/v0.1.json) (JSON Schema 2020-12).
**Rules the schema cannot express, and all semantics:** this document.
**Vectors:** [`test-vectors/trust-store/`](test-vectors/trust-store/) (loader) and
[`test-vectors/verify/`](test-vectors/verify/) (verification).
**Reference implementation:** KHALM-VMR's crate `vmr-verify` (`TrustStore`).

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in
RFC 2119 / RFC 8174.

## 1. What a trust store is

A trust store is a verifier operator's **local root of trust**: a small,
public JSON file that maps issuer DIDs to the public keys the operator trusts
to sign records for them. It is obtained **before** verification and **out
of band** — on a USB stick, in a signed e-mail, from a regulator's
publication — the way a browser ships root certificates or SSH keeps
`known_hosts`. At verification time nothing is fetched: no network, no
contact with the issuer, no DID resolution.

A record verifies only when it is signed by a key this store trusts for the
issuer the record names (`record-format-v0.1.md` §6). The key inside a
record is never a source of trust: anyone can generate a key, embed it and
sign.

A store may also name the **policy authorities** whose keys the operator
trusts to sign policy packs (`policy-pack-format-v0.1.md` §4), in a list of
their own (§4.2). The two lists are kept apart by structure: a record's key
is looked up only among the issuers and a pack's only among the authorities,
and no key is in both: not within one store, and not across a trust store and
the authority store given with it (§4.2).

v0.1 stores are **unsigned**. Their integrity is the operator's
responsibility, as with a CA bundle: whoever can edit the file decides whom
the verifier trusts. Every verification report therefore names the store it
trusted by its canonical hash (§5), so a result can be tied to the exact set
of keys it relied on. Signed, distributed stores are future work (v0.2).

## 2. Format

```json
{
  "trust_store_version": "0.1",
  "issuers": [
    {
      "issuer_id": "did:web:factory-operator.ph",
      "issuer_name": "New Clark City Fab Operator",
      "keys": [
        {
          "key_id": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:HyoPYysSFOQ5d6x64H8_pHddcHp7E91G5SZbdiaeWJg",
          "public_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": "yRw99YmqYhAQER8UMKILOv-OFDLjl9n5E-SckLlV318",
            "y": "BCdTbjkziAfvOeGj-1v8vO2OqdV0_zX1ZWJLA43GxOY"
          },
          "attestation_level": "software",
          "valid_from": "2026-01-01T00:00:00Z",
          "valid_until": "2027-01-01T00:00:00Z",
          "revoked": false
        }
      ]
    }
  ]
}
```

(The key above is the record conformance vector's test-only key.)

A store that trusts a policy authority lists it under `policy_authorities`.
This one trusts no issuer, as an authority store does (§4.2):

```json
{
  "trust_store_version": "0.1",
  "issuers": [],
  "policy_authorities": [
    {
      "authority_id": "khalm-policy-vectors",
      "authority_name": "KHALM policy vectors (test-only)",
      "keys": [
        {
          "key_id": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:gs6uavA3GXnqxOYNw7bUgmfhhG_sRfgJ6989zU5kXpU",
          "public_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": "OHTUOQTDXX3o2oV9VcOvoE5utl0JWj7WvG1sTtn-yuw",
            "y": "8lNAVjB4yiNzd_8M_r_2yDo-6xriVRvCm6HuBdvW6ks"
          },
          "attestation_level": "software",
          "valid_from": "2026-01-01T00:00:00Z",
          "revoked": false
        }
      ]
    }
  ]
}
```

(The key above is the test-only authority key of the policy vectors: the
signed pack of `test-vectors/policy/` is signed with it, and names this
`authority_id`.)

| Member | Rule |
|---|---|
| `trust_store_version` | exactly `"0.1"` |
| `issuers` | an array, possibly empty (a store that trusts no one) |
| `issuers[].issuer_id` | a DID in the record's `issuer_id` syntax (W3C DID Core, ASCII; `record-format-v0.1.md` §2 rule 10); unique across the store; compared with a record's `issuer.issuer_id` by exact string equality — no case folding, no percent-decoding, no resolution |
| `issuers[].issuer_name` | the display name a verifier shows for this issuer. The record's own `issuer_name` is a claim; this one is the operator's |
| `issuers[].keys` | at least one key |
| `policy_authorities` | optional; an array, possibly empty. Absent and empty are the same store (§5). Every store written without it stays valid, with its identity |
| `policy_authorities[].authority_id` | a non-empty string, the rule of a policy pack's `authority.authority_id` (`policy-pack-schema/v0.1.json`); unique among the authorities; compared with a pack's `authority.authority_id` by exact string equality. It may equal an `issuer_id`: the lists are apart |
| `policy_authorities[].authority_name` | the display name a verifier shows for this authority. The pack's own `authority_name` is a claim; this one is the operator's |
| `policy_authorities[].keys` | at least one key, each exactly an issuer's key object (the rows below). Its `attestation_level` is required, and nothing reads it for a pack, which declares no level |
| `keys[].key_id` | the RFC 7638 thumbprint URN of `public_key` (`record-format-v0.1.md` §5); MUST equal the key id computed from `public_key`; unique across the **whole** store, both lists — a key trusted for two issuers would make every record it signs ambiguous, and a key under an issuer and an authority would let one key speak in both roles, so such a store is rejected |
| `keys[].public_key` | the key as a JWK exactly as in a record (`record-format-v0.1.md` §5): `kty` `"EC"`, `crv` `"P-256"`, `x` and `y` the 32-byte coordinates in canonical base64url, a point on the curve |
| `keys[].attestation_level` | `hardware`, `software` or `self` — authoritative for this key: a record may declare the same or a lower level (`self` < `software` < `hardware`), never a higher one |
| `keys[].valid_from` | a timestamp in the UTC-seconds profile (`record-format-v0.1.md` §2 rule 7): the first second at which the key may sign |
| `keys[].valid_until` | optional; absent = no end. When present, a profile timestamp strictly after `valid_from`: the key may sign strictly before it |
| `keys[].revoked` | `true` or `false` |

Every object is closed (`additionalProperties: false`); unknown members,
duplicate member names and `null` values are rejected, with the same
strictness as records (`record-format-v0.1.md` §2 rules 1–3). A store is
UTF-8 JSON (RFC 8259), at most 16 MiB (16 777 216 bytes). As in records,
strings — member names and values — are sequences of Unicode scalar values:
a `\u` escape that denotes an unpaired surrogate is valid RFC 8259 syntax
but is rejected as `trust_store.structure` (§3); bytes that are not UTF-8,
surrogates in CESU-8 form included, are `trust_store.syntax`.
**Noncharacters** (U+FDD0–U+FDEF, and U+xFFFE and U+xFFFF of every plane)
are scalar values and are permitted, raw or escaped: a loader MUST NOT
reject them.

**Nesting.** A store's text nests arrays and objects at most 127 levels deep,
the outermost counting as the first. Deeper text is rejected as
`trust_store.syntax` (§3), before its version is read, so a loader whose
parser stops at a depth limit conforms without reading past it. A valid store
nests at most six levels.

## 3. Loading

A verifier MUST reject a store that breaks any rule of §2, and SHOULD report
which rule, with these stable kinds, checked in this order (the loader vectors
name the kind):

| # | Kind | Rejected when |
|---|---|---|
| 1 | `trust_store.size` | the file is larger than 16 MiB |
| 2 | `trust_store.syntax` | not UTF-8 (surrogates in CESU-8 form included), not RFC 8259 JSON, anything but whitespace after the top-level value, or text nesting arrays and objects more than 127 levels deep (§2) |
| 3 | `trust_store.version` | `trust_store_version` is a string other than `"0.1"` (checked before the structure, so a store of a later version is reported as such, not as a pile of unknown members) |
| 4 | `trust_store.structure` | not exactly the members of §2 with their JSON types at every level (unknown, duplicate, missing and `null` members; an object written as a JSON array, of its values in any order or of anything else, the store itself included; a missing or non-string version; an `attestation_level` outside the three values; an issuer or a policy authority without keys); a string — member name or value — holding a `\u` escape of an unpaired surrogate (§2) |
| 5 | `trust_store.issuer_id` | an `issuer_id` is not a DID in the §2 syntax |
| 6 | `trust_store.authority_id` | an `authority_id` is the empty string |
| 7 | `trust_store.timestamp` | a `valid_from` or `valid_until` is not a calendar-valid profile timestamp |
| 8 | `trust_store.invalid_key` | a `public_key` is not a P-256 JWK naming a point on the curve (wrong `kty`/`crv`, a coordinate that is not canonical base64url of 32 bytes, an off-curve point) |
| 9 | `trust_store.key_id_mismatch` | a `key_id` is not the thumbprint URN of its `public_key` |
| 10 | `trust_store.duplicate_issuer` | two issuers have the same `issuer_id` |
| 11 | `trust_store.duplicate_authority` | two policy authorities have the same `authority_id` |
| 12 | `trust_store.duplicate_key` | a `key_id` appears twice — under one issuer or authority, under two, or under an issuer and an authority |
| 13 | `trust_store.validity_window` | a `valid_until` is not strictly after its `valid_from` |

Each rule is checked over the whole document, in document order, before the
next rule is checked; the first failure found is reported (for a duplicate,
its second occurrence). For this order, `issuers` and its keys come before
`policy_authorities` and its keys, whatever the order of the two members in
the file. Rules 7 to 9, 12 and 13 apply to every key, of an issuer or of an
authority.

## 4. Lookup and binding

A verifier looks a record's signing key up by `signature.signing_key_id`
(exact string equality with a store `key_id`), among the keys of `issuers`
only: a key listed under `policy_authorities` never signs a record. A hit
yields the issuer entry and the key entry. The key entry's JWK — never the
record's `issuer.public_key` — is the key the signature is verified with,
and it MUST equal the record's `issuer.public_key`. The record is then
bound to the entry: the entry's `issuer_id` MUST equal the record's
`issuer.issuer_id`; a key the store trusts for another issuer does not speak
for this one.

The store's key order and issuer order never change a result: lookups are by
key id, and the canonical hash (§5) sorts both.

### 4.1 Validity and revocation

- `revoked: true` fails **every** record the key signed, whatever its
  `issued_at`: after a compromise, no `issued_at` from that key can be
  believed. (This makes revocation absolute; trusted timestamps, which would
  allow a `revoked_at`, are future work.)
- `valid_from ≤ issued_at < valid_until` (no upper bound when `valid_until` is
  absent). The window bounds what a key may **sign**, not how long its
  signatures last: a record outlives its key's expiry, and rotating to a new
  key never breaks an old lineage link. A retired key that leaks *later* can
  backdate records until it is revoked — inherent without trusted
  timestamps.
- A record's declared `issuer.attestation_level` must not exceed the key's
  level here (`self` < `software` < `hardware`); an under-claim is accepted.

Time is never read from a clock by the verifier: `issued_at` is compared with
the key window, and with the caller-supplied evaluation time
(`record-format-v0.1.md` §6.4).

### 4.2 Policy authorities

A policy pack may carry its authority's signature
(`policy-pack-format-v0.1.md` §4). A verifier that checks it uses the store's
`policy_authorities` only, never `issuers`: an issuer's key does not vouch for
a pack.

**The stores come first.** A verifier MUST load and check the stores before
the pack's signature, in this order, and the first refusal stops it:

1. the trust store: the kinds of §3;
2. the authority store, when one is given: the kinds of §3, then
   `authority_store.issuers`, then `authority_store.issuer_key` (below);
3. the pack: the refusals of `policy-pack-format-v0.1.md` §3;
4. the pack's signature: the steps below.

The vectors `order-authority-store-before-payload-hash` and
`order-issuer-key-before-payload-hash` (`test-vectors/policy/pack-signature.json`)
pin the authority store before the signature.

Given the pack and the evaluation time T, in this order:

1. **No `signature` section:** the pack is unsigned.
2. **The payload hash,** which needs no key: the section's
   `signed_payload_hash` MUST be the pack's payload hash
   (`policy-pack-format-v0.1.md` §4, step 4). A pack that fails it was
   changed after it was signed, or carries another pack's section. It is not
   its authority's, whatever the store holds.
3. **No authority key** whose `key_id` equals the pack's
   `signature.signing_key_id` (exact string equality): the signature is not
   checked, and the pack MUST NOT be reported as its authority's.
4. **The signature** is checked under that key entry's JWK, by the other steps
   of `policy-pack-format-v0.1.md` §4. A failure means it does not verify. A
   report of it names the key, and no authority.
5. **The binding:** the entry's `authority_id` MUST equal the pack's
   `authority.authority_id`. A key the store trusts for one authority does not
   speak for another.
6. **Revocation:** the key MUST NOT be revoked.
7. **The window:** `valid_from ≤ T < valid_until`, with no upper bound when
   `valid_until` is absent. A pack carries no signed time, so the window
   bounds when the key's signatures are relied on, not when they were made.
   After a key's window ends, its authority signs its packs again with a
   current key.

A pack that passes steps 4 to 7 is signed by the authority the entry names,
and a verifier reports the entry's `authority_id` and `authority_name`. A pack
that fails step 2, or any of steps 4 to 7, is not its authority's. What a
verifier does with an unsigned pack, or with a pack whose key it does not
hold, is its own decision.

**An authority store.** An operator may keep the authorities in a file of
their own: a store of this format whose `issuers` is empty. A verifier given
such a file takes the authorities only from it, never also from the store it
verifies records with, and reports its identity (§5) as it reports that
store's. A file given as an authority store whose `issuers` is not empty MUST
be refused, since those issuers would be trusted for nothing a reader could
see. So MUST one that holds, among its `policy_authorities`, a key whose
`key_id` equals the `key_id` of a key the other store lists under `issuers`
(exact string equality, as §2 compares keys within one store): that key would
vouch both for records and for the packs they are judged by. An
organisation that issues records and signs packs holds one key for each
role. This refusal is decided after the check of `issuers`.

**Identifiers.** A verifier SHOULD report a pack it refuses, or an authority
store it refuses, with the stable identifier below. `policy-pack-format-v0.1.md`
§4 lists the same identifiers, with the same meanings, in the same order: the
order in which the reference verifier decides them, by the steps above. A pack
the loader refuses is named by `policy-pack-format-v0.1.md` §3, between the
authority store and step 1.
- **The reference CLI** reports an unsigned pack as
  the state `unsigned`, never as `pack_signature.unsigned`, and refuses it as
  `pack_signature.unsigned_refused` only under `--require-signed-pack`, as it
  does `pack_signature.not_checked_refused`.
- **The pack-signature vectors** (`test-vectors/policy/pack-signature.json`)
  name every identifier the reference CLI refuses with: all but
  `pack_signature.unsigned`.

| Step | Identifier | Refused when |
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

## 5. Canonical form and identity

A store's **canonical form** is the document with:
- its issuers sorted by `issuer_id` (ASCII, so byte order, code-point order
  and UTF-16 order agree);
- its policy authorities sorted by `authority_id` in code-point order, the
  byte order of the UTF-8 form. An `authority_id` need not be ASCII, and for
  one that is not, UTF-16 order can differ;
- each entry's keys sorted by `key_id`;
- `valid_until` omitted when absent;
- `policy_authorities` omitted when absent or empty.

It is serialized with the JSON Canonicalization Scheme (RFC 8785, as in
`record-format-v0.1.md` §3). Its **identity** is

```
sha256:<lowercase hex of SHA-256(canonical form)>
```

Reformatting the file, reordering members, issuers, authorities or keys, and
adding an empty `policy_authorities`, change neither the identity nor any
verification result; changing any value does. A store written before
`policy_authorities` existed keeps its identity. A verifier SHOULD report the
identity of the store it used.

## 6. Design choices

Choices this format made, and why: `trust_store_version: "0.1"` (matching
`record_version`); `issuer_id` (the record's member name); `keys[]` for each
issuer (key rotation without duplicate issuer entries that could disagree);
`key_id` stored and checked against the JWK (the lookup key, and what humans
compare); no publication on a distributed ledger; and no public-key resolution
from the DID (`did:web` resolution is an HTTPS request, and a verifier fetches
nothing).

## 7. Revision history

v0.1 is unpublished; `trust_store_version` stays `"0.1"` through this
revision.

- **2026-09-11** — initial format (Phase 4, decision D7).
- **2026-09-11 — Phase 4 QA revision** after the independent Phase 4 QA
  (`QA/QA_REPORT_PHASE4.md`), before any store or passport was issued:
  - strings are sequences of Unicode scalar values: a `\u` escape of an
    unpaired surrogate is `trust_store.structure`, not `trust_store.syntax`
    (it is valid RFC 8259); non-UTF-8 bytes, CESU-8 surrogates included,
    stay `trust_store.syntax`; noncharacters are permitted (§2, §3 kinds 2
    and 4; P4-03). A store of a later version is still reported as
    `trust_store.version` when it also carries such an escape, in a value
    or in a member name (the reference loader reported the member-name case
    as structure; it now reads only the version before kind 3).

  No integer rule is needed here (P4-01): a store has no integer members.
  The loader vectors gained five cases (26 in all); no existing case
  changed.
- **2026-09-13 — policy authorities** (`docs/TASKS.md` 6.16;
  `docs/dev/phase6.md` P6-14 and P6-16; decisions A16-1 to A16-11 of
  `docs/dev/task-6.16.md`), before any store was published:
  - **New:** the optional member `policy_authorities` (§2); lookup,
    binding, revocation and the window judged at the evaluation time for a
    pack's signature, and the authority store (§4.2). Every existing store
    stays valid and keeps its identity (§5).
  - **New kinds:** `trust_store.authority_id` (kind 6) and
    `trust_store.duplicate_authority` (kind 11). The kinds after them
    renumber, and their relative order is unchanged.
  - **Wider rules:** `trust_store.duplicate_key` covers both lists, and
    `trust_store.structure` covers an authority without keys.
  - **Stated for the first time:** the nesting bound (§2, kind 2). **The
    reference loader's behaviour changed:** text nested past 127 levels was
    `trust_store.structure`, since its syntax pass had no depth limit, and it
    is now `trust_store.syntax`, even for a store of a later version.

  The loader vectors gained cases for each point
  (`test-vectors/trust-store/README.md`). No existing case changed its
  result.
  - **2026-09-14, the same task** (`docs/dev/task-6.16.md` A16-22, A16-24). No
    behaviour changed.
    - §4.2 states the payload-hash check, which needs no key, as step 2,
      before the key is looked up; the reference CLI already took it there.
    - §4.2 gains a table of the stable identifiers of a refused pack and a
      refused authority store.
    - The pack-signature vectors pin both
      (`test-vectors/policy/pack-signature.json`).
  - **2026-09-14, the same task: the QA's findings QA16-01 and QA16-04**
    (`QA/QA_REPORT_TASK_6_16.md`; `docs/dev/task-6.16.md` A16-25).
    - **Behaviour changed:** an authority store holding a key the trust store
      lists under `issuers` is refused, as `authority_store.issuer_key` (§1,
      §4.2). The reference CLI accepted it.
    - §4.2 states that the stores are checked before the pack and its
      signature, in the reference CLI's order, and lists its identifiers in
      that order, with `pack_signature.unsigned`, as
      `policy-pack-format-v0.1.md` §4 does.
    - The pack-signature vectors gained four cases; no existing case changed.
      No trust-store loader rule changed.
- **2026-09-14 — the task 10.11a QA's finding QT-01**
  (`QA/QA_REPORT_TASK_10_11A.md`; `docs/dev/fix-json-object-shape.md`), before
  any store was published.
  - **Wording only.** §3 kind 4 now names an object written as a JSON array,
    of its values in any order or of anything else. Its words "with their
    JSON types at every level" already covered it. No kind, order or
    identity rule changed, and no store that loads changed.
  - **The reference loader's behaviour changed.** It read the store, an
    issuer, a policy authority, a key or a `public_key` written as the array
    of its values, in the order of its own struct's members, and loaded the
    store. It now refuses each as `trust_store.structure`, and so does the
    reference CLI for an authority store (§4.2, step 2).
  - **Vectors.** No existing case changed.
    - The loader vectors gained six cases, each `trust_store.structure`:
      `error-structure-store-as-array`, `error-structure-issuer-as-array`,
      `error-structure-key-as-array`, `error-structure-public-key-as-array`,
      `error-structure-authority-as-array` and
      `error-structure-authority-key-as-array`.
    - The pack-signature vectors gained eight
      (`test-vectors/policy/pack-signature.json`).
- **2026-09-15 — the Verifiable Model Record** (tasks 10.11c and 10.11d),
  before any store was published. Wording only: a store holds the keys trusted
  to sign records; §6 states this format's design choices without the earlier
  internal drafts it compared them with. No member, rule, loader kind or
  identity changed, and no trust-store vector's result moved.
- **2026-09-15 — KHALM-VMR** (task 10.11f), before any store was published.
  Wording only: the reference implementation's software is named KHALM-VMR,
  a reference implementation of this standard, never the standard's own
  tool; no crate, member, rule or byte changed.
- **2026-09-16 — the test labels** (task 10.12a), before any store was
  published. The example authority store names `khalm-policy-vectors`, and
  its key is the one its label `khalm v0.1 policy-vector pack authority key
  (test-only)` now derives. No member, rule, loader kind or identity rule
  changed; the trust-store vectors keep their 52 cases and results.
