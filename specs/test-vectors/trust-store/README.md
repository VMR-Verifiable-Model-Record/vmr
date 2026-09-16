# Trust store loader vectors (v0.1)

For [`../../trust-store-format-v0.1.md`](../../trust-store-format-v0.1.md).
Each case in [`cases.json`](cases.json) is a trust-store file (`input`: `text`
or `hex`, then `append_spaces` spaces if present) and the result a conforming
loader must produce:

- `{"result": "ok", "sha256": …}` — the store loads, and its canonical
  identity (§5: issuers sorted by `issuer_id`, policy authorities by
  `authority_id` in code-point order, each entry's keys by `key_id`, an empty
  `policy_authorities` omitted, JCS, SHA-256) is exactly this. Reordered and
  reformatted copies of one store share one identity;
- `{"result": "error", "kind": …}` — the store is rejected with this kind
  (§3). Every one of the 13 kinds has at least one store. A case names its
  kind by id, never by its number in §3.

52 cases: 13 stores that load and 39 that are rejected.

Added on 2026-09-11 (no earlier case
changed): noncharacters in `issuer_name`, raw and escaped, load with one
identity; a `\u` escape of a lone surrogate is `trust_store.structure`;
surrogate bytes in CESU-8 form are `trust_store.syntax`; and a store of
version `0.2` that also has a member named by a lone surrogate is still
`trust_store.version` (kind 3 is checked over the whole store before kind 4).
The raw noncharacters and the CESU-8 bytes are given as `hex`.

Added with policy authorities (2026-09-13): 20 cases,
appended after the first 26, none of which changed its result.

- **Stores that load (6):**
  - `ok-policy-authorities`: one authority, holding key P;
  - `ok-policy-authorities-empty`: an empty list, with `ok-basic`'s identity;
  - `ok-two-policy-authorities` and `ok-two-policy-authorities-reordered`:
    one identity for both orders;
  - `ok-authority-store`: no issuers and one authority, the kind of store an
    authority store is (§4.2);
  - `ok-policy-authorities-code-point-order`: authorities named U+1F600 and
    U+FF21, sorted by code point. UTF-16 code-unit order would give another
    identity.
- **An authority's own refusals (7):**
  - without keys, with an unknown member, or `policy_authorities: null`
    (`trust_store.structure`);
  - an empty `authority_id` (`trust_store.authority_id`);
  - an authority key's bad timestamp and its mismatched key id: the key rules
    apply to every key;
  - two authorities with one id (`trust_store.duplicate_authority`).
- **A key in one list only (2):** key A under an issuer and an authority, and
  key P under two authorities (`trust_store.duplicate_key`).
- **Rule order (2):** an empty `authority_id` before an issuer key's bad
  timestamp (kind 6 before 7), and two authorities with one id holding one
  key (kind 11 before 12).
- **The nesting bound (3):** text nested 127 levels is read and refused for
  its unknown member (`trust_store.structure`). Text nested 128 levels is
  `trust_store.syntax`, under version `0.2` too.

Added on 2026-09-14 (trust-store
format §3 kind 4 and §7): 6 cases, appended after the first 46,
none of which changed its result.

- **What each case does.** It writes one object of a store that loads as the
  array of its values, in the order of the schema's `properties` (the order in
  which a parser that reads a record from the array of its fields takes them),
  so a loader with that fault loads each store.
- **Each is `trust_store.structure`:**
  - `error-structure-store-as-array`: the store itself;
  - `error-structure-issuer-as-array`;
  - `error-structure-key-as-array`;
  - `error-structure-public-key-as-array`;
  - `error-structure-authority-as-array`;
  - `error-structure-authority-key-as-array`.

The issuer keys are the test-only derived keys of
[`../verify/README.md`](../verify/README.md). Keys P, Q and R, the
authorities' keys, are derived the same way from the labels `khalm v0.1 trust-store-vector policy authority key P`, `khalm v0.1 trust-store-vector policy authority key Q` and
`khalm v0.1 trust-store-vector policy authority key R`, and are just as test-only. Generated with the verification vectors,
by their generator (`VMR_WRITE_VECTORS=1 cargo test -p vmr-verify --test vectors -- --ignored`), which recomputes each
expected identity from the §5 rule rather than reading it from the loader;
never hand-edited. Regenerate as described there.
