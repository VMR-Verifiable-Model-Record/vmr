# Audit log profile `vmr.agent` test vectors v0.1

The conformance cases of
[`../../audit-profile-agent-v0.1.md`](../../audit-profile-agent-v0.1.md) (§6).
One file, `cases.json`. The core format's own cases,
[`../audit-log/`](../audit-log/), are unchanged by this profile.

An implementation of the profile conforms when, for every entry case, it
accepts what the case marks `"accept"` and refuses the others with the refusal
id in `"expect"` (always `audit_entry.structure`, core §5.1), and when, for
every digest case, it computes the case's session key, item key and digest.

These vectors are CC0-1.0, as the other test vectors of this repository are.

## Structure

- `entries` — one line each, read as a log of one entry (index 0, the empty
  tree's root as its `previous_root`), so the profile's checks are what decide
  it. `raw` is the line without its line feed. There is an accepting case for
  every kind of §4, and a refusing case for every check of §4.6: `rule` names
  the check a refusing case breaks, and every listed member (`outcome`,
  `decision`, `scope`) has a case whose value is outside its list. Every line
  is an entry of the core profile: a reader without this profile accepts every
  case.
- `digests` — §3's keyed digest. Each case gives the content secret and the
  label it is derived from, a `session_id`, the entry's kind, the member and
  the entry's index, the item key's `label`, and the content: `content_text`
  when the runtime received the item as bytes or text (the bytes are its UTF-8,
  as received, before any parsing), or `content_json` when it received the item
  only as a parsed JSON value (the bytes are its JCS form). `content_hex` is
  the bytes digested, in both cases. The expected `session_key`, `item_key`
  (lower-case hexadecimal) and `digest` follow.

The cross-entry rules (§4.1's reachable tools, §4.2's order of a call's
entries, §4.4's approval gate) are the writer's: a reader reports where a log
breaks them and never refuses it, so no case here refuses for them.

## The keys

The content secret is derived from a fixed label, for tests only:
`sha256(label)` is the 32-byte secret, as the audit-log vectors derive their
keys. The entry cases' digests are real keyed digests under the same secret.
The digest cases' expected values were computed once with an implementation
that shares no code with this repository's (Python's `hmac` and `hashlib`),
and the generator refuses to write a digest this build computes differently.

## Regenerating

    VMR_WRITE_VECTORS=1 cargo test -p vmr-audit-log --test agent_vectors -- --ignored

in its own commit. `agent_vectors_are_reproducible` fails when the committed
bytes differ from a fresh generation; every case is replayed, the cases are
held to cover every kind, rule and listed value, and the schema
[`../../audit-profile-agent-schema/v0.1.json`](../../audit-profile-agent-schema/v0.1.json)
is held to the profile, by `vmr/crates/vmr-audit-log/tests/agent_vectors.rs`.
