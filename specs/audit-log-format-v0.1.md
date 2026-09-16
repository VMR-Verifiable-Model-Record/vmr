# VMR Audit Log Format v0.1

**Status:** normative for this repository's implementation
(`vmr/crates/vmr-audit-log`). v0.1 published 2026-09-16 at tag `v0.1.0` of the
public repository, with the Verifiable Model Record format; its bytes do not
change from here. An editorial correction that changes no normative rule is
published as v0.1.1; anything that changes a rule, as v0.2. This text is that
first editorial correction, v0.1.1: no normative rule changed. Identified by
`https://verifiablemodel.org/schemas/audit-log/v0.1.json`, the `$id` of
`specs/audit-log-schema/v0.1.json`. Apache-2.0, as the record format is; the
test vectors are CC0-1.0.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Scope

This document defines an append-only, tamper-evident audit log and the
documents that speak about it:

| Document | Signed by | Read by |
|---|---|---|
| the audit entry (§4.1) | nobody: the log's Merkle tree and its checkpoints commit to it | whoever replays the log; an auditor inside a proof |
| the checkpoint (§6) | the log's audit key | an auditor; anyone who names a log's state |
| the inclusion and consistency proofs (§7, §8) | nobody: each carries signed checkpoints | an auditor |

Any software may write such a log. What an entry means is its **profile's**
(§5), and the core of this format knows no vendor, engine or deployment. The
profile KHALM's sovereignty enforcer writes is one of them (§5.2), set down
here so that anyone can check that enforcer's log with free software.

A record may name a checkpoint as the signed statement
`vmr-audit-checkpoint-v1` (record format §7.7), whose digest is the
checkpoint's signed payload (§3).

Not defined here:

- what a log's writer does besides writing it, and what it refuses;
- how a log is stored, rotated, shipped or retained;
- the record (`specs/record-format-v0.1.md`), which this format meets only at
  that statement reference.

## 2. Conventions

These apply to every document of this format unless a section says
otherwise. Another format MAY adopt them by reference, with its own refusal
ids.

1. **Text.** A document is UTF-8 JSON (RFC 8259) without a byte order mark.
2. **Size.** Each section gives a document's largest size in bytes. A
   larger document is refused before it is parsed.
3. **Nesting.** A document nests arrays and objects at most 127 levels deep,
   the outermost counting as the first. A deeper document is refused as
   syntax, before any member is read. No valid document nests more than six
   levels.
4. **Members.** Every object is closed: a member this document does not name
   is refused, and so is a member that appears twice, wherever the object is.
   Optional members are omitted when they have no value, never `null`.
   - **Finding a repeat.** A reader finds a repeated member in the text. A
     JSON reader that keeps one of the two values and drops the other does
     not find it.
   - **Its refusal.** A repeat is refused after the version (rule 10), as
     the structure refusal of the document whose object repeats the member:
     `checkpoint.structure` or `audit_proof.structure`. A repeat inside a
     checkpoint that a proof carries is the checkpoint's
     `checkpoint.structure` (§7, §8). A format that adopts these
     conventions names its own ids. An audit
     entry is the exception: a repeat in its line is
     `audit_entry.not_canonical` (§4.4), whether the line is read from a log
     or from a proof.
5. **Integers.** A member of integer type is a JSON number without a fraction,
   an exponent or a minus sign, from 0 to 2^53 − 1, unless its row states a
   narrower range.
6. **Timestamps** are the record's profile (record format §2 rule 7):
   `YYYY-MM-DDTHH:MM:SSZ`, UTC, one-second resolution.
7. **Hashes** are `sha256:` followed by 64 lower-case hexadecimal digits: the
   SHA-256 of the bytes the row names.
8. **Identifiers** of the form `urn:uuid:…` are lower-case canonical UUID URNs
   (record format §2).
9. **Key ids** are RFC 7638 SHA-256 thumbprints in RFC 9278 URN form, and a
   **JWK** is an EC P-256 public key, both as in record format §5.
10. **Types.** Each document names its version and type in two members,
    `<name>_version` and `<name>_type`. They are read before the rest of the
    document; a document whose version or type is not this revision's is
    refused as version, whatever else it holds.
11. **Refusals** have stable ids. Each table of checks lists them in the
    order they run; a document is refused with the first that fails.

## 3. Signed documents

The checkpoint (§6) carries a top-level `signature` section. The
construction is the policy-pack format's (`specs/policy-pack-format-v0.1.md`
§4). A format whose own documents are signed the same way MAY adopt this
section by reference, with its own key rule in check 2 and its own refusal
ids.

- **The signed payload** is the document as received, parsed as JSON, with
  its top-level `signature` member removed, serialised in the JCS form of
  RFC 8785.
- **The payload hash** is the hash (§2 rule 7) of the signed payload's UTF-8
  bytes. It names a document's content independently of its layout, whether
  or not it is signed.
- **The `signature` section**:

  | Member | Value |
  |---|---|
  | `algorithm` | `"ES256"` |
  | `signature` | `"base64url:"` followed by the unpadded base64url of the 64-byte `r ‖ s`, low-s (record format §5.2) |
  | `signed_payload_hash` | the payload hash |
  | `signing_key_id` | the key id of the signing key |

- **Checking a signature**, in this order:
  1. **section:** the section is present; `algorithm` is `ES256`;
     `signed_payload_hash` is the recomputed payload hash; `signature`
     decodes to exactly 64 bytes;
  2. **key:** the key is the one the document may be signed with: for the
     checkpoint, the pinned audit key. `signing_key_id` MUST be that key's
     key id;
  3. **signature:** the ES256 signature over the signed payload's bytes
     verifies under the key, and `s` is low.

  A signature over any other bytes does not verify: the document with its
  `signature` member, a re-serialisation of a typed model, a COSE
  `Sig_structure`.
- **Domain separation.** The `<name>_type` member is inside the signed payload
  and is checked (§2 rule 10) before the signature. Every document named here
  has a disjoint closed structure, and a signer holds each key in one role
  only (§9): an audit key signs its log's checkpoints and nothing else.

## 4. The audit log

### 4.1 The entry

One line of the log. Its text is the JCS form (RFC 8785) of the entry object,
at most 65 536 bytes.

| Member | Type | Rule |
|---|---|---|
| `log_version` | string | `"0.1"` |
| `index` | integer | the entry's position in the log, from 0 |
| `previous_root` | string | a hash: the root (§4.3) of the entries before this one; for index 0, the empty tree's root |
| `recorded_at` | string | a timestamp: the log writer's clock when it wrote the entry |
| `kind` | string | one of §5.2's kinds |
| `detail` | object | the members §5.2 gives the kind, and no other |

An entry names no log: the chain of `previous_root` and the checkpoints that
commit to the tree (§6) bind it to its log.

### 4.2 The file

- **Lines.** The log is a file of entries, each its JCS text followed by one
  line feed (U+000A). JCS escapes every control character, so an entry never
  contains a raw line feed.
- **Append only.** A writer only appends. The one exception is §4.4's
  recovery of a torn tail.
- **The leaf** of an entry is its JCS text without the line feed.

### 4.3 The tree

The log's Merkle tree is RFC 9162 §2.1.1's, over the leaves in index order:

```
leaf(d)    = SHA-256(0x00 ‖ d)
node(l, r) = SHA-256(0x01 ‖ l ‖ r)
MTH({d0})  = leaf(d0)
MTH(D[n])  = node(MTH(D[0:k]), MTH(D[k:n]))   for n > 1, k the largest power of two below n
```

- **The empty tree.** Its root is `SHA-256(0x02)`, as in record format §6.3,
  **not** RFC 9162's `SHA-256("")`. It appears only as the `previous_root` of
  entry 0. No checkpoint is made of the empty tree, and a verifier refuses one
  (§6, refusal 5).
- **The record format's tree.** For every non-empty size this is record
  format §6.3's tree: pairing nodes left to right and promoting an odd trailing node
  gives the same root and the same inclusion proofs.

### 4.4 Reading a log

A reader checks every line, in order, with the first failure refusing the log:

| # | Id | Refused when |
|---|---|---|
| 1 | `audit_entry.size` | a line is longer than 65 536 bytes |
| 2 | `audit_entry.syntax` | a line is not UTF-8 JSON, or nests past 127 levels |
| 3 | `audit_entry.not_canonical` | a line is not the JCS form of the JSON it holds (a repeated member, whitespace, another number or string spelling) |
| 4 | `audit_entry.version` | a line is not an object whose `log_version` is `"0.1"` |
| 5 | `audit_entry.structure` | a member is unknown, missing, `null` or of another type, the kind is unknown, or the detail breaks §5.2 |
| 6 | `audit_log.index` | a line's `index` is not its position |
| 7 | `audit_log.previous_root` | a line's `previous_root` is not the root of the lines before it |
| 8 | `audit_log.torn_tail` | after every complete line checks, bytes remain that no line feed ends |

Refusals 1 to 5 also apply to an entry inside an inclusion proof (§7).

**Recovery.** A crash can leave only one kind of damage: a last line without
its line feed (refusal 8). A writer MAY recover from exactly that: it moves
those bytes aside, truncates the log to its last complete line, and appends a
`log.recovered` entry naming their offset, their length and their hash. Any
other refusal is not repaired.

## 5. Profiles

### 5.1 A profile

The core of an entry (§4.1) is the same for every log. Its `kind`, and the
members of its `detail`, are a **profile's**: one writer's vocabulary of what
it records and what each kind carries.

- **A profile's name** is `<owner>.<name>`, lower case.
  `khalm-vmr.enforcer` (§5.2) is this revision's only registered profile.
  Another writer names its own, and nothing in §§1 to 4 or 6 to 9 changes.
- **No member of a log names its profile.** A reader is given the profile with
  the audit key it pins: a log's bytes commit to its entries, not to what they
  mean.
- **The core profile** is what a reader uses when it does not have the
  writer's: every kind §4.1's grammar allows, with any object as its `detail`.
  It checks a log's shape, its chain, its signatures and its proofs, and
  nothing about the meaning of an entry. A reader that accepts a log under the
  core profile has checked less, and MUST NOT report more.
- **A profile refuses with `audit_entry.structure`** (§4.4 refusal 5),
  whatever its rule: one reader reports one refusal id.

### 5.2 The `khalm-vmr.enforcer` profile

The kinds KHALM's sovereignty enforcer writes. Its enforcement bundle and its
export token are its own documents, defined in
`specs/sovereignty-format-v0.1.md`, **which is not part of the Community
edition**; this profile names them where an entry records one, and needs
nothing from that document to be read. A reader of this document, and an
implementation of this profile, need never see it.

#### The kinds

Types in the detail: **boot time** is an object `{"seconds": integer,
"nanoseconds": integer 0–999999999}`, a time on the kernel's `CLOCK_BOOTTIME`;
**u64** is a string of decimal digits without leading zeros naming an integer
from 0 to 2^64 − 1; **u32** is an integer from 0 to 4294967295; **refusal** is
a refusal id, a string matching `^[a-z_]+\.[a-z_]+$`; **text** is a string of
at most 4096 bytes. A member marked `?` is optional.

**Process and user ids.** `tgid` and `uid` are the ids the kernel's initial
namespaces give the task that made the attempt. `tgid` is its thread group id
in the initial PID namespace (what `bpf_get_current_pid_tgid` reports). `uid`
is its user id in the initial user namespace. Inside a PID or user namespace
(a container, or a WSL distribution) the process sees other numbers, and
`getpid()` there differs from `tgid`. An id is reused once its process exits,
so `tgid` with `boot_time` names a process only at that moment.

| Kind | Detail members |
|---|---|
| `enforcer.started` | `audit_key_id` (key id), `bundle_id` (UUID URN), `bundle_payload_hash` (hash), `record_id` (UUID URN), `model_hash` (hash), `mechanism` (`^[a-z0-9-]{1,64}$`), `object_version` (u32), `boot_id` (`^[0-9a-f-]{1,64}$`) |
| `enforcer.refused` | `refusal`, `detail` (text) |
| `enforcer.stopped` | none: the detail is `{}` |
| `bundle.loaded` | `bundle_id` (UUID URN), `bundle_payload_hash` (hash), `signing_key_id` (key id) |
| `bundle.refused` | `refusal`, `detail` (text) |
| `key.operation` | `operation` (`"load_audit_key"` or `"load_policy_key"`), `result` (`"ok"` or `"failed"`), `key_id?` (key id), `detail?` (text) |
| `egress.denied` | `hook` (`"socket_connect"` or `"socket_sendmsg"`), `family` (u32), `protocol` (u32), `address?` (§5.2's canonical address), `port?` (integer 0–65535), `boot_time`, `cgroup_id` (u64), `tgid` (u32), `uid` (u32) |
| `egress.allowed` | `hook` (as above), `destination` (§5.2), `grant` (u32), `boot_time`, `cgroup_id` (u64), `tgid` (u32), `uid` (u32) |
| `socket.create_denied` | `family` (u32), `protocol` (u32), `boot_time`, `cgroup_id` (u64), `tgid` (u32), `uid` (u32) |
| `socket.listen_denied` | `family` (u32), `boot_time`, `cgroup_id` (u64), `tgid` (u32), `uid` (u32) |
| `file.open_denied` | `device` (u64), `inode` (u64), `boot_time`, `cgroup_id` (u64), `tgid` (u32), `uid` (u32) |
| `export.granted` | `token_id` (UUID URN), `token_payload_hash` (hash), `signing_key_id` (key id), `destination` (§5.2), `not_before` (timestamp), `not_after` (timestamp), `deadline` (boot time), `grant` (u32) |
| `export.refused` | `refusal`, `detail` (text), `token_id?` (UUID URN), `signing_key_id?` (key id), `destination?` (§5.2) |
| `export.install_failed` | `token_id` (UUID URN), `grant` (u32), `detail` (text) |
| `events.dropped` | `count` (integer, at least 1) |
| `events.malformed` | `length` (integer), `refusal` |
| `log.recovered` | `offset` (integer), `length` (integer, at least 1), `sha256` (hash of the bytes moved aside) |

`address` and `port` of `egress.denied` are both present, or both absent when
the attempt named no IPv4 or IPv6 address. An `export.refused` entry records
what of the token could be read before the refusal, and never key material.

#### The destination object

| Member | Type | Rule |
|---|---|---|
| `protocol` | string | `"tcp"` or `"udp"` |
| `address` | string | an IPv4 address in dotted-decimal form, or an IPv6 address in the text form of RFC 5952 |
| `port` | integer | 1 to 65535 |

- **Canonical address.** The address MUST be written in its one canonical
  text: IPv4 as four decimal octets without leading zeros; IPv6 in RFC 5952's
  form (lower case, the longest run of zero groups, and the first of equal
  runs, compressed to `::`, a single zero group not compressed).
- **Refused addresses:** the unspecified addresses `0.0.0.0` and `::`, and
  every IPv4-mapped IPv6 address (`::ffff:0:0/96`), which MUST be written as
  its IPv4 address.
- **Matching an attempt.** A destination is never written as an IPv4-mapped
  address, but a Runtime on a dual-stack socket can connect or send to one.
  - **As its IPv4 address.** An enforcer matches such an attempt as the IPv4
    address it maps: `::ffff:a.b.c.d` as `a.b.c.d`, that is, an address
    whose first 80 bits are zero and next 16 bits are one.
  - **In the kernel.** The kernel program normalises the socket address in
    this way before it looks up a grant. It records the attempt with family
    `AF_INET` (2) and the IPv4 address (§5.2's `egress.denied` and
    `egress.allowed`).
  - **Every other IPv6 address** is matched as written, among them the
    IPv4-compatible `::a.b.c.d` and the NAT64 prefix `64:ff9b::/96`.

#### The text form

A destination's text form is the protocol, `://`, the address (an IPv6
address in square brackets), `:` and the port in decimal:

```
tcp://203.0.113.7:443
udp://[2001:db8::1]:53
```

Every destination has exactly one text form, and two destinations are equal
exactly when their text forms are.

## 6. The checkpoint

The audit key's signed statement of the log's size and root. At most 16 384
bytes. `vmr.audit-checkpoint` is a `_type` value (§2 rule 10), not a statement
format of the record format's §4.7: a record names a checkpoint with the
registered format `vmr-audit-checkpoint-v1`.

| Member | Type | Rule |
|---|---|---|
| `checkpoint_version` | string | `"0.1"` |
| `checkpoint_type` | string | `"vmr.audit-checkpoint"` |
| `log_id` | string | a key id: the audit key's |
| `tree_size` | integer | the number of entries the root covers |
| `root_hash` | string | a hash: the root (§4.3) over the first `tree_size` entries |
| `issued_at` | string | a timestamp: the log writer's clock |
| `signature` | object | §3, by the audit key |

**Checks**, in order, under the auditor's pinned audit key:

| # | Id | Refused when |
|---|---|---|
| 1 | `checkpoint.size` | it is larger than 16 384 bytes |
| 2 | `checkpoint.syntax` | it is not UTF-8 JSON, or nests past 127 levels |
| 3 | `checkpoint.version` | it is not an object whose `checkpoint_version` is `"0.1"` and whose `checkpoint_type` is `"vmr.audit-checkpoint"` |
| 4 | `checkpoint.structure` | a member is unknown, repeated, missing (except `signature`), `null` or of another type, or breaks a rule of this section |
| 5 | `checkpoint.empty_tree` | `tree_size` is 0 |
| 6 | `checkpoint.signature_section` | §3 check 1 fails |
| 7 | `checkpoint.wrong_key` | `log_id` or `signing_key_id` is not the pinned audit key's key id |
| 8 | `checkpoint.signature_invalid` | §3 check 3 fails |

A checkpoint inside a proof is checked from check 3 on; checks 1 and 2 are
the proof's. A checkpoint a writer keeps is also checked against its log:
the log holds at least `tree_size` entries and its root over them is
`root_hash`.

## 7. The inclusion proof

Shows that one entry is in a log a checkpoint covers. At most 262 144 bytes.

| Member | Type | Rule |
|---|---|---|
| `proof_version` | string | `"0.1"` |
| `proof_type` | string | `"vmr.audit-inclusion-proof"` |
| `checkpoint` | object | a checkpoint (§6) |
| `leaf_index` | integer | the entry's index |
| `entry` | string | the entry's exact JCS text (§4.1), without a line feed |
| `audit_path` | array of hashes | at most 64: RFC 9162 §2.1.3.1's `PATH(leaf_index, D[tree_size])`, the sibling nearest the leaf first |

**Verification**, in order, under the pinned audit key. It needs no clock and
no file:

| # | Id | Refused when |
|---|---|---|
| 1 | `audit_proof.size` | it is larger than the document's limit |
| 2 | `audit_proof.syntax` | it is not UTF-8 JSON, or nests past 127 levels |
| 3 | `audit_proof.version` | it is not an object whose `proof_version` is `"0.1"` and whose `proof_type` is the document's |
| 4 | `audit_proof.structure` | a member is unknown, repeated, missing, `null` or of another type, or breaks a rule of this section |
| — | `checkpoint.*` | the checkpoint fails §6's checks 3 to 8; the refusal is the checkpoint's own id |
| 5 | `audit_proof.index` | `leaf_index` is not below the checkpoint's `tree_size` |
| — | `audit_entry.*` | the entry fails §4.4's checks 1 to 5; the refusal is the entry's own id |
| 6 | `audit_proof.entry_index` | the entry's `index` is not `leaf_index` |
| 7 | `audit_proof.path` | the root recomputed from the entry's leaf and `audit_path` (RFC 9162 §2.1.3.2) is not `root_hash`, or `audit_path` has another length than the tree's shape at `leaf_index` requires |

For the consistency proof, rows 1 to 4 apply with its own limit and type.

Since `tree_size` is signed with `root_hash`, a verifier takes the tree's
shape from them, never from the proof, and a padded, truncated or re-indexed
path fails row 7.

## 8. The consistency proof

Shows that a log a later checkpoint covers extends the log an earlier one
covered: the entries under the first are unchanged. At most 32 768 bytes.

| Member | Type | Rule |
|---|---|---|
| `proof_version` | string | `"0.1"` |
| `proof_type` | string | `"vmr.audit-consistency-proof"` |
| `from` | object | a checkpoint (§6): the earlier |
| `to` | object | a checkpoint (§6): the later |
| `proof` | array of hashes | at most 128: RFC 9162 §2.1.4.1's `PROOF(from.tree_size, D[to.tree_size])` |

**Verification**, in order, under the pinned audit key, after §7's rows 1 to
4:

| # | Id | Refused when |
|---|---|---|
| — | `checkpoint.*` | `from`, then `to`, fails §6's checks 3 to 8 |
| 8 | `audit_proof.order` | `from.tree_size` is larger than `to.tree_size` |
| 9 | `audit_proof.consistency` | RFC 9162 §2.1.4.2's verification fails; when the two sizes are equal, the proof MUST be empty and the two roots equal |

## 9. Keys

- **Public key files.** A pinned key (here, a log's audit key) is given to a
  reader as `vmr key export` writes it: an object with exactly `key_id` and
  `public_key`, where `key_id` is the key id of `public_key` (`docs/CLI.md`).
- **One key, one role.** The audit key signs its log's checkpoints and nothing
  else, and a checkpoint's `log_id` is that key's key id: one key, one log. A
  key that signs a document of another format MUST NOT be a log's audit key.
- **Rotation.** A log is its key's. Rotating the audit key starts a new log,
  and no consistency proof spans the two: an auditor pins both keys and reads
  two logs.

## 10. Conformance

An implementation conforms when, for every case of
`specs/test-vectors/audit-log/`, it accepts what the case accepts and refuses
with the refusal id the case names. A case that names a profile is for an
implementation that has it; the others are the core's.

## 11. Revision history

| Date | Change |
|---|---|
| 2026-09-16 | First revision. The audit log leaves `specs/sovereignty-format-v0.1.md` (its §2, §3, §7 to §10, and the destination object of §4.1 and §4.2) for this document, published with the record format, and the entry kinds become a profile (§5), KHALM's enforcer being the first. No member, check, refusal or signed byte changed: the vectors of the four moved sections pass unchanged, in `specs/test-vectors/audit-log/` |
| 2026-09-16 | The array caps of §7 and §8 are enforced by the reference implementation, which read them from the schema and not from the document before (the release QA's QR-06). An `audit_path` above 64 elements, or a `proof` above 128, is refused `audit_proof.structure` before the path is walked, where it was refused `audit_proof.path` after it. Two vectors were added, `inclusion-path-above-64` and `consistency-proof-above-128`. No member, limit, refusal id or signed byte changed |
