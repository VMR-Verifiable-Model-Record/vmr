# VMR Audit Log Profile `vmr.agent` v0.1

**Status:** normative for this repository's implementation
(`vmr/crates/vmr-audit-log`, `src/profiles/vmr_agent.rs`). v0.1, published
2026-09-30 with release v0.1.5 of the public repository; its bytes do not
change from here. An editorial correction that changes no normative rule is
published as v0.1.1; anything that changes a rule, as v0.2.

`vmr.agent` is a profile of the VMR audit log format v0.1 (`specs/audit-log-format-v0.1.md`, "the core"),
named under its §5.1: an entry of this profile is an audit entry (core §4.1)
whose `kind` and `detail` follow the rules below. Nothing in the core
changes, and a reader without this profile still checks such a log's shape,
chain, signatures and proofs under the core profile. Identified by
`https://verifiablemodel.org/schemas/audit-profile-agent/v0.1.json`, the `$id`
of `specs/audit-profile-agent-schema/v0.1.json`. Apache-2.0; the test vectors
are CC0-1.0.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Scope

This profile records what an agent runtime decided about the tool calls a
model proposed: which tools a session could reach, what the model proposed,
which gate permitted or refused it, whether a person approved it, and whether
it ran. Any runtime that makes such decisions may write it, whoever made the
runtime and whichever model it runs.

**It records decisions, not content.** No member holds a prompt, an
instruction, a tool's arguments, schema or result, or anything the model
wrote. Content appears only as a keyed digest (§3), which a reader without the
deployment's secret cannot reverse, however short or guessable the content
is. A log of this profile is written to be handed to an auditor from a
deployment whose conversations do not leave the device.

Not defined here:

- how a runtime makes its decisions, or what its gates are built from;
- what its policy document holds: the profile names it by hash;
- how a log is stored, shipped, rotated or retained (core §1).

## 2. Terms and types

- A **session** is one conversation or task the runtime runs, from its start
  to its end, named by a `session_id`.
- A **turn** is one request to the model: one generation. A turn's number,
  `turn`, counts a session's requests from 0.
- A **call** is one tool call the model proposed. A call's number, `call`,
  counts a session's proposals from 0, in the order the model made them.

From the core: **hash**, **UUID URN** and **integer** (§2). And:

| Type | Rule |
|---|---|
| **u64** | a string of decimal digits without leading zeros naming an integer from 0 to 2^64 − 1 |
| **refusal** | a refusal id: a string matching `^[a-z_]+\.[a-z_]+$` |
| **text** | a string of at most 4096 bytes, unless its row gives a lower limit |
| **name** | a string matching `^[A-Za-z0-9_./:-]{1,128}$` |
| **gate** | a string matching `^[a-z][a-z_]{0,63}$` (§4.3) |
| **digest** | `"hmac-sha256:"` followed by 64 lower-case hexadecimal digits (§3) |
| **person** | a string matching `^[A-Za-z0-9_.:|+=/-]{1,128}$` (§4.4) |

## 3. Keyed digests

A plain SHA-256 of a short or guessable item (an amount, an address, "yes")
is reversed by hashing candidates until one matches. Every digest of content
in this profile is therefore keyed with a secret the log never holds.

- **The content secret** is 32 bytes the writer draws at random when it
  starts a log, and keeps on the device beside the log's audit key. It is not
  the audit key, never appears in a log, and belongs to one log.
- **The session key** of a session is
  `HMAC-SHA-256(content secret, session_id)`, over the UTF-8 bytes of the
  whole `session_id`, `urn:uuid:` included.
- **The item key** of one digest member of one entry is
  `HMAC-SHA-256(session key, label)`. The label is the ASCII bytes of
  `<kind>/<member>/<index>`: the entry's kind, the member's name, and the
  entry's `index` (core §4.1) in decimal without leading zeros. Example:
  `call.proposed/arguments_digest/1043`. The core makes every `index` unique
  in its log, so no two digests share a label.
- **The digest** is `hmac-sha256:` followed by the lower-case hexadecimal of
  `HMAC-SHA-256(item key, content)`. Every key here is 32 bytes.
- **The content** is bytes:
  - when the runtime received the item as bytes or text (the text the model
    generated for a call's arguments, a tool's raw output), those bytes, as
    received, before any parsing;
  - when it received the item only as a parsed JSON value (a tool-use object
    from a model service, a JSON-RPC result), the UTF-8 bytes of its JCS form
    (RFC 8785).

  A holder that keeps content for disclosure keeps these bytes.

**Disclosure** (informative). To show that some content is what an entry
committed to, the holder gives the item key and the content; anyone recomputes
the digest and finds it in the entry, which a signed checkpoint covers. An item
key reveals nothing about any other item. A session key opens every item of
its session to guessing, and the content secret every session of the log, so
a holder discloses the narrowest key that answers the question. Destroying the
content secret, and every session key given out, makes every digest in the
log permanently impossible to open.

## 4. The kinds

`session_id` (UUID URN) is the runtime's id for a session, unique within the
log. Every kind carries it, except `events.dropped` and `log.recovered`, and
the two policy kinds, where it is absent for a policy the runtime loads for
every session. Sessions may interleave in one log. Within a session, entries
appear in the order the runtime made the decisions they record.

A member marked `?` is optional. **No text member carries session content**:
`runtime`, `model` and `detail` name things and reasons, never a prompt, an
argument, a result or a path that holds a user's name.

### 4.1 Sessions, policies and tools

| Kind | Detail members |
|---|---|
| `session.started` | `session_id`, `runtime` (text, at most 256 bytes: the runtime's name and version as it reports them), `model` (text, at most 256 bytes: the model's name as the runtime knows it, never a file path), `model_hash?` (hash: the model's `model_hash`, record format §7.3), `record_id?` (UUID URN: the record the runtime checked before it loaded the model), `configuration_hash` (hash), `seed?` (u64), `parent_session_id?` (UUID URN), `parent_call?` (integer) |
| `session.ended` | `session_id`, `outcome` (`"completed"`; `"stopped"` by a person; `"terminated"` by the runtime, at a limit or a shutdown; or `"failed"`), `stopped_by?` (person) |
| `policy.loaded` | `session_id?`, `policy_hash` (hash of the policy document's bytes as the runtime loaded them) |
| `policy.refused` | `session_id?`, `policy_hash?` (hash), `refusal`, `detail` (text) |
| `tool.registered` | `session_id`, exactly one of `tool` (name) and `tool_digest` (digest), `provider?` (name), `schema_digest?` (digest of the tool's argument schema) |
| `tool.unregistered` | `session_id`, exactly one of `tool` (name) and `tool_digest` (digest), `provider?` (name) |

- `configuration_hash` is the hash of the session's generation settings
  (sampling parameters, limits) in the runtime's own serialisation. It MUST NOT
  cover a prompt, an instruction or any other content: those are content.
- `parent_session_id` and `parent_call` name the session and call that
  started this one, for a runtime that runs a sub-agent as its own session.
  `parent_call` is present only with `parent_session_id`.
- `stopped_by` is present only when `outcome` is `"stopped"`.
- `provider` names where a tool comes from (a tool server, a plug-in), so two
  tools of one name are told apart.
- A tool is written as `tool` when its name is a **name**, and otherwise as
  `tool_digest`.
- The tools a session could reach at a point are those its `tool.registered`
  entries named before that point, less those a later `tool.unregistered`
  entry of the session named with the same `tool` and `provider`.

### 4.2 Turns and calls

| Kind | Detail members |
|---|---|
| `turn.started` | `session_id`, `turn`, `input_digest?` (digest of what the turn added to the model's context: the user's message, or the tool results fed back), `grammar_digest?` (digest of the constraint applied to the turn's generation), `model?` (text, at most 256 bytes), `model_hash?` (hash) |
| `call.proposed` | `session_id`, `call`, `turn`, exactly one of `tool` (name) and `tool_digest` (digest), `arguments_digest` (digest) |
| `gate.decided` | `session_id`, `call`, `gate`, `decision` (`"permitted"` or `"refused"`), `refusal?` |
| `call.executed` | `session_id`, `call`, `outcome` (`"ok"` or `"error"`), `result_digest?` (digest) |
| `call.refused` | `session_id`, `call`, `gate`, `refusal` |

- `model` and `model_hash` of `turn.started` are present when the turn went
  to another model than the session's, for a runtime that routes between
  models.
- `refusal` of `gate.decided` is present exactly when `decision` is
  `"refused"`.
- A writer names the proposed tool as `tool` only when the session could
  reach a tool of that name (§4.1). Any other proposed name is model output,
  and is written as `tool_digest`.
- Each `call` of a session is proposed once: one `call.proposed` per call.
- A call's `gate.decided` entries come after its `call.proposed`, in the
  order the gates ran. A call ends in `call.refused`, or in one
  `call.executed` for each attempt to run it, in order; nothing of the call
  follows `call.refused`.

### 4.3 Gates

A gate is a check a proposed call passes before it runs. Five gate names are
registered; any other is the writer's own, and a reader shows it as written.
A writer's own refusal ids SHOULD be `<gate>.<reason>`, which the gate type
allows.

| Gate | Meaning |
|---|---|
| `grammar` | the constraint applied during generation (`grammar_digest`), checked against the proposal |
| `dispatch` | the check of a proposal against the tools the session could reach and their argument schemas |
| `policy` | the check of a proposal against the session's policy document |
| `guard` | a check of a proposal against the session's own context, such as what the user asked for |
| `approval` | a person's decision (§4.4) |

Registered refusal ids, so that logs from different runtimes read alike. A
writer uses one of these when it fits, and its own otherwise.

| Refusal | Meaning |
|---|---|
| `dispatch.unknown_tool` | the proposal names no tool the session could reach |
| `dispatch.bad_arguments` | the arguments do not parse, or do not match the tool's schema |
| `policy.forbidden` | the session's policy forbids the call |
| `guard.not_requested` | the call does not follow from the session's context |
| `approval.denied` | a person refused the call |
| `approval.timed_out` | nobody answered in time |

### 4.4 People

| Kind | Detail members |
|---|---|
| `approval.requested` | `session_id`, `call`, `presented_digest?` (digest of what the person was shown) |
| `approval.granted` | `session_id`, `call`, `approver` (person), `latency_ms` (integer), `scope?` (`"call"`, `"tool"` or `"session"`), `arguments_digest?` (digest) |
| `approval.denied` | `session_id`, `call`, `approver` (person), `latency_ms` (integer) |
| `approval.timed_out` | `session_id`, `call`, `waited_ms` (integer) |

- **The approval gate.** A writer records a person's answer as one of these
  entries, then the `approval` gate's `gate.decided`: permitted after
  `approval.granted`, refused after `approval.denied` (`approval.denied`) or
  `approval.timed_out` (`approval.timed_out`).
- **Overriding a refusal.** A person who lets a call go on after another gate
  refused it is recorded as `approval.requested` and `approval.granted` after
  that gate's `gate.decided`; the call's end follows as usual.
- **Standing approval.** `scope` is `"call"` when absent. An approval of
  `"tool"` or `"session"` scope also covers the session's later calls of that
  tool, or all its later calls: each is recorded as a `gate.decided` of the
  `approval` gate, permitted, with no request of its own. A `"tool"` scope
  is matched by the proposed `tool`: a tool written as `tool_digest` gets no
  standing approval of `"tool"` scope, since its digests differ from entry to
  entry.
- **Edited arguments.** When the person changed the arguments before
  approving, `arguments_digest` is the digest of the arguments as approved,
  and those are what ran.
- **Who.** `approver` and `stopped_by` are the identifier the host supplied
  for the person. It SHOULD be a pseudonymous identifier the deployment can
  resolve to a person (a staff number, an account id), never a name or a
  contact detail: the log is written to be handed to others, and the
  deployment keeps the mapping. The type admits the identifiers identity
  providers issue (`auth0|5f7c…`, a base64 id), and no `@` and no space. A
  runtime with a single user and no identity writes one identifier of its
  own for that user, the same in every entry.
- `latency_ms` and `waited_ms` are milliseconds from the request, by the
  runtime's own monotonic clock. They are not derived from `recorded_at`,
  whose resolution is one second.

### 4.5 The log itself

| Kind | Detail members |
|---|---|
| `events.dropped` | `count` (integer, at least 1): events the runtime produced that the writer could not record |
| `log.recovered` | `offset` (integer), `length` (integer, at least 1), `sha256` (hash of the bytes moved aside): core §4.4's recovery |

### 4.6 Checks

A reader with this profile refuses an entry with `audit_entry.structure`
(core §4.4 refusal 5, §5.1) when:

1. its kind is not one of §4's;
2. its detail has a member the kind does not name, or lacks one it requires;
3. a member is `null`, is not of its type, is a string outside its list of
   values, a text longer than its limit, or an integer below its least value;
4. both or neither of `tool` and `tool_digest` are present;
5. `refusal` of `gate.decided` is present without `decision` `"refused"`, or
   absent with it;
6. `parent_call` is present without `parent_session_id`, or `stopped_by`
   without `outcome` `"stopped"`.

The rules that relate entries to each other (§4.1's reachable tools, §4.2's
order of a call's entries, §4.4's approval gate) are the writer's. A reader
does not refuse a log for breaking them: its integrity is the core's to
check, and these rules are about what the runtime did. A reader SHOULD report
where a log breaks them (among them a second `call.proposed` for one
`call`, and an entry of a session after its `session.ended`, which §2's
session forbids), and above all a `call.proposed` whose `tool` the
session could not reach, which may be model output written in clear.

## 5. Writing

- **Checkpoints.** A writer SHOULD sign a checkpoint (core §6) after every
  `session.ended`, when it stops in an orderly way, and while entries are
  being written at least every 1 000 entries and every 10 minutes.
- **One log, one audit key, one content secret** (core §9). A writer that
  starts a new log starts a new audit key and a new content secret.
- **Loss is recorded.** A writer that learns it has lost events writes
  `events.dropped` with their number, so a reader knows the log is incomplete.

## 6. Conformance

An implementation of this profile conforms when, for every case of
`specs/test-vectors/audit-profile-agent/`, it accepts what the case accepts,
refuses with the refusal id the case names, and computes each digest case's
digest. These cases are this profile's; the core's own cases in
`specs/test-vectors/audit-log/` are unchanged by it.

## 7. Revision history

| Date | Change |
|---|---|
| 2026-09-30 | First revision, published with release v0.1.5. Before publication it had one independent review of the document and two of its implementation. |
