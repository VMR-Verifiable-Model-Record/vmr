# VMR conformance test v0.1

This is the open test of the Verifiable Model Record specification v0.1: the
record format (`../record-format-v0.1.md`), the trust store
(`../trust-store-format-v0.1.md`) and the policy pack
(`../policy-pack-format-v0.1.md`). Any implementation, from any vendor and in
any language, runs it through a small adapter. **Passing it is what
"VMR-conformant" means**, and nothing else does.

- **No one grants conformance.** An implementation's maker runs the test and
  publishes the report. No mark, status or listing is reserved for anyone,
  KHALM included. KHALM's libraries go through this runner and this protocol
  like any other implementation: see
  `../../vmr/crates/vmr-cli/examples/conformance_adapter.rs` and its descriptor.
- **The logo.** The VMR logo refers to the standard. It never marks a model,
  record or product as certified; conformance is claimed only by passing this
  test. Its use rule, a draft awaiting legal review, is
  [`../../docs/legal/vmr-logo-use-rule.md`](../../docs/legal/vmr-logo-use-rule.md).

## Contents

| File | What | Licence |
|---|---|---|
| `run.py` | the runner: Python 3.8 or later, standard library only | Apache-2.0 |
| `suite.json` | versions, roles, profiles, every case with its tag, and a SHA-256 pin of every file a case reads | CC0-1.0 |
| `issuer-cases.json` | the issuer cases | CC0-1.0 |
| `build_suite.py` | writes `issuer-cases.json` and `suite.json`'s pins, sets and lists from the committed vectors | Apache-2.0 |
| `tests/` | the runner's own tests, against an oracle adapter that answers from the expected values | Apache-2.0 |

The other cases are the specification's vectors in `../test-vectors/` (CC0-1.0).

## What conformant means

An implementation claims one or more **roles**, and optionally **profiles**.

| Role | The implementation | Sets |
|---|---|---|
| `verifier` | verifies records against a trust store (record format §6); recomputes a record's signed payload, its hash and its key id (§3, §5, §9); loads trust stores (trust-store format §3, §5) | `record-payload`, `verify`, `trust-store` |
| `issuer` | makes a signed record from given inputs (§4, §5, §7.3, §8.4); computes named-set digests, name and order rules and training commitments (§7.2, §8.2, §8.3) | `issue`, `model-hash` |
| `policy-evaluator` | loads policy packs (policy-pack format §3); checks a pack's signature against the stores (trust-store format §4.2); evaluates a pack against a record (§5 to §8) | `policy-evaluation`, `pack-loader`, `pack-signature` |

**Tags.** Every case is tagged `core`, `profile:<name>` or
`profile-gated:<name>`. A case is tagged `profile:snn-compact-v1` (or, for the
one case below, `profile-gated:snn-compact-v1`) when a record it holds names
the KHALM engine profile (record format §7.4). The profiles are:
- `snn-compact-v1`, defined;
- `audit-log`, planned: its cases join a later suite version.

**Required profiles.** A role's `required_profiles` in `suite.json` lists the
profiles whose cases the role must pass. **In suite 0.1.x no role requires a
profile** (the specification's owner, 2026-09-16): supporting a registered
profile is not a condition of conformance, so an implementation that reads no
`snn-compact-v1` record can be a conformant verifier, issuer and
policy-evaluator. Record format §7.1 says what such an implementation does
with a record in a profile it does not support: it reports the record as
unsupported, not as invalid. An implementation that does support a profile
claims it in its descriptor, and its cases are then run and must pass.

Cases of a profile that a run neither requires nor claims are **skipped**:
they are reported with the result `skipped`, they count towards no role, and
the summary names how many were skipped. Every rule of the general format
that an engine-record case tests has a twin on a general-description record
(`general_checks_on_engine_records`), so a profile-blind implementation is
still held to all of them.

**The one `profile-gated:<name>` case.** Every other profile-tagged case is
skipped outright by a run that does not claim (or have required) its
profile, so nothing ever asks an adapter to apply record format §7.1's
"unsupported, not invalid" rule for a registered profile it does not
implement. One case, `verify/pass-vector-json` (the suite's own committed
`snn-compact-v1` vector), is tagged `profile-gated:snn-compact-v1` instead of
the plain tag and is **never skipped**: it is sent whether or not the run
claims `snn-compact-v1`.
- If the run does not claim (and no claimed role requires) `snn-compact-v1`,
  the only passing answer is `{"unsupported": true, ...}`; a real `verdict`
  - even the correct one - fails the case, because declining is what §7.1
  requires of an implementation that has not claimed support.
- If the run does claim `snn-compact-v1`, the case is held to its own
  recorded `verdict`/`check`/`lineage`, exactly like any other case of that
  profile; answering `unsupported` then fails it.

This reuses the profile v0.1 actually registers, rather than a second,
made-up "registered" identifier invented only for this rule: see
`docs/handoffs/2026-09-16-conformance-gaps.md` for the alternative
considered and rejected.

**The pass rule.**
- A case passes only when the adapter answers it and every contract member
  matches. An `unsupported` answer, an error, a timeout or a mismatch fails
  it - except the one `profile-gated:<name>` case above, where `unsupported`
  is what passes a run that does not claim `<name>`.
- A case of a profile that the run neither requires nor claims is not run: its
  result is `skipped`, and it neither passes nor fails anything. A
  `profile-gated:<name>` case is never skipped.
- A claimed role passes when every `core` case in its sets passes, every case
  tagged with one of its `required_profiles` passes, and every
  `profile-gated:<name>` case in its sets is answered as the rule above
  requires.
- A required profile with no case in the role's sets is a suite configuration
  error, not a silent pass: the runner refuses the suite.
- A claimed profile passes when the claimed roles' sets hold cases of it and
  every one passes (a `profile-gated:<name>` case of a claimed `<name>`
  counts here too).
- An implementation is **conformant** when a full run (no `--set`) meets all
  of these:
  - it claims `verifier` or `issuer`, or both;
  - every claimed role passes;
  - every claimed profile passes.

  There are no partial scores.
- **The claim** is the runner's `Result:` line, stated with the report that
  produced it. For example: `VMR v0.1 conformant (vmr-conformance suite
  0.1.1): verifier, issuer; profiles: snn-compact-v1`.

**What is compared.** Only what the specifications make contract. The wording
of reasons, the layout of reports and exit codes are each implementation's own.
The `exit_code` in the pack-signature vectors is one command-line tool's
answer, and it is not compared.

## Running

```
python run.py ADAPTER.json --report report.json
```

- `--jobs N` sets how many cases run at once (default: the processor count, at most 8).
- `--timeout S` sets the seconds a case may take (default 120).
- `--set NAME,...` runs only some sets. Such a partial run makes no claim.

The runner refuses to run when a file the suite pins has other bytes.

Exit status:
- **0:** conformant, or a partial run whose cases all passed;
- **1:** otherwise;
- **2:** the suite, the descriptor or the arguments are unusable.

## The adapter

**The descriptor** is a JSON file:

```
{"adapter_version": "0.1",
 "implementation": {"name": "...", "version": "..."},
 "command": ["my-vmr", "conformance"],
 "roles": ["verifier"], "profiles": [],
 "reports_refusal_identifiers": true}
```

- `reports_refusal_identifiers` says whether the implementation reports the
  refusal identifiers of policy-pack format §3 (`policy_pack.load`). Policy-pack
  format §9 leaves that optional, so the descriptor states it, and the runner
  compares the identifier of every refusal case when it is `true`. When it is
  `false` the identifiers are not compared, the adapter must then report none,
  and the conformance claim says so: an implementation cannot pass the whole
  refusal taxonomy by answering "error" without an identifier and saying
  nothing about it. **Required only when `roles` includes `policy-evaluator`**
  (the only role whose sets run `policy_pack.load`): a verifier- or
  issuer-only descriptor may omit it, and `false` is then assumed.
- In `command`, `{python}` stands for the runner's own Python interpreter.
- `$NAME` and `${NAME}` are environment variables, and an unset one is refused.
- A relative program path containing a `/` is taken from the descriptor's folder.
- The command runs in that folder.

**The protocol.** For each case the runner:
1. starts the command once;
2. writes one request to its standard input:
   `{"protocol": "vmr-conformance/0.1", "operation": ..., "case": "<set>/<id>", "input": {...}}`;
3. reads one JSON object from its standard output.

**Encoding.** The request is UTF-8, and the answer MUST be UTF-8: the runner
writes UTF-8 bytes to standard input and decodes standard output strictly as
UTF-8, so an adapter that reads or writes in the platform's encoding mangles
the non-ASCII names 18 of the 33 `model-hash` cases carry. The answer is the
only thing the adapter writes to standard output — one JSON object, nothing
before it and nothing after it. Standard error and the exit status are not
read, so an adapter may log there freely.

**Concurrency.** The runner starts one process per case and runs several at
once (`--jobs`, 8 by default), so an adapter must not depend on being the only
one running: no shared temporary path, no fixed port, no lock on a file it
writes. Use `--jobs 1` for an adapter that cannot.

Every document or byte string in an input is
`{"bytes_hex": "<lower-case hex>"}`, holding the exact bytes.

An answer is one of:
- the operation's members;
- `{"unsupported": true, "reason": ...}`;
- `{"adapter_error": ...}`.

| Operation (sets) | Input | Answer |
|---|---|---|
| `record.verify` (`verify`) | `record` (with `form`, `json` or `cose`), `trust_store`, `evaluation_time`, `previous` (each with `form`; the immediate predecessor first), `require_complete_lineage` | `verdict` (`pass` or `fail`); `check`, the first failing check id of record format §6.2 or `null`; `lineage`, the §6.5 outcome or `null`, compared when the case states one |
| `record.signed_payload` (`record-payload`) | `record`, the JSON form | `signed_payload`, the §3 text; `signed_payload_hash`; `key_id`, of `issuer.public_key` (§5) |
| `trust_store.load` (`trust-store`) | `store` | `result` `ok` with `sha256`, the canonical identity (§5); or `result` `error` with `kind` (§3) |
| `record.issue` (`issue`) | `declared`, the record without its derived members; `model_files`, every file of the model (`name`, `bytes_hex`); `learned_state_components`, the names of the files that are the components; `training_records`, `null` for a `not-held` disclosure; `signing_key`, a P-256 JWK with `d` | `form` (`json` or `cose`) and `bytes_hex`, the signed record |
| `model_hash` (`model-hash`) | the case's own members: `kind` and `members`, `sets`, `name`, `names` or `record_format` (`../test-vectors/model-hash/README.md`) | the case's expected members |
| `policy.evaluate` (`policy-evaluation`) | `pack`, `record`, `evaluation_time`, `context`: `null`, or `lineage_outcome` and `predecessors` (each `signed_payload_hash` and `record`) | `pack_payload_hash`; `results`, each `rule_id`, `rule_type`, `severity`, `status`, `evidence_hash`; `indeterminate`; `overall`; `policy_compliance` |
| `policy_pack.load` (`pack-loader`) | `pack` | `result` `ok` with `pack_payload_hash`; or `result` `error`, and `refusal` (policy-pack format §3), compared when the descriptor says `reports_refusal_identifiers` |
| `policy_pack.signature` (`pack-signature`) | `pack`, `trust_store`, `authority_store` (`null` or a document), `evaluation_time`, `require_signed_pack` | `pack_payload_hash` (`null` when the pack's text is refused); and `pack_signature` (its `state` and identifiers) or `refusal` |

### Worked requests

The table names each member; this pins the exact JSON shape, since two things
about it are not guessable from prose alone: **which documents carry a
sibling `"form"` member and which do not** (only `record.verify`'s `record`
and each `previous` entry do - every other document, including
`record.signed_payload`'s `record`, is always the JSON form and has no
`"form"` key), and **which members are always present rather than omitted**
(`record.verify`'s `previous` is always an array, `[]` when there are no
predecessors, never omitted; its `require_complete_lineage` is always a
boolean). `bytes_hex` is shortened to `"<hex>"` below; the real value is the
exact document bytes, lower-case hex, per "Encoding" above.

- **`record.verify`** (no predecessor):
  ```json
  {"protocol": "vmr-conformance/0.1", "operation": "record.verify", "case": "verify/pass-vector-json",
   "input": {"record": {"form": "json", "bytes_hex": "<hex>"},
             "trust_store": {"bytes_hex": "<hex>"},
             "evaluation_time": "2026-09-11T00:00:00Z",
             "previous": [],
             "require_complete_lineage": false}}
  ```
  A successor's `previous` holds one entry per ancestor, immediate first, each
  with its own `form`: `"previous": [{"form": "cose", "bytes_hex": "<hex>"}]`.
  Answer: `{"verdict": "pass", "check": null, "lineage": "initial"}`.

- **`record.signed_payload`** - `record` has no `"form"`:
  ```json
  {"protocol": "vmr-conformance/0.1", "operation": "record.signed_payload", "case": "record-payload/example-v0.1",
   "input": {"record": {"bytes_hex": "<hex>"}}}
  ```
  Answer: `{"signed_payload": "...", "signed_payload_hash": "sha256:...", "key_id": "urn:..."}`.

- **`trust_store.load`** - `store` has no `"form"`:
  ```json
  {"protocol": "vmr-conformance/0.1", "operation": "trust_store.load", "case": "trust-store/ok-basic",
   "input": {"store": {"bytes_hex": "<hex>"}}}
  ```
  Answer: `{"result": "ok", "sha256": "sha256:..."}` or `{"result": "error", "kind": "trust_store.duplicate_issuer"}`.

- **`record.issue`** - `declared` is a plain JSON object (the record with its
  derived members removed - listed below), never a `bytes_hex` document;
  `model_files` entries have `name` and `bytes_hex`, no `form`:
  ```json
  {"protocol": "vmr-conformance/0.1", "operation": "record.issue", "case": "issue/issue-general-open-weights-not-held",
   "input": {"declared": {"record_version": "0.1", "record_id": "urn:uuid:...", "issued_at": "2026-09-10T00:00:00Z",
                          "issuer": {"issuer_id": "did:web:...", "issuer_name": "...", "attestation_level": "software"},
                          "model_identity": {"model_format": "safetensors", "parameter_count": 64, "architecture": {"...": "as the record schema requires"}},
                          "learning_provenance": {"...": "as the record schema requires"},
                          "lineage": {"lineage_type": "initial", "lineage_chain_length": 1, "root_record_id": "urn:uuid:..."},
                          "policy_compliance": {"...": "as the record schema requires"},
                          "deployment_context": {"...": "as the record schema requires"}},
             "model_files": [{"name": "config.json", "bytes_hex": "<hex>"}],
             "learned_state_components": ["config.json"],
             "training_records": null,
             "signing_key": {"kty": "EC", "crv": "P-256", "x": "...", "y": "...", "d": "..."}}}
  ```
  Answer: `{"form": "json", "bytes_hex": "<hex>"}` (or `"form": "cose"`).

- **`model_hash`** - the input carries no document at all: it is the case's
  own JSON members, verbatim (`../test-vectors/model-hash/README.md` names
  which members a given `kind` carries):
  ```json
  {"protocol": "vmr-conformance/0.1", "operation": "model_hash", "case": "model-hash/digest-one-file",
   "input": {"kind": "named-set-digest",
             "members": [{"name": "weights.bin", "bytes_hex": "<hex>", "sha256": "sha256:..."}]}}
  ```
  Answer: the case's own expected members, e.g. `{"digest": "sha256:..."}`.

- **`policy.evaluate`** - `pack`, `record` and every `predecessors[i].record`
  have no `"form"`; `context` is `null` or an object:
  ```json
  {"protocol": "vmr-conformance/0.1", "operation": "policy.evaluate", "case": "policy-evaluation/data-residency-pass",
   "input": {"pack": {"bytes_hex": "<hex>"}, "record": {"bytes_hex": "<hex>"},
             "evaluation_time": "2026-09-11T00:00:00Z", "context": null}}
  ```
  With lineage context: `"context": {"lineage_outcome": "complete",
  "predecessors": [{"signed_payload_hash": "sha256:...", "record": {"bytes_hex": "<hex>"}}]}`.
  Answer: `{"pack_payload_hash": "sha256:...",
  "results": [{"rule_id": "...", "rule_type": "...", "severity": "...", "status": "...", "evidence_hash": "sha256:..."}],
  "indeterminate": [], "overall": "pass",
  "policy_compliance": {"policy_pack_id": "...", "evaluated_at": "...", "overall_status": "compliant", "results": [{"rule_id": "...", "status": "...", "evidence_hash": "sha256:..."}]}}`.

- **`policy_pack.load`** - `pack` has no `"form"`:
  ```json
  {"protocol": "vmr-conformance/0.1", "operation": "policy_pack.load", "case": "pack-loader/ok-signed",
   "input": {"pack": {"bytes_hex": "<hex>"}}}
  ```
  Answer: `{"result": "ok", "pack_payload_hash": "sha256:..."}` or
  `{"result": "error", "refusal": "policy_pack.duplicate_rule_id"}` (the
  `refusal` member is compared only when the descriptor says
  `reports_refusal_identifiers`).

- **`policy_pack.signature`** - `pack`, `trust_store` and `authority_store`
  (when not `null`) have no `"form"`; `authority_store` and
  `require_signed_pack` are always present:
  ```json
  {"protocol": "vmr-conformance/0.1", "operation": "policy_pack.signature", "case": "pack-signature/unsigned",
   "input": {"pack": {"bytes_hex": "<hex>"}, "trust_store": {"bytes_hex": "<hex>"},
             "authority_store": null, "evaluation_time": "2026-09-11T00:00:00Z",
             "require_signed_pack": false}}
  ```
  Answer: `{"pack_payload_hash": "sha256:...", "pack_signature": {"state": "unsigned"}}` (or,
  for a checker that refuses every unsigned pack, `{"pack_payload_hash": null, "refusal": "pack_signature.unsigned"}`).

**The issuer's record.** The derived members are:
- `issuer.public_key` and `issuer.key_id`;
- `model_identity.learned_state_components`, `learned_state_hash` and
  `model_hash`;
- `learning_provenance.training_input_count`, `training_input_digest` and
  `training_input_merkle_root`;
- `signature`.

How the answer is checked:
- **The JSON form:** every member except `signature.signature` must equal the
  expected record's.
- **The COSE form:** it must be the canonical envelope (§4.4) of the expected
  signed payload.
- **Both forms:** the signature must be a low-s ES256 signature over the §4.1
  Sig_structure, under the issuer's key. Any such signature passes;
  deterministic signing is not required.

## The report

`--report` writes JSON with these members:
- `report_version`, `protocol`, `suite`, `suite_version`, `specification_version`;
- `suite_sha256`, `runner_sha256`, and `files` (the pins);
- `implementation`, `claimed`, `partial`, `sets_run`, `started_at`, `platform`, `python`;
- `roles`: each role's `claimed`, `required_profiles`, `passed`, `core` counts
  and per-profile counts;
- `profiles`: each profile's `claimed`, `passed` and counts;
- `conformant` and `claim`;
- `cases`: every case's `set`, `id`, `tag` and `result` (`pass`, `fail`,
  `unsupported` or `error`). A case that did not pass also has its `reason`,
  its `expected` members and the adapter's `answer`.

The summary printed to standard output has one line per role and profile, the
cases that did not pass (the first 50) and the `Result:` line.

## Versions and upkeep

- **Versions.** Suite 0.1.x tests specification v0.1. A change to any vector,
  case, tag or rule is a new suite version, and a claim names its suite version.
- **After the vectors are regenerated:** run `python build_suite.py`, then
  `python build_suite.py --check`. The check exits 1 when a generated file is
  stale.
- **The runner's tests:** `python -m unittest discover -s specs/conformance/tests`.
- **`general_checks_on_engine_records`** in `suite.json` lists the
  profile-tagged cases that test a general rule on an engine record. The
  profile became optional on 2026-09-16, and each of these cases has a twin on
  a general-description record, named `<id>-general-record` and tagged `core`,
  so no rule of the general format is tested only on an engine record.
