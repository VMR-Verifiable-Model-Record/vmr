# `vmr` — KHALM-VMR's command-line tool

`vmr` makes, verifies and inspects Verifiable Model Records (VMR) (signed records
of an AI model), makes signing keys and provisions trust stores. It is a
reference implementation of the Verifiable Model Record standard, never the
standard's own tool: it makes a record of any AI model, from any vendor,
whose weights you hold, from the model's files (§3.3), and a record made by
any conforming tool is equally valid. Verification is **offline**: it needs
only the record and a trust store provisioned beforehand — no network, no
contact with the issuer, no key taken from the record.

- Design and decisions: [`docs/dev/phase5.md`](dev/phase5.md) (decisions C1–C15).
- The formats: [`specs/record-format-v0.1.md`](../specs/record-format-v0.1.md),
  [`specs/trust-store-format-v0.1.md`](../specs/trust-store-format-v0.1.md),
  [`docs/INPUT_FORMAT.md`](INPUT_FORMAT.md), [`docs/STATE_FORMAT.md`](STATE_FORMAT.md).
- The investor demo: [`docs/DEMO.md`](DEMO.md).
- A record of a well-known model, made by an example signer:
  [`docs/examples/phi-4-mini-instruct/`](examples/phi-4-mini-instruct/README.md);
  and one of a model whose signer trained it, so the record states how it was
  made: [`docs/examples/vmr-demo-assistant/`](examples/vmr-demo-assistant/README.md).

## 1. Two builds

| Build | How | Commands that work | Needs |
|---|---|---|---|
| **default**, the Community `vmr` (no engine) | `cargo build --release -p vmr-cli --manifest-path vmr/Cargo.toml` (the Community workspace) | `record emit --model` (a record of any model's files), `model hash`, `record verify`, `record inspect`, `key generate`, `key export`, `trust-store add` | to build: Rust only — no clang, no C headers, no C++ library, no GPU. To run: on Windows, only DLLs that ship with Windows — no Visual C++ Redistributable (the C runtime is linked in, see below) |
| **engine** | not part of the Community edition: the KHALM engine build, from this repository's private workspace | all of the above **and** `record emit --engine` (the KHALM engine profile) | the C++ library built by CMake, its headers, clang (bindgen); the binary links the CUDA runtime and driver libraries, so expect to need the NVIDIA driver where it runs (not tested on a machine without one) |

**No Visual C++ runtime DLL on Windows** (QA P5-01). Rust links the MSVC C
runtime dynamically unless told otherwise, and `vmr.exe` then needs
`VCRUNTIME140.dll` from the Visual C++ Redistributable, which a clean
Windows machine does not have: the verifier binary would not start there.
The repository's `.cargo/config.toml` links it statically
(`-C target-feature=+crt-static` for `x86_64-pc-windows-msvc`), and
`CMakeLists.txt` compiles the engine library with the static MSVC runtime
to match (`CMAKE_MSVC_RUNTIME_LIBRARY`). Cargo reads that file only when it
runs **inside the repository** (it searches the current directory and its
parents), so run the commands below from the repository root (or from
`vmr\`), and with no `RUSTFLAGS` environment variable, which would replace
the setting. A test reads the built binary's import table and fails on any
Visual C++ runtime DLL (`vmr-cli/tests/cli_runtime.rs`); to check a release
binary by hand, from a Visual Studio developer prompt:
`dumpbin /dependents vmr.exe` lists `KERNEL32.dll`, `ntdll.dll`,
`ADVAPI32.dll`, `bcrypt.dll`, `api-ms-win-core-synch-l1-2-0.dll` and, a second
time, `kernel32.dll`, all part of Windows. An engine library built before this change was compiled
against the DLL runtime and no longer links (`LNK1120` after `LNK4098`):
rebuild it with CMake, then `cargo clean -p vmr-ffi`.

`vmr --version` tells the builds apart: `vmr 0.1.4 (KHALM-VMR, a reference
implementation of the Verifiable Model Record standard; record format v0.1)`
for the default build, `vmr 0.1.0 (KHALM-VMR, implements the Verifiable
Model Record standard; record format v0.1; engine build: record emit also
takes a KHALM engine brain)` for the engine build; each build carries its own
version number, and the record format they implement is the same. The default
build has no
engine: its `record emit` takes
a model's files and names no engine option. Its dependency tree has no
engine, FFI, bindgen or C toolchain
(`cargo tree -p vmr-cli --all-features --target all -e normal,build,dev`), and
no networking code: it reads files and writes to the terminal.

The Community workspace, `vmr/`, builds the default `vmr` and holds no
engine crate. It is built and tested from a copy of the repository that
holds none of the engine's files: Rust 1.96 or newer and nothing else, on
Windows and on Linux alike.

> The KHALM engine build is not part of the Community edition. Everything in this repository builds, tests and verifies without it.

## 2. The flow

```
issuer                                              verifier (another terminal, ideally another machine)
------                                              ----------------------------------------------------
vmr key generate --output factory.key
vmr key export --key factory.key --output factory.pub.json
                          --- factory.pub.json, out of band (USB stick, signed e-mail) --->
                                                    vmr trust-store add --trust-store trust-store.json
                                                        --public-key factory.pub.json --issuer-id did:web:...
                                                        --issuer-name "..." --attestation-level software
                                                        --valid-from 2026-01-01T00:00:00Z
vmr model hash --model my-model/                    (every name it will hash; signs nothing)
vmr record emit --model my-model/ --manifest manifest.json --key factory.key --output model.vmr
    (engine build, a KHALM brain instead of --model: --engine brain.khalm003
     --profile discrete-reservoir --input frames.khalmtrn)
                          --- model.vmr, any channel ------------------------------------->
                                                    vmr record verify --record model.vmr
                                                        --trust-store trust-store.json
                                                        [--policy-pack khalm-reading-eu-ai-act-2026.json]
```

The trust store is the verifier's own file of whom it trusts, provisioned
**before** verification — the way a browser ships root certificates or SSH
keeps `known_hosts`. A key is never trusted because a record carries it.

## 3. Commands

Every command has `--help`, which lists its options, defaults and the exit
codes (§5). Timestamps (`<T>`) are always the record's UTC-seconds profile,
`YYYY-MM-DDTHH:MM:SSZ` (e.g. `2026-09-11T08:00:00Z`): no offsets, no
fractions, a real calendar date.

### 3.1 `vmr record verify`

```
vmr record verify --record <FILE> --trust-store <FILE> [--at <T>]
                    [--previous <FILE>]... [--require-lineage]
                    [--policy-pack <FILE> [--authority-store <FILE>]
                                          [--require-signed-pack]] [--json]
```

Answers one question: *is this a well-formed v0.1 record, signed by a key
that this trust store trusts for the issuer the record names?* The checks,
their order and their ids are `specs/record-format-v0.1.md` §6; the CLI
calls `vmr-verify` and renders its report — it adds no trust logic.

| Option | Meaning |
|---|---|
| `--record` | the record, COSE (`.vmr`) or JSON form; the form is detected from the bytes |
| `--trust-store` | the trust store (loaded and validated first; an unusable store is exit 1, naming the loader's `trust_store.*` kind). Its `policy_authorities`, if it has any, are what a pack's own signature is checked against, unless `--authority-store` is given (§3.1.1) |
| `--at` | the evaluation time `T`; default: the current UTC second. The output says which (`(--at)` / `(current time)`) |
| `--previous` | a predecessor record, immediate predecessor first; repeat for each. Each is verified in full and linked (spec §6.5) |
| `--require-lineage` | fail unless the predecessors reach an initial record; without it an unverified lineage is reported, not failed |
| `--policy-pack` | also evaluate the record against this policy pack (`specs/policy-pack-schema/v0.1.json`; the reference packs are in `specs/policy-packs/`). The pack is loaded and validated, and its own authority signature decided, before anything is verified: an unusable pack, or one whose signature is refused, is exit 1 with the reason, never a verification result. What the evaluation found is reported next to — never merged with — the issuer's declaration, and exit 4 says it did not accept the record |
| `--authority-store` | with `--policy-pack`: take the policy authorities whose keys may sign the pack from this file, never also from `--trust-store`. It is a trust store that lists only `policy_authorities`, with `"issuers": []` (trust-store format §4.2). An unusable one, one that lists issuers, or one holding a key `--trust-store` trusts for an issuer, is exit 1. Its identity is printed as the trust store's is (§3.1.1) |
| `--require-signed-pack` | with `--policy-pack`: refuse, exit 1 and no report, a pack that is unsigned or signed by a key no trusted policy authority holds (§3.1.1) |
| `--json` | print the verifier's full report as JSON (`vmr-verify`'s `VerificationReport::to_json`, unchanged, plus a newline). Characters a terminal would act on or hide (DEL, C1 and bidi controls, invisible characters, noncharacters) are written as JSON `\u` escapes, so the output is safe to print and parses to exactly the same values |

A pass:

```
✓ Record valid — signed by a key the trust store trusts for this issuer
  Issuer:        did:web:factory-operator.ph (New Clark City Fab Operator, per trust store)
  Key:           urn:ietf:params:oauth:jwk-thumbprint:sha-256:HyoPYysSFOQ5d6x64H8_pHddcHp7E91G5SZbdiaeWJg (software)
  Record:        urn:uuid:2b6a0c48-9f21-4f3a-8c51-1d0b4a7e9c00, issued 2026-09-10T00:00:00Z
  Model:         sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435 (snn-compact-v1)
  Model state:   sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435
  Training data: sha256:ac0e49c1c10c4c9d3359204958f390e9950f95a018a67ebfd6408b3d56ac5536
  Policy status: "compliant", declared by the issuer, not evaluated (example-policy-pack-v1)
  Lineage chain: 1 record (initial)
  Checked at:    2026-09-11T00:00:00Z (--at)
  Trust store:   sha256:06839c8fbe28d1b74d2e43c2272a94a8ef683839c61029773a6607b258d0990d (2 issuers, 2 keys)
```

- **Issuer** is the trust store's view — its id and its name for that issuer.
  The record's own `issuer_name` is a claim and is not shown on a pass.
- **Key** is the signing key's id; in parentheses the attestation level the
  record declares (never more than the store grants).
- **Model** is the record's `model_hash`, the model's identity under both
  descriptions (spec §7.3, §7.4), with its `model_format`. The line after it is
  `learned_state_hash`: **Model state**, the state's hash, in the engine
  profile; **Components**, the digest of the components the issuer chose, in
  the general description.
- **Policy status** is the issuer's own declaration, always and only. Without
  `--policy-pack` nothing is evaluated: the line says so and the report's
  `policy.evaluation` is `not_requested`. With it, a second line says what
  this verifier found — see §3.1.1.
- **Lineage chain**: `1 record (initial)`; `N records, verified back to
  the initial record`; or, when predecessors are missing, `N records
  declared ...; not verified`.
- **Trust store** is the store's canonical SHA-256 (trust-store spec §5): the
  exact set of keys this result relied on, whatever the file's layout.

A failure — the first failing check and its reason, then the record's
claims, labelled as such:

```
✗ Record NOT valid — signature.valid: the signature does not match the record's signed content under the trust store's key: the record was changed after it was signed, or its signature was damaged or made with another key
  Claims (not verified):
    Record:      urn:uuid:..., issued 2026-09-11T08:00:00Z
    Issuer:      did:web:factory-operator.ph ("New Clark City Fab Operator")
    Model:       sha256:... (snn-compact-v1)
    Model state: sha256:...
  Checked at:    2026-09-11T08:01:00Z (current time)
  Trust store:   sha256:... (1 issuer, 1 key)
```

A malformed, truncated, tampered, forged or untrusted record is a
verification failure (exit 3), never a crash. Every record- or
store-derived string is printed through `display_safe`: control characters,
ANSI escapes, bidirectional overrides and invisible characters are shown
escaped (`\u{001b}`), so a record cannot repaint the terminal. And every
such value is cut to 200 characters before it is escaped, marked with its
whole length (`<its first 200 characters>…[250000 characters in all]`), so
a record cannot flood the terminal either; ids, hashes and timestamps are far
shorter and always shown whole. A policy pack's `disclaimer` is the one
exception: it is the line that limits what the pack's authority claims, so
`pack check` shows it whole, cut only at 2000 characters, which no disclaimer
written to be read reaches. `--json` carries every value complete. Error
messages get the same treatment: an unusable trust store is reported with
what it got wrong, its own text (a member name, a value) escaped and cut
short.

#### 3.1.1 `--policy-pack`: what the issuer declared, and what this verifier found

Two different statements, shown separately and never merged. The record's
`policy_compliance` is the **issuer's declaration**, signed by the issuer and
reported verbatim. An evaluation `--policy-pack` runs is **this verifier's
finding**, against the pack you named, at your evaluation time. `vmr` never
overwrites one with the other.

A pack is a document its author publishes, and a finding is that author's
reading of the text they cite, applied to what the record declares — not a
ruling by whoever wrote the standard. Before relying on one, read
`docs/POLICY_PACKS.md`: who may publish a pack, what `compliant` does and does
not mean, and what no pack can check. The output points there in one line,
after the pack payload hash.

The Gate 5 demo record against the EU AI Act reference pack, `--at
2026-09-11T12:00:00Z`, exit 0 (an excerpt). Since task 7.6 the demo declares
its issuer's own evaluation of that pack, made with this command at the
record's `issued_at` and signed into it (`docs/dev/task-7.6.md`), so the
declaration and the finding agree. The demo pins a data governance document
and no human oversight document, so the pack's recommended human oversight
rule fails. Recommended rules do not move the overall status, and
`compliant` means that the pack's mandatory rules passed, not that the Act is
met:

```
  Policy status: "compliant" for khalm-reading-eu-ai-act-2026 as of 2026-09-11T00:00:00Z, declared by the issuer
  Policy check:  compliant — evaluated here against pack khalm-reading-eu-ai-act-2026 1.0.0
                 6 rules: 5 pass, 1 fail
                 pack signature: none, the pack carries no authority signature
                 pack payload hash: sha256:c5f638f6b1a5d9831fe236de2203c2451ddc93bd13c2d1115046dd9a00f94680
                 the pack author's reading of the cited text — docs/POLICY_PACKS.md says what it does not mean
                 fail          eu-ai-act-human-oversight (recommended, Regulation (EU) 2024/1689 (AI Act) Art. 14(3) and Annex IV(2)(e)): the record has no /human_oversight member: it declares that it pins no human oversight documentation
```

A record that signs an empty `software_hash` fails the mandatory
`eu-ai-act-technical-documentation` rule instead, since P6-17 a signed `""`
fails a requirement for that member: `software_hash is empty`, exit 4, and a
line `Accepted:      no: the evaluation found the record non-compliant`.

- **Policy status** is the declaration: its status, the pack it is about, and
  the issuer's own `evaluated_at`. Without `--policy-pack` it keeps its older
  form, `"<status>", declared by the issuer, not evaluated (<pack>)`.
- **Policy check** is the finding: the overall status, then the pack's
  `pack_id` and its `pack_version`, as the pack's author names them. Under it:
  how many rules gave which result; the pack's signature and its payload hash
  (below), which names the text that was applied, whatever its version
  (policy-pack format §2); and every rule that did **not** pass, with its severity, the clause
  it encodes and why, at most eight of them.
- **A disagreement is called out.** When the declaration and the finding are
  about the same pack (the declared `policy_pack_id` is the evaluated pack's
  `pack_id`) and their statuses differ, a line at column 0 names both:

```
!! DISAGREEMENT — the issuer declared "compliant" (example-policy-pack-v1); this evaluation found "non-compliant" (example-policy-pack-v1)
```

  When the packs differ, that is a note, never a disagreement, whatever the
  two statuses are: `note: the record declares policy pack "…"; the
  evaluator applied "…"`. The two statements then answer different questions
  (the owner, 2026-09-13, QA Q6-08).
- **A lineage rule needs the predecessors.** A rule that reads what
  verification established — `require_verified_lineage` or
  `require_state_kept` (P6-17) — sees the predecessors given with `--previous
  <FILE>` (repeatable, immediate predecessor first) and what verification made
  of them. A successor verified without them is not failed for it: the rule is
  `indeterminate`, exit 4, and its reason names `--previous`. An initial
  record needs none.
- **The evaluation time is yours, not the record's.** An evaluation run here
  is stamped with `--at`, or the current second, exactly as `time.not_future`
  is. It is never compared with the record's `issued_at`: the format's rule
  that a *declared* `policy_compliance.evaluated_at` may not post-date
  `issued_at` (check 19, `time.policy_not_after_issued`) is about the
  evaluation the issuer embedded and signed. Evaluating a five-year-old
  record today is normal and is not a finding.
- **The pack's own signature is checked against the authorities you trust.**
  A pack may carry its authority's signature (policy-pack format §4). `vmr`
  looks its key up by the pack's `signing_key_id` among the policy
  authorities of the trust store (`policy_authorities`, trust-store format
  §4.2), or among those of `--authority-store` when you give one. The
  authorities never come from both, and an issuer's key never vouches for a
  pack (the owner, 2026-09-13, `docs/dev/phase6.md` P6-14 and P6-16). Then:
  - **`valid`:** the signature verifies under that key, the key is trusted
    for the authority the pack names, it is not revoked, and the evaluation
    time is inside its window. A pack carries no signed time, so the window
    is judged at `--at`, or the current second. The line reads `pack
    signature: valid — signed by <key id>, a key the trust store trusts for
    policy authority <id> (<name>)`, with the store's name for the authority.
  - **Refused, exit 1, before the record is verified, with no report:** a
    signature that does not verify (another key, damaged bytes), a key
    trusted for another authority, a revoked key, or a key outside its
    window. So is a pack whose `signed_payload_hash` is not the hash of its
    own content, which needs no key to see (QA Q6-05). A bad pack must never
    look like a bad record.
  - **Every refusal names its stable identifier** right after `cannot be
    used:`, as a trust store's names its `trust_store.*` kind. A pack the
    loader refuses is `policy_pack.*` (policy-pack format §3); a refused
    signature, `--require-signed-pack`'s refusals and a refused authority
    store use the identifiers of trust-store format §4.2
    (`pack_signature.*`, `authority_store.issuers`,
    `authority_store.issuer_key`). Scripts match the identifier, never the
    wording. The first refusal is the one named, in trust-store format §4.2's
    order: the trust store, then the authority store, then the pack, then its
    signature.
  - **Evaluated, and labelled:** an unsigned pack, `pack signature: none, the
    pack carries no authority signature`, and a pack whose key no policy
    authority in the store holds, `pack signature: names <key id> as its
    signer — NOT checked: no policy authority in the trust store holds that
    key`. That key id is only what the pack names. The five reference packs
    are unsigned.
  - **`--require-signed-pack`** refuses both of those, exit 1, for a gate that
    must evaluate only a pack its authority signed.
  - **The pack payload hash** follows, `pack payload hash: sha256:…`, signed
    or not. It names the pack's content whatever its layout (policy-pack
    format §4), so a gate can pin a pack by it.
  - **With `--authority-store`,** the lines say "authority store", and a
    field after `Trust store:` names that store as the trust store is named:
    `Authorities:   sha256:… (1 authority, 1 key)`. The file is a trust store
    that lists only `policy_authorities`, with `"issuers": []`; one that lists
    issuers is refused, exit 1. So is one holding a key `--trust-store` trusts
    for an issuer (`authority_store.issuer_key`): one key may not vouch both
    for records and for the packs they are judged by, so an organisation
    that does both holds one key for each role.
- **Exit code**: 0 when the record verified *and* the evaluation accepted
  it; 4 when it verified and the evaluation did not — non-compliant, or
  undecidable. A record that does not verify is never evaluated at all (exit
  3, and the report's `policy.evaluation` is `skipped`). A pack refused for
  its own signature, or by `--require-signed-pack`, is exit 1 before anything
  is verified, whatever the record would have given. **Only `mandatory`
  rules decide** the overall status: `non-compliant` when a mandatory rule
  failed, else `indeterminate` when a mandatory rule could not be decided,
  else `compliant`. A `recommended` or `informational` rule is listed with
  its result but moves neither the status nor the exit code, so a pack with
  no mandatory rule is `compliant`, exit 0, whatever its rules found.
- **`--json`** carries all of it under `policy.evaluation`: `state`
  (`evaluated`), `policy_pack_id`, `policy_pack_version`,
  `policy_pack_payload_hash`, `pack_signature` (`{"state": "unsigned"}`,
  `{"state": "not_checked", "signing_key_id": …}`, or `{"state": "valid",
  "signing_key_id": …, "authority_id": …, "authority_name": …}`),
  `authority_store` (`sha256`, `authority_count`, `key_count`; only with
  `--authority-store`), `status`, and `rules[]` with each rule's `rule_id`, `status`, `severity`,
  `reference`, `evidence_hash` and reason. The `evidence_hash` is the SHA-256
  of the canonical (JCS) form of the values at the rule type's fixed list of
  record pointers, in that order, with `null` for a member that is absent,
  and for `audit_integrity` and `execution_integrity` one element more: what
  verification established about the lineage. That element is `null` for an
  initial record, which verification tells nothing its own members do not
  say, so its hashes are the ones its issuer, or the library evaluating
  without context, computes. The list is the same whatever
  the rule's settings (`docs/CODEMAP.md` §4.8), so a third party can recompute
  what a result was based on. The issuer's
  declaration stays under `policy.declared`.

### 3.2 `vmr record inspect`

```
vmr record inspect --record <FILE>
```

Prints every section of a record (either form) under a first line that
cannot be mistaken for a result:

```
UNVERIFIED — the record's own claims; nothing here was checked against a trust store.
  To verify it: vmr record verify --record <FILE> --trust-store <FILE>
  File:           'model.vmr' (COSE_Sign1 form, 3897 bytes, sha256:...)
  Record:         urn:uuid:... (format version 0.1)
  Issued at:      ...
  Issuer:         did:web:factory-operator.ph ("New Clark City Fab Operator"), attestation level software
  ...
  Policy:         "compliant" for khalm-reading-eu-ai-act-2026 (6 rule results, 5 pass), as of 2026-09-11T00:00:00Z: declared by the issuer, not evaluated
  Lineage:        initial, chain length 1, root urn:uuid:...
  Governance doc: sha256:... (data governance documentation, by hash: declared, not checked)
  Signature:      ES256 by urn:..., payload hash sha256:... (as the record states them; not checked)
```

The `Policy:` line is the issuer's declaration, shown and not checked. Its
`"compliant"` means what it means in §3.1.1: the pack's mandatory rules passed,
not that the Act is met.

It checks nothing: a forged record inspects exactly like a genuine one. A
file that is not a v0.1 record (the format's strict parse, at most 1 MiB)
is exit 1. That parse is structural — exactly the schema's members with
their JSON types, or the one canonical COSE envelope — not the schema's
value rules: a record with an upper-case id or a malformed timestamp
still inspects (exit 0), and `verify` fails it at `format.schema`. Values are shown as `verify` shows them: escaped, and cut at 200
characters with their length; at most eight state components are listed
(a record in the engine profile has three), then how many more there are.

A record in the general model description (spec §7.3, task 10.11b; any
`model_format` but `snn-compact-v1`) reads in its own words, and a profile
record reads as before:

```
  Model:          sha256:... (safetensors, 64 parameters, as the issuer states)
  Model state:    sha256:... (the components' named-set digest)
  Components:     config.json 79 bytes sha256:...
  Training input: none committed: not held by the issuer (0 records, epochs not stated, times not stated)
  Merkle root:    none
```

- A committed record set counts `records`, not `frames`, and a
  `training_input_format` gets a `Record format:` line.
- Training times that are both absent read `times not stated`; an empty
  `source_type` reads `source not stated`; `Environment:` names `accelerator software` only
  when `accelerator_software` is present (QA QB-07). A profile record, which
  states all three, reads as before.
- Without `parameter_count`, which is optional in the general description
  (spec §7.3), the line reads `parameters not stated` in place of the count.
- `derived_from` gets a `Derived from:` line per base model.
- An `accelerator` is added to `Environment:`.
- A record without `deployment_context` reads `Deployment: none stated`.
- `verify` shows `Training data: none committed (not disclosed, or not held
  by the issuer)` for a record that commits no records (spec §8.4).

A record that carries the optional `data_governance` or `human_oversight`
member (task 10.11a) gets a line for each, after `Lineage:` and only then:

```
  Governance doc: sha256:... (data governance documentation, by hash: declared, not checked)
  Oversight doc:  sha256:... (human oversight documentation, by hash: declared, not checked)
```

A hash names the document the issuer relied on. Nothing reads the document,
and nothing here says that it exists or is adequate.

When the optional `model_identity.statement_references` names other signed
statements about the model (spec §7.7, task 10.11e), each gets a line, after
`Derived from:` and only then:

```
  Statement ref:  oms-v1 sha256:... (a signed statement about the model, by digest: declared, not checked)
```

Nothing fetches or reads the statement. `verify` checks each reference's form
only, and its `format.consistency` detail (in `--json`) ends with how many
references the record names: `1 statement reference: declared, not checked
(its form only)`.

### 3.3 `vmr record emit`

> Emit a signed record of a model from its files: for any AI model, from any
> vendor, whose weights you hold. vmr hashes each file under its path in the
> folder and signs your manifest's statements about the model, its training
> and its declared policy with --key. Only a party that holds a model's files
> can compute its hashes: sign a record only for files you hold. vmr reads no
> model format and checks none of the manifest's statements. The policy
> section is your declaration; vmr evaluates no policy pack here.

That is the first paragraph of `vmr record emit --help`. Every build makes a
record of a model's files (§3.3.1); the engine build also makes the KHALM
engine profile's record of a trained brain (§3.3.2), and there `--model` and
`--engine` are one choice. Both write a new file, say where every value came
from, and never write a record that would fail verification at the moment it
is written, by a verifier whose trust store trusts the signing key.

#### 3.3.1 A model's files (every build)

```
vmr record emit --model <DIR|FILE> --manifest <MANIFEST> --key <KEY> --output <FILE>
                  [--component <NAME>]... [--training-records <DIR>]
                  [--issued-at <T>] [--record-id <URN>] [--format cose|json] [--force]
```

| Option | Meaning |
|---|---|
| `--model` | the model: a folder of its files, each named by its path in the folder with `/`, or one file, named by its own name |
| `--component` | a file of the model that you name as its learned state; repeat for each (on Windows a `\` typed in it is read as `/`). Without it every file is a component. `model_hash` covers every file either way |
| `--training-records` | a folder of the training records, committed as `named-set-v1`: their count, named-set digest and Merkle root (spec §8.2, §8.3). Without it, the manifest's `training.input_disclosure` says the records are `not-held` or `not-disclosed` (spec §8.4); exactly one of the two is given |
| `--manifest` | the issuer's statements (§4.3): the model's format and architecture, and optionally its parameter count, its bases and other statements about it |
| `--key`, `--output`, `--issued-at`, `--record-id`, `--format`, `--force` | as in §3.3.2 |

**How the files are read** (spec §7.2).

- **Names are taken as the file system stores them:** no normalisation, no
  case folding, `/` between folders on every system. A folder's names come
  from its listing.
- **One file given is named as its folder lists it,** not as its path was
  typed. On a case-insensitive disk (NTFS, or a Windows drive under `/mnt/`
  in WSL), `--model …\WEIGHTS.BIN` opens a file stored as `weights.bin`, and
  the name is `weights.bin`: the record Linux makes from the stored name. A
  spelling its folder does not list (a short 8.3 name), or one that matches
  several listed names when case is ignored, is refused; give the path as
  the folder lists it.
- **No file is left out by name:** hidden files, `.git/` and `.gitattributes`
  are files of the model like any other.
- **Links:** a link that resolves to a regular file is hashed as that file
  under the link's own name, so a Hugging Face cache folder of links gives
  the same `model_hash` as a plain copy. A link to a directory, to nothing or
  through a loop refuses the folder. A Windows junction is a link.
- **Links WSL made on an NTFS disk:** Windows cannot follow a symbolic link
  that WSL or another Linux tool made there. A folder holding one is refused
  on Windows, with that reason, and hashed on Linux, where the link resolves;
  read such a folder from Linux, or replace the links with copies of their
  files. Neither system signs a different record.
- **Refused as well:** a pipe, a socket or a device, and a file whose name,
  or the name of a folder on its path, is not a sequence of Unicode scalar
  values. A folder with such a name that holds no file contributes nothing.
- **No files, no record:** a folder that holds no file, or only empty
  folders, is refused, because a record describes at least one file
  (spec §7.3).
- **Reading:** each file is read once, in 1 MiB pieces, and a file whose size
  changes while it is read is refused.

`vmr model hash` (§3.7) shows every name before anything is signed; §3.7 lists
every refusal as it is printed.

**What it does.** Checks the output: not one of its inputs, and not inside the
`--model` or `--training-records` folder, whose files it would change. Checks
the manifest's statements before any file is read: a `model_format` that is a
registered profile identifier (`snn-compact-v1`) is refused, because a model's
files are described in general (spec §7.3), never under a profile's name.
Reads the key and the time; names and hashes the files; builds and signs the
record (`vmr-builder`); refuses a record over 1 MiB, the most a verifier reads
(name the weight files with `--component`: `model_hash` still covers every
file); runs the exact bytes through the verifier against a store holding only
the signing key, at the record's own `issued_at`; writes the file. That gate
checks form and consistency; it is **not** verification, which is the
verifier's, against its own store.

```
Emitted record: urn:uuid:72f12ccc-25aa-8bcc-9df0-06aef3eea830 (derived from the record's content)
  Written to:            'model.vmr' (COSE_Sign1 form, 1947 bytes)
  Issuer (declared):     did:web:example.org ("Example issuer"), attestation level software
  Signing key:           urn:ietf:params:oauth:jwk-thumbprint:sha-256:j-viOxneAORZGySgPm8gxXKiF6jscNhuStVlCLMFGdo
  Issued at:             2026-09-14T00:00:00Z (--issued-at)
  Model format:          "joblib" (declared in the manifest)
  Model hash:            sha256:d1d731572bf6fa1977c4ef6ba1cb139c8366729c99a24ddde7e9c548ff440e49 (3 files read, 117414 bytes, from 'figs-compas-recidivism')
  Components:            every file of the model (3)
  Links:                 none
  Training records:      none committed: not held by the issuer
  Policy (declared):     "indeterminate" for example-policy-pack-v1: declared in the manifest, not evaluated
  Lineage:               initial, chain length 1
Files hashed:
  22326399e23f99fe38a6a0a00ce044e2206427e7be55fed138e36e7fd980c473  1338  .gitattributes
  041e3deb06e8fc3c996b63ca100e4440bbf8538c55b6d1f0cebf7b5afd6f720f  2643  README.md
  28bc9246450acc5146a8509ce2b60a7303d756073b09b92fb4e25b63030aec44  113433  sklearn_model.joblib
```

Each value says where it came from: "declared" for the manifest's statements,
which vmr does not check, and "read" for what the files gave. The record's
`model_hash` is what `vmr model hash` prints for the same folder, on every
system: the same folder gives the same `model_hash` on Windows and on Linux,
and the same issuer inputs give the same record, byte for byte, on both. The
example is
[`docs/examples/phi-4-mini-instruct/`](examples/phi-4-mini-instruct/README.md),
made by an example signer, not by Microsoft. The signer of
[`docs/examples/vmr-demo-assistant/`](examples/vmr-demo-assistant/README.md)
trained its model instead, so that record carries the training input, the
environment and both documents, and the reference packs read it as compliant.

#### 3.3.2 A KHALM engine brain (engine build)

```
vmr record emit --engine <BRAIN> --profile <PROFILE> --input <FRAMES>
                  --manifest <MANIFEST> --key <KEY> --output <FILE>
                  [--backend cpu|cuda] [--issued-at <T>] [--record-id <URN>]
                  [--format cose|json] [--force]
```

| Option | Meaning |
|---|---|
| `--engine` (alias `--brain`) | the trained brain, a KHALM003 file; its geometry is read from its header |
| `--profile` | **required**: `discrete`, `discrete-rl`, `discrete-reservoir`, `discrete-reservoir-hybrid` or `hebbian` (CUDA only). The brain file does not store it, and it is part of the hashed state header |
| `--input` | the training input: the `KHALMTRN` stream (§4.4); its SHA-256 is the record's `training_input_digest` |
| `--manifest` | the issuer's descriptive statements (§4.3) |
| `--key` | the signing key, a PKCS#8 PEM (`vmr key generate`) |
| `--output` | a new file; an existing one is refused unless `--force` (§4.8) |
| `--backend` | `cpu` (default; portable, no GPU) or `cuda`. It does not change the attested bytes |
| `--issued-at` | the record's `issued_at`; default: the current UTC second. A time after the current one is refused (exit 1, nothing written): every verifier checking the record now would reject it (`time.not_future`) |
| `--record-id` | the record's id (`urn:uuid:` + lower-case 8-4-4-4-12 hex); default: derived from the record's content |
| `--format` | `cose` (default: the COSE_Sign1 envelope, the distribution form) or `json` |

What it does: reads and checks every input (an `--issued-at` in the future
is refused here); creates a one-agent engine of the
brain's geometry with the profile and backend given (every other engine
scalar at its default); loads the brain; checks the stream's words per frame
against the engine's; builds and signs the record (`vmr-provenance`'s
`RecordBuilder`, agent 0); checks the training digest is the SHA-256 of the
input file; runs the exact output bytes through the verifier against a store
holding only the signing key, at the record's own `issued_at`; writes the
file. Together these hold one promise: a record that would fail
verification at the moment it is written — by a verifier whose trust store
trusts the signing key — is never written. That gate checks form and
consistency; it is **not** verification, which is the verifier's, against
its own store (which also decides from when, and until when, the key may
sign: a record dated before a store's `valid_from` fails there, at
`trust.key_validity`).

```
Emitted record: urn:uuid:758fc27c-273c-8e17-8621-e495f060b05e (derived from the record's content)
  Written to:            'model.vmr' (COSE_Sign1 form, 3897 bytes)
  Issuer (declared):     did:web:factory-operator.ph ("New Clark City Fab Operator"), attestation level software
  Signing key:           urn:ietf:params:oauth:jwk-thumbprint:sha-256:_Kz-JNKs2xh9ynwLWb3TjfsOBE_lHi_dyuep2Jmkle8
  Issued at:             2026-09-13T22:41:04Z (current time)
  Learned state hash:    sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435 (brain 'golden_reservoir.brain': 64x128x16, profile discrete-reservoir, cpu backend)
  Training input digest: sha256:ac0e49c1c10c4c9d3359204958f390e9950f95a018a67ebfd6408b3d56ac5536 (the SHA-256 of 'training-frames.khalmtrn': 16 frames of 2 words)
  Policy (declared):     "compliant" for khalm-reading-eu-ai-act-2026: declared in the manifest, not evaluated
  Lineage:               initial, chain length 1
```

The `Policy (declared):` line is the manifest's declaration, signed as stated.
Its `"compliant"` means what it means in §3.1.1: the pack's mandatory rules
passed, not that the Act is met.

**Reproducible, in both builds.** The same inputs and the same `--issued-at`
give the same bytes
(ES256 is deterministic, RFC 6979). The default id is a UUIDv8 over the
record's own canonical payload (built with a placeholder id), so it changes
exactly when the content does. The placeholder is
`urn:uuid:00000000-0000-8000-8000-000000000000`: a non-initial manifest that
names it as its predecessor or root is refused with a derived id ("a
record cannot be its own predecessor", "only an initial record is its
own root"), because during the derivation the record *is* that id; give
`--record-id` to emit one. No real record id is the placeholder.

**The derived id is this tool's default, not a rule of the format.** The
record format names no derivation: `record_id` is any `urn:uuid:` the issuer
chooses (§2), and nothing verifies it against the content. Two conforming
implementations therefore derive different default ids for identical
content, and a reader MUST NOT treat a record id as a hash of the record.

**Limits of the engine profile.** One agent per record (v0.1). The engine is created with default
scalars, so a brain trained with non-default `h_ceiling`/`h_floor` attests the
defaults in its state header. The engine opens brain files through a narrow
`char*` path: keep brain paths ASCII on Windows.

### 3.4 `vmr key generate`

```
vmr key generate --output <FILE> [--force]
```

Makes a P-256 signing key from the operating system's CSPRNG (`getrandom`:
`BCryptGenRandom`/`ProcessPrng` on Windows, `getrandom(2)` on Linux) and
writes it as a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`). Every run makes a
different key; the output is the key's id — never the key:

```
Generated signing key: urn:ietf:params:oauth:jwk-thumbprint:sha-256:Br7KbrUpGW-OwvBIgkXmmVclpjRDy8BRyWhOJycdMPw
  Private key:  'factory.key' (PKCS#8 PEM, P-256, not encrypted: keep it secret; vmr never prints it)
  Permissions:  on Windows the file inherits its folder's permissions; to let only its owner read it, run: icacls "factory.key" /inheritance:r /grant:r *S-1-3-4:F
```

**MVP limits:** the file is **not encrypted** (no passphrase); there is no
hardware key store (HSM/TPM) and no rotation tooling. On Unix the file is
created with mode `0600` and there is no `Permissions:` line. On Windows it
inherits its folder's ACL — `vmr` cannot set one itself (that would take
unsafe code or another dependency) and says so on the `Permissions:` line
(QA P5-06). What the folder grants matters: under `%USERPROFILE%` (where
[`DEMO.md`](DEMO.md) puts its folders) a new file is readable by its owner,
SYSTEM and Administrators only; in a folder made at the root of a drive it
is typically readable — and replaceable — by every local account
(`Authenticated Users: (M)`). The printed command removes the inherited
entries and grants full control to the file's owner alone (`*S-1-3-4` is
the OWNER RIGHTS SID, so the command runs as it stands in cmd and
PowerShell); `icacls factory.key` then shows `OWNER RIGHTS:(F)` and nothing
else. Keep keys in a folder only you can read, or run it.

An existing file is never overwritten unless `--force` (which destroys the
key it held); a device, a directory or a pipe never is, `--force` or not
(§4.8).

### 3.5 `vmr key export`

```
vmr key export --key <FILE> [--output <FILE> [--force]]
```

Writes the public key file (§4.2) to standard output, or to a new `--output`
file. No private key material leaves the key file.

### 3.6 `vmr trust-store add`

```
vmr trust-store add --trust-store <FILE> --public-key <FILE>
                    --issuer-id <DID> --issuer-name <NAME>
                    --attestation-level self|software|hardware
                    --valid-from <T> [--valid-until <T>]
```

The verifier operator's trust decision, made explicit — none of these has a
default: the DID the key may sign for; the name verification shows for that
issuer; the highest attestation level its records may declare; the first
second (and, optionally, the last) at which it may sign. Before trusting a
public key file received from an issuer, compare its key id with the issuer
over a second channel (phone, a signed letter): that comparison is what makes
the store trustworthy.

- Reads only a public key file (§4.2) — never a record — and checks that
  its `key_id` is the thumbprint of its key.
- Creates the store if it does not exist; otherwise adds to it. Refuses a key
  already in the store (under any issuer, or under a policy authority:
  `trust_store.duplicate_key`), an issuer name that contradicts the store, and
  an unusable existing store — leaving the file untouched.
- Keeps a store's `policy_authorities` as they are. It adds issuers' keys
  only: the same decision for a key that signs **policy packs** is
  `vmr trust-store add-authority` (§3.10). One key never does both — a key
  the store trusts for an issuer may not be added for an authority, or the
  other way round (`trust_store.duplicate_key`).
- Validates the whole new store with the verifier's loader before writing, and
  writes it atomically (a temporary file, then a rename), in canonical order.
- Does not judge the name: `--issuer-name` is the operator's own words,
  stored as given. An empty one is accepted (a pass then reads
  `did:web:… (, per trust store)`), and one holding control characters is
  stored as is and always shown escaped.
- Refuses a `--trust-store` that is a device name, a device path or a name
  ending in a dot or a space, and one that is the `--public-key` file
  itself (§4.8).

```
Trusted key urn:ietf:params:oauth:jwk-thumbprint:sha-256:...
  for issuer:   did:web:factory-operator.ph (New Clark City Fab Operator)
  attestation:  up to software
  may sign:     from 2026-01-01T00:00:00Z (no end)
  Trust store:  'trust-store.json' created: 1 issuer, 1 key, sha256:...
```

Revoking a key or editing a window is done in the file itself (trust-store
format §2: `"revoked": true`); `vmr` has no command for it yet. Save the
file as UTF-8 **without** a byte order mark: Windows PowerShell 5.1's
`Set-Content -Encoding UTF8` (and `Out-File`, which may even write UTF-16)
adds one, and the store is then refused — `vmr` says so, and says how to
save it. In Windows PowerShell 5.1, for example, revoking the key of a
one-key store (in a larger store, edit only the entry you mean):

```powershell
$path = "$PWD\trust-store.json"
$text = [IO.File]::ReadAllText($path)
[IO.File]::WriteAllText($path, $text.Replace('"revoked": false', '"revoked": true'))
```

(`[IO.File]::WriteAllText` writes UTF-8 without a byte order mark; the full
path matters, because .NET does not follow PowerShell's current folder.
PowerShell 7's `Set-Content` writes no byte order mark either.) The same
holds for every JSON file `vmr` reads — manifests, public key files, JSON
records: a byte order mark or UTF-16 is refused, and the message names it.

### 3.7 `vmr model hash`

```
vmr model hash --model <DIR|FILE> [--json]
```

Names and hashes a model's files exactly as `record emit --model` does
(§3.3.1) and prints the `model_hash` a record of them carries, then every name
with its size and SHA-256, in the order hashed. It signs nothing and writes no
file. Use it to see every name before signing (spec §7.2 asks a tool to show
them), to check a record against a model you downloaded (its `Model hash` must
equal the record's `model_hash`), and to state a base model's `model_hash` in a
manifest's `model.derived_from`.

```
Model hash: sha256:d1d731572bf6fa1977c4ef6ba1cb139c8366729c99a24ddde7e9c548ff440e49 (3 files read, 117414 bytes, from 'figs-compas-recidivism')
  22326399e23f99fe38a6a0a00ce044e2206427e7be55fed138e36e7fd980c473  1338  .gitattributes
  041e3deb06e8fc3c996b63ca100e4440bbf8538c55b6d1f0cebf7b5afd6f720f  2643  README.md
  28bc9246450acc5146a8509ce2b60a7303d756073b09b92fb4e25b63030aec44  113433  sklearn_model.joblib
```

`--json` prints one line, its members sorted as serde_json writes them:

```
{"files":[{"hash":"sha256:…","name":"…","size_bytes":…},…],"model_hash":"sha256:…"}
```

Each file is as a record's component carries it. A character a terminal acts
on or hides in a name (a bidirectional override, a zero-width character, a
byte order mark, a line separator, a C1 control, DEL) is written as a JSON
`\u` escape, as `record verify --json` writes its claims, so the JSON parses
to the names as stored.

**Refusals.** Each exits 1, writes nothing to standard output and signs
nothing. `record emit --model` refuses the same folders with the same
reasons. Every refusal but the empty folder's prints a second line, this hint:

```
  hint: a model's files are read by specs/record-format-v0.1.md §7.2; `vmr model hash --model <DIR|FILE>` shows what vmr reads, and signs nothing
```

The first line, as printed on this project's Windows (NTFS) and Linux (tmpfs)
machines. `vmr` shows the full path of the entry it refuses; here the folder the
cases were made in is shortened to `<dir>`, and everything else is as printed
(the empty folder is shown as its path was given):

| Refused | As printed |
|---|---|
| a path that does not exist | Windows: `vmr: error: '<dir>\no-such-model' cannot be read: The system cannot find the file specified. (os error 2); nothing was written` (and the hint)<br>Linux: `vmr: error: '<dir>/no-such-model' cannot be read: No such file or directory (os error 2); nothing was written` (and the hint) |
| a folder that holds no file, only folders | Windows: `vmr: error: model folder 'empty' holds no regular file: a record describes at least one file; nothing was written`<br>Linux: `vmr: error: model folder 'empty' holds no regular file: a record describes at least one file; nothing was written` |
| a link to a directory (on Windows, a junction) | Windows: `vmr: error: '<dir>\junction\m\j' is a link that resolves to a directory: spec §7.2 refuses a folder that holds one; nothing was written` (and the hint)<br>Linux: `vmr: error: '<dir>/link-dir/m/linked' is a link that resolves to a directory: spec §7.2 refuses a folder that holds one; nothing was written` (and the hint) |
| a link to nothing | Windows: `vmr: error: '<dir>\junction-gone\m\j' is a link that resolves to nothing: spec §7.2 refuses a folder that holds one; nothing was written` (and the hint)<br>Linux: `vmr: error: '<dir>/link-nothing/m/alias.bin' is a link that resolves to nothing: spec §7.2 refuses a folder that holds one; nothing was written` (and the hint) |
| a link loop | Linux: `vmr: error: '<dir>/link-loop/m/b' is a link that cannot be resolved, for instance through a loop (Too many levels of symbolic links (os error 40)): spec §7.2 refuses a folder that holds one; nothing was written` (and the hint) |
| a symbolic link WSL made on an NTFS disk, read on Windows, in the folder | Windows: `vmr: error: '<dir>\wsl-links\m\alias.bin' is a link Windows cannot follow (a symbolic link made by WSL or another Linux tool on this disk): spec §7.2 refuses a folder that holds one; read the folder from Linux, or replace the links with copies of their files; nothing was written` (and the hint) |
| the same link given as the file | Windows: `vmr: error: '<dir>\wsl-links\m\alias.bin' is a link Windows cannot follow (a symbolic link made by WSL or another Linux tool on this disk): spec §7.2 refuses a folder that holds one; read the folder from Linux, or replace the links with copies of their files; nothing was written` (and the hint) |
| a pipe | Linux: `vmr: error: '<dir>/fifo/m/pipe' is not a regular file (a pipe, a socket or a device): a model's files are regular files (spec §7.2); nothing was written` (and the hint) |
| a socket | Linux: `vmr: error: '<dir>/socket/m/s.sock' is not a regular file (a pipe, a socket or a device): a model's files are regular files (spec §7.2); nothing was written` (and the hint) |
| a file whose name is not Unicode | Windows: `vmr: error: '<dir>\surrogate-file\m\bad-�.bin' is a file whose name, or the name of a folder on its path, is not a sequence of Unicode scalar values (bytes that are not UTF-8, or an unpaired surrogate): spec §7.2 refuses a folder that holds one; nothing was written` (and the hint)<br>Linux: `vmr: error: '<dir>/not-utf8-file/m/bad-�.bin' is a file whose name, or the name of a folder on its path, is not a sequence of Unicode scalar values (bytes that are not UTF-8, or an unpaired surrogate): spec §7.2 refuses a folder that holds one; nothing was written` (and the hint) |
| a file below a folder whose name is not Unicode | Windows: `vmr: error: '<dir>\surrogate-folder\m\dir-�\inside.bin' is a file whose name, or the name of a folder on its path, is not a sequence of Unicode scalar values (bytes that are not UTF-8, or an unpaired surrogate): spec §7.2 refuses a folder that holds one; nothing was written` (and the hint)<br>Linux: `vmr: error: '<dir>/not-utf8-folder/m/dir-�/inside.bin' is a file whose name, or the name of a folder on its path, is not a sequence of Unicode scalar values (bytes that are not UTF-8, or an unpaired surrogate): spec §7.2 refuses a folder that holds one; nothing was written` (and the hint) |
| a file this user cannot read | Linux: `vmr: error: '<dir>/unreadable/m/locked.bin' cannot be read: Permission denied (os error 13); nothing was written` (and the hint) |
| one file given by a spelling its folder does not list (a short 8.3 name) | `vmr: error: '<path>' is not a name its folder lists: the file system opened the file under another spelling, such as a short 8.3 name; give the path as its folder lists it (spec §7.2 names a file as the file system stores it); nothing was written` (and the hint) |
| one file given by a spelling that matches several listed names when case is ignored | `vmr: error: '<path>' matches several names its folder lists when case is ignored ("<name>", "<name>"): give the path as its folder lists it (spec §7.2 names a file as the file system stores it); nothing was written` (and the hint) |
| a file whose size changes while it is read | `vmr: error: '<path>' changed while it was read (<n> bytes when opened, <n> read, <n> after): nothing is signed over a file that changes; nothing was written` (and the hint) |
| a file larger than 2^53 - 1 bytes | `vmr: error: '<path>' is <n> bytes, more than a record can state (2^53 - 1); nothing was written` (and the hint) |

The last four are not produced on these disks (they hold no 8.3 names, no two
names equal with case ignored, and no file that changes or is that large); their
text is the code's, with `<path>`, `<name>` and `<n>` standing for the values.

### 3.8 `vmr pack sign`

```
vmr pack sign --pack <FILE> --key <KEY> --output <FILE> [--replace] [--force]
```

An authority signs its own policy pack. Any authority may publish and sign a
pack — a regulator, a standards body, an enterprise, an industry consortium —
and this is how one does it with `vmr`. The signature is the policy-pack
format's own (§4): ES256 over the pack's payload, which is the document as it
stands with any `signature` member removed, in its RFC 8785 canonical form.

- Writes the pack with a `signature` section added: `algorithm` (`ES256`),
  `signature` (`base64url:` and the 64-byte `r ‖ s`, low-s),
  `signed_payload_hash` and `signing_key_id` (the key's RFC 7638 thumbprint
  URN). Every other member keeps its value; `signature` is the only one added,
  and none is removed or changed.
- **The file is rewritten in sorted member order**, indented two spaces, and
  not in the order you wrote it. Only the layout moves: the pack's content, and
  its payload hash, are the same. If your pack's member order matters to you
  (a review diff, a generator), sort it once and keep it sorted, and the file
  then comes back as you gave it.
- The payload hash does not change. A pack and the same pack signed share it,
  because a `signature` member is never part of what is signed. So a pack you
  pinned by its payload hash before signing keeps that hash after.
- Deterministic (RFC 6979): the same pack and the same key give the same bytes
  on every machine and every run.
- Validates the pack before signing anything (the policy-pack format §3), and
  loads what it wrote and verifies that signature before the file is written.
  A pack `vmr` refuses is an input error (exit 1) and nothing is written.
- Refuses a pack that already carries a signature (`pack_sign.already_signed`)
  unless `--replace` says to sign it again; `--replace` drops the old section
  and signs the same payload, so the payload hash still does not move. The
  output then names the signature it dropped (`Replaced:`), because that
  signature may be another party's.
- Says the authority as the **pack** states it, marked as the pack's own
  claim. Signing a pack establishes nothing about who wrote it; only the
  store of whoever checks it does that (§3.9).
- Refuses an `--output` that exists unless `--force`, and an `--output` that is
  a device name or either input file (§4.8).
- Decides no trust. Whose key may speak for which authority is the decision of
  whoever checks the pack, held in the `policy_authorities` of their trust
  store (trust-store format §4.2). Send them the public key
  (`vmr key export`), and have them compare its key id with you over a second
  channel, exactly as for an issuer's key.

```
Signed policy pack: khalm-reading-eu-ai-act-2026 1.0.0
  Authority:    khalm-reference-packs (KHALM reference packs) — the pack's own claim
  Signing key:  urn:ietf:params:oauth:jwk-thumbprint:sha-256:...
  Payload hash: sha256:c5f638f6b1a5d9831fe236de2203c2451ddc93bd13c2d1115046dd9a00f94680
  Signed pack:  'signed-pack.json' (the pack as given, with its signature section added)
```

With `--replace`, the last two lines name what was dropped:

```
  Signed pack:  'signed-pack.json' (the pack as given, its signature section replaced)
  Replaced:     the signature of urn:ietf:params:oauth:jwk-thumbprint:sha-256:...
```

Signing is part of the free Community edition, as emitting and verifying a
record are. Making a signature is not a paid feature: a standard whose
signatures only one vendor's tool can make is not an open standard.

### 3.9 `vmr pack check`

```
vmr pack check --pack <FILE> [--authority-store <FILE> | --trust-store <FILE>]
               [--at <T>] [--require-signed] [--json]
```

Reads a policy pack on its own — no record, no verification — and says what it
is: its `pack_id` and `pack_version`, the authority it names, its jurisdiction,
its payload hash, and every rule with its type, its severity and what it asks.
A pack author runs it to see what they just signed, without inventing a record
to evaluate.

- **Without a store nothing is checked.** An unsigned pack reads
  `unsigned`; a signed one names the key it *states* as its signer and says the
  signature was not checked. A pack's claim about itself is a claim.
- **With `--authority-store`, or with `--trust-store`,** the signature is
  decided exactly as `record verify --policy-pack` decides it (trust-store
  format §4.2, §3.1.1 above): the key is looked up by `signing_key_id` among
  that store's `policy_authorities`; the signature must verify under it; and
  the key must be trusted for the authority the pack names, unrevoked, and
  inside its window at `--at` (else the current time). Only then is the state
  `valid`. A key no trusted authority holds is `not checked`, not a failure.
  The two options are the two `record verify` reads, and they are mutually
  exclusive: `--authority-store` is a store of authorities alone (`"issuers":
  []`), `--trust-store` the store you verify records with, whose
  `policy_authorities` are read and whose issuers are not. Provision either
  with `vmr trust-store add-authority` (§3.10).
- **`--require-signed` is the gate.** Without it this command exits 0 for an
  unsigned pack and for one signed by a key no trusted authority holds — it
  *reports*, it does not accept — so `vmr pack check … && deploy` would deploy
  on a pack nobody vouched for. With it those two states are refused instead
  (exit 1, `pack_signature.unsigned_refused` and
  `pack_signature.not_checked_refused`), as `record verify
  --require-signed-pack` refuses them. It needs a store, and it changes no
  other outcome.
- A signature that does not verify, or a key that may not speak for the pack's
  authority, is exit 1 with the format's own identifier
  (`pack_signature.invalid`, `pack_signature.other_authority`,
  `pack_signature.revoked`, `pack_signature.outside_validity`).
- A pack whose section states a `signed_payload_hash` that is not the pack's
  own is exit 1 (`pack_signature.payload_hash`), with or without a store: it
  was changed after it was signed, or carries another pack's section.
- A file that is not a pack is an input error (exit 1), named by the
  policy-pack format's own refusal (`policy_pack.…`), as it is for
  `record verify --policy-pack`.
- `--json` prints the same as a JSON object: `version`, `pack_id`,
  `pack_version`, `jurisdiction`, `description`, `disclaimer`, `authority`,
  `payload_hash`, `signature` (the state, as the verifier's report writes it),
  `checked`, `consulted` and `rules`. `checked` names the store that **checked
  the signature** and the time it judged at, and is `null` whenever nothing was
  checked — no store given, the pack unsigned, or no authority in the store
  holding the key it names — so `checked != null` means the signature was
  checked. A store that was read and decided nothing is named by `consulted`
  instead, with the time it would have judged at.
- The pack's `disclaimer` is shown, next to its `description`: what the
  authority says its pack is **not**. A long value is shortened in the summary,
  as a description is, and `--json` carries both whole.

```
Policy pack: khalm-reading-eu-ai-act-2026 1.0.0
  File:         'khalm-reading-eu-ai-act-2026.json'
  Authority:    khalm-reference-packs (KHALM reference packs) — the pack's own claim
  Jurisdiction: eu
  Description:  Regulation (EU) 2024/1689 (the AI Act) ...
  Disclaimer:   A reference implementation of the VMR policy-pack format, not legal advice and not an official instrument. ...
  Payload hash: sha256:c5f638f6b1a5d9831fe236de2203c2451ddc93bd13c2d1115046dd9a00f94680
  Signature:    unsigned — this pack carries no authority signature (pin it by its payload hash)
  Rules:        6 rules, 3 mandatory
    eu-ai-act-record-keeping (audit_integrity, mandatory)
      The record belongs to a lineage of records that is kept, ordered and traced to its origin. ...
```

### 3.10 `vmr trust-store add-authority`

```
vmr trust-store add-authority --trust-store <FILE> --public-key <FILE>
                              --authority-id <ID> --authority-name <NAME>
                              --valid-from <T> [--valid-until <T>]
                              [--attestation-level self|software|hardware]
```

The verifier operator's other trust decision: whose signature on a **policy
pack** counts. `trust-store add` (§3.6) trusts a key for an issuer, whose
records it may sign; this trusts a key for a policy authority, whose packs it
may sign (`vmr pack sign`, §3.8). Without it every verifier who wanted to
trust a new authority had to write the store's JSON by hand — the side that
signs had a command, the side that decides whom to believe did not.

- Reads only a public key file (§4.2) — never a pack: a key is never trusted
  because a pack carries it. Compare its key id with the authority over a
  second channel, as for an issuer's key.
- `--authority-id` is what a pack's `authority.authority_id` must say for this
  key to speak for it (exact string equality; not a DID). `--authority-name` is
  the name a checked signature shows — yours, not the pack's claim.
- `--trust-store` (also spelled `--authority-store`) may be the store you
  verify records with, or an authority store of its own; it is created if it
  does not exist, and a store created here has `"issuers": []`, which is what
  `pack check --authority-store` and `record verify --authority-store` take.
- Writes `policy_authorities` only, never `issuers`, and keeps the rest of the
  store as it is. Refuses a key the store already holds — under an authority
  here, under an issuer as `trust_store.duplicate_key` — and an authority name
  that contradicts the store, leaving the file untouched. No entry is weakened
  in place: revoking a key or editing a window is done in the file itself
  (§3.6), and there is no `--force`.
- `--valid-from` and `--valid-until` bound when the key's pack signatures are
  **relied on**, not when they were made: a pack carries no signed time.
- `--attestation-level` defaults to `self` and is never read when a pack's
  signature is checked — a pack declares no level. The trust-store format's key
  object carries it because issuers' and authorities' keys share a shape.
- Validates the whole new store with the verifier's loader before writing, and
  writes it atomically, in canonical order. The private key is never read and
  no key material is ever printed.

```
Trusted key urn:ietf:params:oauth:jwk-thumbprint:sha-256:...
  for authority: eu-notified-body-1234 (Notified Body 1234, per this operator)
  may sign:      policy packs from 2026-01-01T00:00:00Z (no end)
  Trust store:   'authorities.json' created: 1 policy authority, 1 key, sha256:...
```

## 4. Files

### 4.1 Private key

An unencrypted PKCS#8 `PRIVATE KEY` PEM of a P-256 key, LF line endings, at
most 64 KiB — what OpenSSL and every JOSE/COSE library read. An encrypted
PKCS#8 key, a SEC1 `EC PRIVATE KEY` (convert: `openssl pkcs8 -topk8 -nocrypt`)
or a public key is refused with that reason; the file's content is never
quoted.

### 4.2 Public key file

```json
{
  "key_id": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:…",
  "public_key": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" }
}
```

Exactly the two members a trust-store key entry carries under the same names
(trust-store format §2), so the file also drops into a hand-written store as
it stands. `key_id` must be the RFC 7638 thumbprint URN of `public_key`.
Both objects are closed, and neither may be written as a JSON array (of its
values, in any order, or of anything else).

### 4.3 Manifest (`manifest_version` `0.1`)

The issuer's descriptive statements, for both kinds of record: a model's
files (`--model`, every build) and a KHALM engine brain (`--engine`, engine
build); where they differ, the table says so. Closed at every level: unknown,
duplicate and `null` members are refused, and so is an object written as a
JSON array (of its values, in any order, or of anything else);
`manifest_version` is checked first.

**The version check.** Once the file is UTF-8 JSON without a byte order mark,
a `manifest_version` other than `"0.1"` is reported before any other fault,
as `manifest_version is <its JSON>; this vmr reads "0.1"`, whatever JSON value
it is (a string, a number, an object), provided it holds no array. A
`manifest_version` that is or holds an array, and a manifest that is not an
object, cannot be read that way: the full parse refuses them as a value of
the wrong type (for example `invalid type: sequence, expected a string`).
Either way the
manifest is refused, with exit 1. The version message is a convenience; the
full parse decides what is accepted.
Examples: a model's files,
[`docs/examples/phi-4-mini-instruct/manifest.json`](examples/phi-4-mini-instruct/manifest.json);
an engine brain, [`docs/demo/record-manifest.json`](demo/record-manifest.json).

| Member | Record field | Rule |
|---|---|---|
| `manifest_version` | — | `"0.1"` |
| `issuer.issuer_id` | `issuer.issuer_id` | a DID (W3C DID Core, ASCII) |
| `issuer.issuer_name` | `issuer.issuer_name` | the issuer's own name (a verifier shows its trust store's) |
| `issuer.attestation_level` | `issuer.attestation_level` | `hardware`, `software` or `self`; must not exceed what the verifier's store grants |
| `model_format` | `model_identity.model_format` | a model's files: **required**, the issuer's name for the model's format (`safetensors`, `gguf`, `onnx`, …); a registered profile identifier (`snn-compact-v1`) is refused (spec §7.1, §7.4). `--engine`: optional, default `snn-compact-v1`, and any other value is refused |
| `model.architecture` | `model_identity.architecture` | a model's files: **required**, `type`, `topology` and `precision` as the issuer describes them. `--engine`: `model` is refused, the engine's state gives it |
| `model.parameter_count` | `model_identity.parameter_count` | optional: the issuer's count (vmr reads no model format); absent, the record does not state one (spec §7.3) |
| `model.derived_from` | `model_identity.derived_from` | optional: `[{"model_hash", "name", "relation"}]`, each base by its own `model_hash` (`vmr model hash` of the base), ascending by `model_hash`, never the model's own; `relation` is `fine-tune`, `adapter`, `merge`, `quantization`, `distillation` or `other` (spec §7.5) |
| `model.statement_references` | `model_identity.statement_references` | optional: `[{"format", "digest"}]`, other signed statements about the model, ascending by `digest`; a `format` without `.` must be registered (`oms-v1` or `vmr-audit-checkpoint-v1`). Declared and signed as stated; vmr reads no referenced statement (spec §7.7) |
| `training.epochs` | `learning_provenance.training_epochs` | integer ≤ 2^53 − 1; optional for a model's files, required with `--engine` |
| `training.started_at`, `training.ended_at` | `learning_provenance.training_started_at`, `…_ended_at` | timestamps; optional for a model's files, required with `--engine` |
| `training.environment` | `learning_provenance.training_environment` | `hardware_id`, `tee_measurement`, `software_hash` (`sha256:…` or `""`), `training_software`; optional `accelerator_software` and optional `accelerator` (each never `""`) (spec §8.5) |
| `training.input_provenance` | `learning_provenance.training_input_provenance` | `source_type`, `source_description`; optional `data_residency` (two capital letters) or `data_residency_countries` (two or more, ascending), and optional `collection_period` `{start, end}` (spec §8.5) |
| `training.input_disclosure` | `learning_provenance.training_input_disclosure` | a model's files without `--training-records`: **required**, `not-held` or `not-disclosed` (spec §8.4); refused with `--training-records`, and with `--engine` |
| `deployment_context` | `deployment_context` | optional for a model's files (spec §7.6), required with `--engine`; as in the record: `deployment_id` (UUID URN), `deployed_at`, `deployed_by` (DID), the three optional hashes, `inference_boundary`, `policy_pack_id` |
| `policy_compliance` | `policy_compliance` | the issuer's **declaration** — `policy_pack_id`, `evaluated_at`, `results`, `overall_status` — copied as stated. `record emit` evaluates nothing: it signs what the manifest says. (Evaluating a pack is the verifier's side, `record verify --policy-pack`, §3.1.1, and `vmr` never writes its result into a record: an issuer that declares an evaluation carries the report's result into this member itself, by the policy-pack format's §8, as the demo manifest does, `docs/dev/task-7.6.md`.) Note `evaluated_at` may not be later than `issued_at` — a declaration cannot post-date the signature over it — and the builder refuses it |
| `lineage` | `lineage` | `{"lineage_type": "initial"}` alone (vmr sets chain length 1 and root = the record's own id), or another type with `previous_record_id`, `previous_record_hash`, `lineage_chain_length`, `root_record_id` |
| `data_governance` | `data_governance` | optional (task 10.11a): `{"documentation_hash": "sha256:…"}`, the SHA-256 of the document the issuer names as its data governance documentation, in lower-case hex (PowerShell's `Get-FileHash` prints upper case, which is refused with a hint). vmr reads no document: the manifest states its hash. Absent: the record carries no such member |
| `human_oversight` | `human_oversight` | optional, as `data_governance`, for the issuer's human oversight documentation |

Everything else in the record comes from the inputs. For a model's files:
`model_hash`, `learned_state_hash` and every component's hash and size from
the files read; the training records' count, digest and Merkle root from
`--training-records`. For an engine brain: the state hashes, component sizes,
`parameter_count` and `model_hash` from the engine's canonical state; the
training digest, Merkle root and frame count from the stream. For both: the public key and key ids from `--key`; the signature. The value
rules (DIDs, timestamps, ids, hashes, enums) are the record schema's, and
the lineage rules (`initial` names no predecessor and is its own root at chain
length 1; any other type names its predecessor, has chain length 2 or more and
another root) are spec §6.5's; both are checked before signing. So is the
**time order**, the builder's own rule: training ends no earlier than it
starts and no later than the record's `issued_at`, and the data
collection period ends no earlier than it starts. Record format v0.1 has
no such rule, so a verifier — `vmr record verify` included — does not
check it: a record signed with times out of order by another tool still
verifies. It is issuer-side hygiene (`vmr-builder`'s record assembly,
which both builds use). An error
names the record field (`/issuer/issuer_id: …`,
`/lineage/lineage_chain_length: lineage: …`), which is the manifest member of
the same name (`training_*` fields are under `training`).

### 4.4 Training input — `KHALMTRN`

The engine's canonical input stream (`docs/INPUT_FORMAT.md`): a 32-byte header
— magic `KHALMTRN`, version 1, frame count, words per frame, three zero words —
then every frame's u32 words, little-endian. Every header field and the exact
payload length are checked, and the words per frame must match the brain
(`input_bits / 32`). Its SHA-256 is the record's `training_input_digest`.
Example: [`docs/demo/training-frames.khalmtrn`](demo/training-frames.khalmtrn)
(16 frames of 2 words).

### 4.5 Brain — `KHALM003`

Read by the engine. `vmr` reads only its 32-byte header (magic `KHALM003`,
then hidden neurons, input bits, motor neurons as little-endian u64) to create
an engine of that geometry.

### 4.6 Record file

`--format cose` (default) writes the COSE_Sign1 envelope, `--format json` the
pretty-printed JSON document and a newline. Both are one record with one
signature (spec §1). `.vmr` is only a naming convention. `verify` and
`inspect` read either.

### 4.7 Read limits

Record, predecessor and trust-store files: 16 MiB (larger files are not
read: exit 1; the verifier itself refuses records over 1 MiB with
`input.size`, exit 3). Manifest: 1 MiB. Key files: 64 KiB. Training input:
`i32::MAX` bytes. A model's files and training records: any size, read in
1 MiB pieces; the record itself is at most 1 MiB (§3.3.1).

### 4.8 Files `vmr` writes

`key generate --output`, `key export --output`, `record emit --output`
and `trust-store add --trust-store` write regular files only. Refused with
exit 1 before anything is opened, whatever `--force` says, and before any
other work (no key is generated, no model file is read, the engine never runs):

- on Windows, a reserved device name as the file name — `CON`, `PRN`,
  `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9` (and `COM`/`LPT` with a
  superscript 1–3), `CONIN$`, `CONOUT$` — in any case, with or without an
  extension, a trailing colon or spaces (`con.key`, `COM1:`, `nul .txt`):
  Windows would open the device instead of a file, and `--output CON` would
  print a private key on the screen;
- on Windows, a device path (`\\.\…`, `\\?\GLOBALROOT\…`, `\??\…`), and a
  name ending in a dot or a space, which Windows would silently drop
  (`k.pem.` would create `k.pem`);
- on every platform, an existing target that is not a regular file: a
  directory, a device (`/dev/stdout`), a pipe or a socket;
- on every platform, a file the same command reads — `--key` for
  `key export`; `--model` (one file), `--engine`, `--input`, `--manifest` and
  `--key` for `record emit`; `--public-key` for `trust-store add` — however its path
  is spelled (`k.pem`, `.\k.pem`, `K.PEM` on Windows; a hard link on Unix,
  not on Windows): `--force` replaces an old output, never an input, so
  `key export --key k.pem --output k.pem --force` cannot destroy the key;
- for `record emit --model`, an output inside the `--model` or
  `--training-records` folder: writing it there would change the files the
  record describes.

An existing regular file is refused unless `--force`.

## 5. Exit codes

| Code | Meaning |
|---|---|
| 0 | done; for `record verify`: the record verified |
| 1 | usage, input or I/O error: bad arguments, unreadable or malformed input files, an unusable trust store, authority store or policy pack, a pack signature that does not verify or that `--require-signed-pack` (`record verify`) or `--require-signed` (`pack check`) does not accept, a pack `pack sign` will not sign again without `--replace`, a key or an authority a trust store already holds, a bad `--at`, an existing output file — the command could not do its job. A fault in `vmr` itself exits 1 too, and says so in as many words rather than blaming the input |
| 2 | engine error: the engine refused the brain, profile or backend (the engine build only; the default build never returns it) |
| 3 | verification failed: the record is malformed, truncated, tampered, forged or not trusted by this store |
| 4 | verified, but the policy evaluation did not accept it: `record verify --policy-pack` found the record non-compliant, or could not decide it (an indeterminate result is not acceptance — §3.1.1). Only this flag can return it; without it a verified record is exit 0 |

Results go to standard output, errors to standard error as `vmr: error: …`
(with a `hint:` line when there is something to do). Every error line is
escaped on its way out: whatever a message quotes from a file, nothing a
terminal acts on or hides reaches it raw. That includes the argument
parser's usage errors (`error: unexpected argument '…' found`, `invalid
value '…' for '--at <T>'`), which quote the argument as typed: its
characters are escaped the same way, a line break inside it too, while the
message keeps its own layout. File paths appear in quotes as
given — `'C:\Users\me\model.vmr'`, backslashes as typed — with only such
characters escaped. `vmr` never panics on bad input.

**On a terminal** ([`docs/dev/cli-polish.md`](dev/cli-polish.md)). Everything
above is the plain text, what a pipe, a file or a script gets. Its results and
errors are as they were before the screens. The help and usage text changed:
every help lists the two options below, a `Usage:` line reads `[OPTIONS]`
(`Usage: vmr [OPTIONS] <COMMAND>`), each command's help lists only the exit codes
that command returns, and the top-level help says that `vmr` is a reference
implementation of the Verifiable Model Record standard. When standard output is
a terminal whose `TERM` names one that supports colour, `record emit`,
`record verify`, `record inspect`, `model hash`, `key generate`,
`key export --output`, `trust-store add`, `pack sign` and `pack check` draw the
same result as a screen instead: a badge in a box (`SIGNED`, `√ VALID`,
`× NOT VALID`, `UNVERIFIED`, `MODEL HASH`, `KEY CREATED`, `EXPORTED`, `TRUSTED`,
`SIGNED` for a signed pack, and `SIGNATURE VALID` or `PACK` for a pack read)
and bordered tables of the same values. `vmr` run with no arguments, `vmr --help`, `vmr -h` and
`vmr --version` show the standard's VMR logo with the tool's version, the commands and
examples; a command's own `--help` stays plain text.
`TERM=dumb` gets the plain text; so does an unset `TERM` on Linux and macOS,
while on Windows an unset `TERM` gets a screen. A record that verified but that
`--policy-pack`'s evaluation did not accept (exit 4) gets a second badge beside
`√ VALID`: `× NOT ACCEPTED`, or `? NOT ACCEPTED` when the evaluation was
indeterminate. An error on a terminal gets an `ERROR` badge and its hint. Green
is only for what this verifier checked and passed, red for what failed, yellow
for what is only claimed or undecided, and every badge says it in words too.

- `--color auto`, the default, colours a screen unless `NO_COLOR` is set or
  `CLICOLOR=0`; `CLICOLOR_FORCE` turns colour on. `--color never` keeps the boxes
  and tables without colour. `--color always` colours the screens and draws them
  into a pipe or a file too.
- `--ascii` draws the borders with `+`, `-` and `|`, and the screens' own marks
  `√` and `×` as `+` and `x`, for a console whose font has no box-drawing
  characters. A value keeps its characters. The marks `√` and `×` are in every
  common console font (Cascadia Mono, Consolas, Lucida Console, Courier New), so a
  table row never shifts; the plain text keeps its `✓` and `✗`.
- `--json` is never a screen and never coloured, whatever `--color` says; nor is
  the public key `key export` writes to standard output. The error of such a
  run is plain text too: `vmr: error: …`.
- The screens are 96 columns wide; a narrower window wraps their lines. Widths
  follow Unicode: a wide East Asian character or an emoji takes two columns, a
  combining mark none.
- `--full` (`model hash`, `record emit`) shows each file's whole SHA-256 in a
  screen's file table, which otherwise shows its first 12 hex digits, or more
  where two files' hashes begin alike, so that no two rows look the same. The
  plain text and `--json` always show every hash whole.
- `record emit`'s screen shows what its plain text shows: the files' exact byte
  total, the folder they were read from, the training records' folder when
  given, and the parameter count the manifest states.
- While `model hash` or `record emit` reads a model's files, standard error shows
  a loading bar: percent, bytes read of the total, and file N of M, in at most 79
  columns. It is drawn only when standard error is a terminal whose `TERM`
  supports colour: never for `--json`, a redirected standard error or
  `TERM=dumb`. The bar has no colour, so `NO_COLOR` and `--color never` draw it
  as they draw the screens. It appears only once 64 MiB are read and is erased
  before the result. It shows no time remaining: `vmr` reads no clock while it
  hashes.
- A screen shortens no value but a key id that was checked or made, shown
  without its fixed prefix `urn:ietf:params:oauth:jwk-thumbprint:sha-256:`, and,
  without `--full`, a file's hash in a file table.
  `record inspect` shows a record's key ids whole, as the record states them.
  Lists are bounded as the plain text's are, but a policy rule that did not pass
  is always listed. A suggested command names its files `<FILE>`.
- On Windows, a screen switches the console's escape-code processing on, and it
  stays on in that console window after `vmr` exits. When standard output is
  redirected and an error screen goes to the console, that screen is drawn
  without colour.

## 6. Time and randomness

The library crates read no clock and draw no randomness (Law 1). `vmr` is the
boundary where they enter, each in one place and each visible:

- **Time** (`src/clock.rs`, the workspace's only clock read): `verify`
  without `--at` and `emit` without `--issued-at` use the current UTC second,
  and say `(current time)`. Pass the flags for reproducible runs. `emit`
  with `--issued-at` reads the clock only to refuse a time after it (§3.3);
  the record then holds the time given. (The format's verifier, the
  library, never reads a clock: `vmr` is the caller that may, and says so —
  spec §6.1.)
  Verification fails `time.not_future` if the record is dated after `T`:
  across two machines, keep their clocks synchronized (NTP) or pass `--at`.
- **Randomness**: only `key generate`, from the operating system's CSPRNG.
  Record bytes are a pure function of their inputs, the key included.
