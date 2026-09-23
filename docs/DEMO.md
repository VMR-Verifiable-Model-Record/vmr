# The KHALM-VMR investor demo (2 minutes)

**The claim** (`docs/TASKS.md` Part 2): *a model carries a cryptographically
signed record, and any downstream party can verify it offline — no
network, no contact with the issuer — against a trust store it already
holds.*

The demo is not the first terminal. It is the **second** one: a separate
process — ideally a separate machine — holding nothing but the record file
and a small trust store provisioned beforehand. It verifies. Change one claim
in the record, or bring a record signed by anyone else: it refuses.

Commands are Windows PowerShell (5.1 or 7), as run on the founder's box.
On 2026-09-15 (local time), §2's paths and §2.2–§4 were run as written, on
binaries built from commit `4924f6b` (`feat/10.11cd-vmr-rename`) outside the repository;
the transcript and how it was made are in [§5](#5-what-you-will-see-a-real-run). Command reference: [`docs/CLI.md`](CLI.md).

## 1. Say it honestly (read before every demo)

- **Who signed it, and that nothing changed** — that is what verification
  proves: the record was signed, over exactly these bytes, by a key the
  verifier's trust store trusts for the issuer the record names. It does
  **not** prove the claims inside are true (training data, residency,
  deployment): they are the issuer's statements, now provably the issuer's.
- **The trust store is provisioned beforehand, out of band** — like a
  browser's root certificates. Never say "no trust store": say "no network,
  no contact with the issuer, only a small public file it already had".
- **The policy line is a declaration: the issuer's own evaluation, and it
  says "compliant".** The demo declares the EU AI Act reference pack
  (`khalm-reading-eu-ai-act-2026`), one of the reference packs of an open,
  jurisdiction-agnostic format. Its issuer evaluated the record against
  that pack with `vmr record verify --policy-pack` and signed the result
  into it (`docs/dev/task-7.6.md`): the pack's three mandatory rules pass,
  and of its three recommended rules the human oversight one fails, because
  the demo pins no oversight document. "Compliant" means that the pack's
  mandatory rules passed. It does **not** mean that the model complies with
  the AI Act: the pack checks only what a record can show, such as pinned
  hashes and an ordered record, and its data governance rule passes on a
  document that says it is not evidence of compliance with Art. 10
  (`docs/demo/data-governance.md`). Its mandatory technical documentation
  rule passes on a declared `software_hash` that is the SHA-256 of a list of
  software versions (`docs/demo/software-environment.json`): not technical
  documentation in the Annex IV sense, and not a measurement of any build.
  The output says `declared by the
  issuer, not evaluated`; read it out that way. `vmr` can also evaluate the
  pack on the verifier's side (`verify --policy-pack`, `docs/CLI.md`
  §3.1.1) — left out of these two minutes on purpose, and that is the
  answer if you are asked.
- **The model is the repository's golden brain** (a seeded 64×128×16
  reservoir, `tests/fixtures/golden_reservoir.brain`) and the training stream
  is 16 synthetic frames: the record binds their hashes as the issuer's
  claims. The state hash it shows, `sha256:ca124043…f594435`, is the one
  recorded for that brain's state in `tests/fixtures/golden_hashes.json`.
- **Two terminals on one machine stand in for two machines.** On two
  machines, use the default build (no engine) on the second one and keep both clocks
  synchronized (a record dated after the verifier's clock fails
  `time.not_future`). That `vmr.exe` needs only DLLs that ship with Windows
  — no Visual C++ Redistributable (its import table is checked by a test;
  `dumpbin /dependents` shows it too). It has not yet been tried on a
  freshly installed machine: rehearse the two-machine variant once before
  relying on it.

## 2. One-time setup (before the meeting, ~10 minutes)

**The issuer's steps need KHALM's private engine build.** The engine build of
`vmr` (`record emit --engine`), the C++ engine library it links and the golden
brain are private: they are not part of the free Community edition. They are
§2.1's CMake build and its first `cargo build`, the brains copied in §2.2, and
the `record emit --engine` commands at 0:15 and 1:25. Every verifier step uses
the free build.

Set the three paths, then run the blocks in order in one PowerShell window.

```powershell
$repo  = "D:\khalm-tlm"        # the repository
$build = "$repo\build"          # its CMake build tree
$demo  = "$HOME\vmr-demo"       # an empty folder for the demo
[Console]::OutputEncoding = [Text.Encoding]::UTF8   # so piped output shows ✓ and ✗
```

**2.1 Build both flavors of `vmr`.** The verifier's is the default build:
Rust only, no engine. Run Cargo from inside the repository
(`Set-Location $repo` below): the repository's `.cargo/config.toml` links
the C runtime into `vmr.exe`, so the verifier's copy needs no Visual C++
Redistributable on the machine it is taken to ([`CLI.md`](CLI.md) §1).

```powershell
Set-Location $repo
cargo build --release --offline -p vmr-cli --manifest-path "$repo\vmr\Cargo.toml" --target-dir "$repo\vmr\target\default"
```

> The KHALM engine build is not part of the Community edition. Everything in this repository builds, tests and verifies without it.

**2.2 Lay out three folders**: the issuer (the factory), the verifier (the
customer, the auditor, the regulator), and an impostor.

```powershell
New-Item -ItemType Directory -Force "$demo\issuer", "$demo\verifier", "$demo\impostor" | Out-Null
Copy-Item "$repo\vmr\target\default\release\vmr.exe" "$demo\verifier\"
```

> The KHALM engine build is not part of the Community edition. Everything in this repository builds, tests and verifies without it.

**2.3 The issuer makes its signing key** and exports the public half. `vmr`
never prints the key; on Windows it prints how to make the key file
readable by its owner only (under `$HOME` the folder already limits it to
you, SYSTEM and Administrators; [`CLI.md`](CLI.md) §3.4).

```powershell
Set-Location "$demo\issuer"
.\vmr key generate --output factory.key
.\vmr key export --key factory.key --output factory.pub.json
```

**2.4 The verifier provisions its trust store** — beforehand, out of band.
In real life `factory.pub.json` arrives on a USB stick or in a signed e-mail,
and the verifier confirms the key id with the factory by phone. The verifier
decides: this key speaks for `did:web:factory-operator.ph`, at software
level, from 1 January 2026.

```powershell
Copy-Item "$demo\issuer\factory.pub.json" "$demo\verifier\"
Set-Location "$demo\verifier"
.\vmr trust-store add --trust-store trust-store.json --public-key factory.pub.json --issuer-id did:web:factory-operator.ph --issuer-name "New Clark City Fab Operator" --attestation-level software --valid-from 2026-01-01T00:00:00Z
Remove-Item factory.pub.json
```

**2.5 The impostor makes its own key** (for the last beat).

```powershell
Set-Location "$demo\impostor"
.\vmr key generate --output impostor.key
```

**Rehearsing again** later: delete `$demo\issuer\model.vmr`,
`$demo\impostor\model.vmr` and everything in `$demo\verifier` except
`vmr.exe` and `trust-store.json` — `vmr` never overwrites a file without
`--force`.

## 3. Before you start the clock

Open two terminals side by side (Windows Terminal renders ✓ and ✗; the words
"valid" and "NOT valid" say the same in any font). In each, set the paths
again: `$demo = "$HOME\vmr-demo"`. Terminal 1 is the factory
(`Set-Location "$demo\issuer"`), terminal 2 the verifier
(`Set-Location "$demo\verifier"`). Optionally switch the machine's network
off now: nothing below needs it.

## 4. Live: the two minutes

**0:00 — The claim.** *"Every model should carry a record: who made it, from
what data, under which declared policy — signed. And anyone should be able to
check it without calling us."*

**0:15 — Terminal 1, the factory emits the record** for its trained model
(the private engine build):

```powershell
.\vmr record emit --engine brain.khalm003 --profile discrete-reservoir --input training-frames.khalmtrn --manifest record-manifest.json --key factory.key --output model.vmr
```

*"The record binds the model's exact learned state — this hash — and the
exact training stream — this one — to the factory's signature."*

**0:35 — Hand it over** (in real life: e-mail, USB, a download):

```powershell
Copy-Item model.vmr "$demo\verifier\"
```

**0:40 — Terminal 2, the verifier.** Show what it has — and what it is:

```powershell
Get-ChildItem -Name
.\vmr --version
.\vmr record verify --record model.vmr --trust-store trust-store.json
```

*"This machine has three files: the tool — a build with no engine at all —
the record, and its own trust store, a small public file it was given
beforehand. No network. No call to the factory. And it knows: signed by the
New Clark City Fab Operator — the name comes from its own trust store, not
from the record. The policy line is the factory's own declaration: it
evaluated the record against the EU AI Act reference pack and signed the
result, 'compliant' — the pack's checks, not the Act itself — and the tool
says so, that it is the issuer's word and that it was not evaluated here."*

**1:05 — Tamper: someone changes where the data came from.** One claim,
same length, inside the signed bytes: residency `PH` becomes `SG`.

```powershell
$latin1 = [Text.Encoding]::GetEncoding(28591)
$text = $latin1.GetString([IO.File]::ReadAllBytes("$demo\verifier\model.vmr"))
[IO.File]::WriteAllBytes("$demo\verifier\model-tampered.vmr", $latin1.GetBytes($text.Replace('"data_residency":"PH"', '"data_residency":"SG"')))
.\vmr record verify --record model-tampered.vmr --trust-store trust-store.json
```

*"Two letters changed. The signature no longer matches: rejected."*

**1:25 — An impostor** uses the same tool, the same model and the same
manifest — claiming to be the factory — but signs with its own key.

Terminal 1 (the private engine build):

```powershell
Set-Location "$demo\impostor"
.\vmr record emit --engine brain.khalm003 --profile discrete-reservoir --input training-frames.khalmtrn --manifest record-manifest.json --key impostor.key --output model.vmr
Copy-Item model.vmr "$demo\verifier\impostor.vmr"
```

Terminal 2:

```powershell
.\vmr record verify --record impostor.vmr --trust-store trust-store.json
```

*"Anyone can claim to be the factory. Only the factory's key — the one the
verifier already trusts — makes it true."*

**1:50 — Close.** *"Signed at the source, verified anywhere, offline. The
format is open; the verifier is one small binary."*

Exit codes, if asked: `0` valid, `3` not valid (`echo $LASTEXITCODE`).

## 5. What you will see (a real run)

A real run of §2.2–§4 on 2026-09-15 (09:48 local time; the transcript's
times are UTC, 2026-09-15T01:48Z), on binaries built from `4924f6b` of
`feat/10.11cd-vmr-rename` (Windows 11; the engine build linked against the
C++ library of the repository's CMake build; both builds in Cargo's debug
profile, in a target directory outside the repository, not by §2.1's
commands). The script
[`QA/repro/t1011cd_docs_demo_literal.py`](../QA/repro/t1011cd_docs_demo_literal.py),
in a copy whose three folder paths named a local checkout and a scratch folder,
read this document's PowerShell blocks and ran §2's paths and §2.2–§4 as
written, in one Windows PowerShell 5.1 session: `$repo` named a mirror holding
exactly what §2.2 copies, `$demo` a fresh folder, and the two `Set-Location`
commands of §3 were inserted where §4 switches terminal. Every output line
below is that run's, as `vmr` printed it;
[`QA/repro/t1011cd_docs_compare_demo_transcript.py`](../QA/repro/t1011cd_docs_compare_demo_transcript.py)
compares these blocks with the run's log. The prompts name the folders. Key
ids, record ids and times differ on every run — new keys, new time; the state
hash and the training digest do not. The demo's earlier runs, on 2026-09-14
from `feat/7.6-demo-reemit` (`QA/repro/p5_demo_run.py` and
`QA/repro/t76qa_demo_literal.ps1`), ran the commands under their old names
and are this document's history.

Setup (§2.3–2.5):

```
PS issuer> .\vmr key generate --output factory.key
Generated signing key: urn:ietf:params:oauth:jwk-thumbprint:sha-256:VECBx806vLgaJhTyvmqRU4OTCVqKxA1CCwtvYnTJ3Tw
  Private key:  'factory.key' (PKCS#8 PEM, P-256, not encrypted: keep it secret; vmr never prints it)
  Permissions:  on Windows the file inherits its folder's permissions; to let only its owner read it, run: icacls "factory.key" /inheritance:r /grant:r *S-1-3-4:F
PS issuer> .\vmr key export --key factory.key --output factory.pub.json
Exported public key: urn:ietf:params:oauth:jwk-thumbprint:sha-256:VECBx806vLgaJhTyvmqRU4OTCVqKxA1CCwtvYnTJ3Tw
  Public key file: 'factory.pub.json' (the public key only: no private key material)
PS verifier> .\vmr trust-store add --trust-store trust-store.json --public-key factory.pub.json --issuer-id did:web:factory-operator.ph --issuer-name "New Clark City Fab Operator" --attestation-level software --valid-from 2026-01-01T00:00:00Z
Trusted key urn:ietf:params:oauth:jwk-thumbprint:sha-256:VECBx806vLgaJhTyvmqRU4OTCVqKxA1CCwtvYnTJ3Tw
  for issuer:   did:web:factory-operator.ph (New Clark City Fab Operator)
  attestation:  up to software
  may sign:     from 2026-01-01T00:00:00Z (no end)
  Trust store:  'trust-store.json' created: 1 issuer, 1 key, sha256:0aa1fd58e48dcf73a8106fa5d91b542228798de5d0a2a6262e7279aaaa7caa44
PS impostor> .\vmr key generate --output impostor.key
Generated signing key: urn:ietf:params:oauth:jwk-thumbprint:sha-256:ybP8fSXAag7s50OeKVrNTJyMitehHzURIcPuNX1dhfY
  Private key:  'impostor.key' (PKCS#8 PEM, P-256, not encrypted: keep it secret; vmr never prints it)
  Permissions:  on Windows the file inherits its folder's permissions; to let only its owner read it, run: icacls "impostor.key" /inheritance:r /grant:r *S-1-3-4:F
```

Live (§4), terminal 1:

```
PS issuer> .\vmr record emit --engine brain.khalm003 --profile discrete-reservoir --input training-frames.khalmtrn --manifest record-manifest.json --key factory.key --output model.vmr
Emitted record: urn:uuid:417425e9-7eaf-8cea-9c8d-2c7d17b217a3 (derived from the record's content)
  Written to:            'model.vmr' (COSE_Sign1 form, 3897 bytes)
  Issuer (declared):     did:web:factory-operator.ph ("New Clark City Fab Operator"), attestation level software
  Signing key:           urn:ietf:params:oauth:jwk-thumbprint:sha-256:VECBx806vLgaJhTyvmqRU4OTCVqKxA1CCwtvYnTJ3Tw
  Issued at:             2026-09-15T01:48:49Z (current time)
  Learned state hash:    sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435 (brain 'brain.khalm003': 64x128x16, profile discrete-reservoir, cpu backend)
  Training input digest: sha256:ac0e49c1c10c4c9d3359204958f390e9950f95a018a67ebfd6408b3d56ac5536 (the SHA-256 of 'training-frames.khalmtrn': 16 frames of 2 words)
  Policy (declared):     "compliant" for khalm-reading-eu-ai-act-2026: declared in the manifest, not evaluated
  Lineage:               initial, chain length 1
PS issuer> Copy-Item model.vmr "$demo\verifier\"
```

Terminal 2:

```
PS verifier> Get-ChildItem -Name
model.vmr
vmr.exe
trust-store.json
PS verifier> .\vmr --version
vmr 0.1.4 (KHALM-VMR, a reference implementation of the Verifiable Model Record standard; record format v0.1)
PS verifier> .\vmr record verify --record model.vmr --trust-store trust-store.json
✓ Record valid — signed by a key the trust store trusts for this issuer
  Issuer:        did:web:factory-operator.ph (New Clark City Fab Operator, per trust store)
  Key:           urn:ietf:params:oauth:jwk-thumbprint:sha-256:VECBx806vLgaJhTyvmqRU4OTCVqKxA1CCwtvYnTJ3Tw (software)
  Record:        urn:uuid:417425e9-7eaf-8cea-9c8d-2c7d17b217a3, issued 2026-09-15T01:48:49Z
  Model:         sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435 (snn-compact-v1)
  Model state:   sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435
  Training data: sha256:ac0e49c1c10c4c9d3359204958f390e9950f95a018a67ebfd6408b3d56ac5536
  Policy status: "compliant", declared by the issuer, not evaluated (khalm-reading-eu-ai-act-2026)
  Lineage chain: 1 record (initial)
  Checked at:    2026-09-15T01:48:49Z (current time)
  Trust store:   sha256:0aa1fd58e48dcf73a8106fa5d91b542228798de5d0a2a6262e7279aaaa7caa44 (1 issuer, 1 key)
PS verifier> (the tamper: data_residency PH -> SG)
PS verifier> .\vmr record verify --record model-tampered.vmr --trust-store trust-store.json
✗ Record NOT valid — signature.valid: the signature does not match the record's signed content under the trust store's key: the record was changed after it was signed, or its signature was damaged or made with another key
  Claims (not verified):
    Record:      urn:uuid:417425e9-7eaf-8cea-9c8d-2c7d17b217a3, issued 2026-09-15T01:48:49Z
    Issuer:      did:web:factory-operator.ph ("New Clark City Fab Operator")
    Model:       sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435 (snn-compact-v1)
    Model state: sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435
  Checked at:    2026-09-15T01:48:49Z (current time)
  Trust store:   sha256:0aa1fd58e48dcf73a8106fa5d91b542228798de5d0a2a6262e7279aaaa7caa44 (1 issuer, 1 key)
```

The impostor (terminal 1, then terminal 2):

```
PS impostor> .\vmr record emit --engine brain.khalm003 --profile discrete-reservoir --input training-frames.khalmtrn --manifest record-manifest.json --key impostor.key --output model.vmr
Emitted record: urn:uuid:9fbcbc58-6358-8797-ae35-a59dfb3a9bd1 (derived from the record's content)
  Written to:            'model.vmr' (COSE_Sign1 form, 3897 bytes)
  Issuer (declared):     did:web:factory-operator.ph ("New Clark City Fab Operator"), attestation level software
  Signing key:           urn:ietf:params:oauth:jwk-thumbprint:sha-256:ybP8fSXAag7s50OeKVrNTJyMitehHzURIcPuNX1dhfY
  Issued at:             2026-09-15T01:48:49Z (current time)
  Learned state hash:    sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435 (brain 'brain.khalm003': 64x128x16, profile discrete-reservoir, cpu backend)
  Training input digest: sha256:ac0e49c1c10c4c9d3359204958f390e9950f95a018a67ebfd6408b3d56ac5536 (the SHA-256 of 'training-frames.khalmtrn': 16 frames of 2 words)
  Policy (declared):     "compliant" for khalm-reading-eu-ai-act-2026: declared in the manifest, not evaluated
  Lineage:               initial, chain length 1
PS verifier> .\vmr record verify --record impostor.vmr --trust-store trust-store.json
✗ Record NOT valid — trust.key_known: signing key "urn:ietf:params:oauth:jwk-thumbprint:sha-256:ybP8fSXAag7s50OeKVr…" is not in the trust store
  Claims (not verified):
    Record:      urn:uuid:9fbcbc58-6358-8797-ae35-a59dfb3a9bd1, issued 2026-09-15T01:48:49Z
    Issuer:      did:web:factory-operator.ph ("New Clark City Fab Operator")
    Model:       sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435 (snn-compact-v1)
    Model state: sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435
  Checked at:    2026-09-15T01:48:49Z (current time)
  Trust store:   sha256:0aa1fd58e48dcf73a8106fa5d91b542228798de5d0a2a6262e7279aaaa7caa44 (1 issuer, 1 key)
```

Exit codes in that run: 0 for the genuine record, 3 for the tampered one
and 3 for the impostor's.

## 6. If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `time.not_future: issued_at … is after the evaluation time` | the verifier's clock is behind the issuer's | synchronize the clocks, or add `--at` with a later time |
| `trust.key_validity: issued_at … is before the key's valid_from` | the trust store was given a `--valid-from` after the record was emitted | provision with an earlier `--valid-from` |
| `vmr: error: private key 'factory.key' already exists` | a rehearsal left files behind | see "Rehearsing again" in §2 |
| `error: unexpected argument '--engine' found` | `record emit --engine` was run with the verifier's binary, whose `emit` takes a model's files (`--model`), not a brain | emit from the issuer's folder |
| `the engine refused …` | the engine build cannot start the engine (profile, backend, geometry) | use `--profile discrete-reservoir` and the default CPU backend |
| The issuer's `vmr.exe` does not start on another machine | the engine build links the CUDA runtime and driver libraries; without the NVIDIA driver it may not start (not tested) | run the issuer's side on the GPU box; the verifier needs only the default build |
| `VCRUNTIME140.dll was not found` when `vmr.exe` starts | that binary was built with the C runtime as a DLL: Cargo ran outside the repository (so it did not read `.cargo/config.toml`) or with `RUSTFLAGS` set | rebuild as in §2.1, from inside the repository; `dumpbin /dependents vmr.exe` must list only Windows DLLs |
| `✓`/`✗` show as boxes or `Γ£ô` | the console font or code page | Windows Terminal; `[Console]::OutputEncoding = [Text.Encoding]::UTF8` |
| A screen's borders, the logo or the loading bar show as `?` or boxes | the console font has no box-drawing or block characters | add `--ascii`, which draws them with `+`, `-`, `\|` and `#` |
| A screen shows codes such as `←[1;32m` | the console does not act on colour codes | add `--color never`: the same screen, without colour |
| You want the plain text on a terminal, as a script gets it | the screens are drawn on every terminal whose `TERM` supports colour, with or without colour (`NO_COLOR` and `--color never` keep the boxes and tables) | pipe the output, for example `vmr record verify … \| more`; `--json` is never a screen |
