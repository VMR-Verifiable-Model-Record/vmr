# The browser checker (`vmr-check`)

A governance reviewer with no cryptography background checks a Verifiable
Model Record from **any issuer** in a web page. The page runs the same
verifier as `vmr record verify` on the reviewer's own computer: nothing is
uploaded, there is no account, and no key is trusted by default. Every trust
decision is in the trust store the reviewer brings or builds.

This page is the interface the site's page is written against. The crate is
`vmr/crates/vmr-check`; the two files a page loads are:

- `vmr-check.wasm`, the crate built for `wasm32-unknown-unknown`;
- `vmr-check.js`, a hand-written ES module with no dependencies
  (`vmr/crates/vmr-check/js/vmr-check.js`).

A release attaches both as `vmr-check-<version>.wasm` and
`vmr-check-<version>.js`, listed in `SHA256SUMS` and attested like the
binaries.

## What it can and cannot reach

- **No clock.** The evaluation time is always the caller's `at`, and every
  result says so (`at_source: "caller"`).
- **No network, no randomness.** The module imports nothing: a WebAssembly
  module reaches nothing outside its memory except its imports, so it has no
  route to a clock, the network or a random source. Its build must register
  a randomness source (a dependency of its elliptic-curve library asks for
  one), and the one registered always fails. Verification needs no
  randomness.
- **No embedded key.** Nothing is trusted unless the caller's trust store
  trusts it.

## Running the released module

A reviewer trusts the page to run the checker it says it runs. Three things
let them confirm that:

- **The released files.**
  - `SHA256SUMS` lists the SHA-256 of `vmr-check-<version>.wasm` and
    `vmr-check-<version>.js`.
  - `gh attestation verify <file> --repo <repository>` checks that the
    repository's release workflow built the file from its tag.
- **The module the page loads.**
  - `load(source, { expectedSha256 })` hashes the module's bytes before
    instantiating them and refuses a module whose SHA-256 differs.
  - A page passes the `.wasm` line of `SHA256SUMS`: 64 hex digits, with or
    without `sha256:`.
  - The hash is computed with the browser's Web Crypto (`crypto.subtle`),
    never by the module being checked, which could report any value. A page
    without Web Crypto (one not served over HTTPS) cannot use the option:
    `load` rejects.
  - A module that does not match rejects with an error whose `code` is
    `module.sha256_mismatch`.
- **The script that does the checking.** A page loads `vmr-check.js` with
  Subresource Integrity, so the browser refuses a changed script:
  `<script type="module" integrity="sha384-...">`, or `import` from a
  `<link rel="modulepreload" integrity=...>`, with the digest taken from the
  released file. A reviewer who wants to check the page itself compares
  both files with `SHA256SUMS`.

## API

```js
import { load } from "./vmr-check.js";
const vmr = await load(wasmBytesOrUrl, { expectedSha256 }); // the bytes (Uint8Array or ArrayBuffer), a URL (or URL string), or a Response
// everything after this is synchronous
```

### `vmr.version()`

`{ vmr: "0.1.x", record_format: "0.1" }`

### `vmr.verify({ record, trustStore, at, pack, authorityStore, requireSignedPack, previous, requireCompleteLineage })`

| Argument | Type | |
|---|---|---|
| `record` | `Uint8Array` | the record, JSON or COSE form |
| `trustStore` | string or `Uint8Array` | the trust store (JSON) |
| `at` | number | the evaluation time, Unix seconds, from the caller's clock |
| `pack` | string or `Uint8Array`, optional | a policy pack (JSON) to evaluate the record against |
| `authorityStore` | string or `Uint8Array`, optional | with `pack`: check the pack's signature against this store's policy authorities instead of the trust store's (`--authority-store`) |
| `requireSignedPack` | boolean, optional | with `pack`: refuse a pack that is unsigned or signed by a key no trusted authority holds (`--require-signed-pack`) |
| `previous` | array of `Uint8Array`, optional | predecessor records, immediate predecessor first (`--previous`) |
| `requireCompleteLineage` | boolean, optional | fail unless the lineage verifies back to the initial record (`--require-lineage`) |

A store or pack can be given as its bytes, so a file is checked exactly as
saved. A text from a decoder that dropped a byte order mark would load where
`vmr` refuses the file.

Result:

```js
{
  outcome,      // "verified" | "verified_not_accepted" | "failed": the page's headline
  accepted,     // true only for "verified"
  fingerprint,  // the trusted key's fingerprint, as `vmr record verify` prints it, or null
  report,       // the verifier's VerificationReport, every string through display_safe
  report_json,  // the same report as the library writes it (VerificationReport::to_json), byte for byte
  policy,       // report.policy.evaluation when a pack was given, else null
  at_source: "caller"
}
```

**The headline is `outcome`, never `report.verdict` alone.** `outcome` is
the answer `vmr record verify` gives as its exit code:

| `outcome` | Meaning | `vmr` exit code |
|---|---|---|
| `verified` | the record verified, and the pack's evaluation, when a pack was given, accepts it | 0 |
| `verified_not_accepted` | the record verified, but the pack's evaluation is non-compliant or indeterminate | 4 |
| `failed` | the record did not verify | 3 |

With a pack, a record can have `report.verdict` `"pass"` and still not be
accepted: a page that headlines the verdict would claim more than the
verifier.

**`fingerprint`** is the fingerprint of the key the trust store trusted for
the issuer (see `inspect`). It is `null` when no trusted key verified the
record. It is not the key the record embeds: when the two differ, the record
fails a `trust.*` check.

**Why the report comes twice.** The library escapes its JSON for a
terminal: characters a screen would act on or hide are written as JSON `\u`
escapes, which a JSON parser turns back into the raw characters. So the
parsed report holds raw text in these fields, which are a record's claims, a
store's names or a pack's texts:

- `record.*`;
- `issuer.*`;
- `policy.declared`;
- the record ids, types and times in `lineage`;
- the pack's ids, versions, rule texts and details, and the authority names,
  in `policy.evaluation`.

`report` is that report with every string through `display_safe`, as `vmr`
shows it:

- controls, bidi overrides, invisible characters and noncharacters become
  visible `\u{..}` text;
- a backslash is doubled, so a detail the library already escaped shows its
  escapes with doubled backslashes.

`report_json` is the library's text, unchanged. It is the form to save or to
compare with `vmr record verify --json`, which prints the same bytes and a
newline.

### `vmr.inspect(record)`

What the record says about itself, before anything is trusted:

```js
{
  issuer: { name, id },             // as the record names itself
  signing_key_id,                   // as the record states it
  fingerprint: "AbCd EfGh IjKl MnOp QrSt UvWx",
  integrity_against_embedded_key: "matches" | "does_not_match" | "unreadable",
  declared: { ... }                 // the record's fields, its signature section left out
}
```

- **`fingerprint`** is the first 24 characters of the RFC 7638 thumbprint of
  the key the record carries (the part of a key id after its prefix), in
  groups of four. It is computed from the key, never read from the key id
  the record claims. An issuer publishes it beside its key id: `vmr key
  export --output` prints it, and `vmr record verify` prints it for the key
  it trusted.
- **`integrity_against_embedded_key`** is integrity, **not** trust. It says
  whether the record's signature matches the key the record itself carries:
  - `matches`: the record was not changed after that key signed it. A forger
    who signs with their own key gets `matches` too;
  - `does_not_match`: the record was changed after it was signed, or was
    never signed by that key;
  - `unreadable`: the record carries something that is not a P-256 key.

  Only `verify`, against a trust store the reviewer decided on, says whose
  record it is. A page must not present this field as a verification.

### `vmr.storeForEmbeddedKey(record, { expectedFingerprint, attestationLevel })`

A trust store (JSON text) trusting the key the record carries, for the issuer
the record names: the reviewer's decision to trust that key, written down. It
is what `vmr trust-store add` writes for that key and issuer (vmr-verify's
`TrustStoreDocument::add_issuer_key` and `TrustStore::to_file_json`, the code
the CLI runs).

**`expectedFingerprint` is required.** It is the fingerprint the reader types
or pastes from the issuer's own publication: its website, a signed letter, a
phone call. It never comes from the record or from `inspect`.

- It is compared with the fingerprint of the key the record carries, with
  spaces removed: `HyoP YysS FOQ5 d6x6 4H8_ pHdd` and
  `HyoPYysSFOQ5d6x64H8_pHdd` are the same. Letter case matters.
- A different fingerprint is refused as `store.fingerprint_mismatch`. The
  refusal does not repeat the key's own fingerprint.
- A record whose signature does not match the key it carries (`inspect`
  would say `does_not_match` or `unreadable`) is refused as
  `store.integrity`. Trusting the key would not make that record verify, and
  the issuer the record names is the key holder's claim only when it does.

The record decides nothing about its own trust:

- **attestation level:** `attestationLevel` (`"self"`, `"software"` or
  `"hardware"`) when given, else `"self"`, the store format's lowest and most
  conservative. A record that declares a higher level than the store grants
  fails `trust.attestation` until the reviewer chooses that level;
- **valid from** the record's `issued_at`, with no end;
- **the key id** is the key's own thumbprint, computed, whatever the record
  claims.

The text is a file to keep and pass back to `verify`, not text to show: its
issuer id and name are the record's, written as JSON. For a record that
cannot be read, or a store that would not be valid, the result is the fail
shape below.

### `vmr.fileHasher()`

```js
const h = vmr.fileHasher();
h.update(chunk); // a Uint8Array, any number of times, any sizes
h.finish();      // "sha256:<64 lower-case hex digits>"; the hasher is then spent
```

Any chunking of the same bytes gives the same digest. A chunk of any size is
copied into the module through one buffer of 1 MiB, so the module's memory
does not grow with it. A page can pass a whole file, but reading it in slices
(`File.slice`) keeps the page's own memory small.

### `vmr.checkFiles({ record, files: [{ name, sha256, size }] })`

The files the reviewer holds, against the files the record lists:

```js
{
  learned_state_hash: { listed, computed /* or null */, matches },
  model_hash:         { listed, computed /* or null */, matches },
  files:         [{ index, name, shown, status: "match" | "mismatch" | "missing" | "duplicate", given_index }],
  extra:         [{ index, name, shown }],
  refused_names: [{ index, name, shown, reason, indexes? }],
  near_miss:     [{ index, given_index, why: "unicode-form" | "case" }]
}
```

**Names.** A name is each file's path relative to the model folder, with `/`
separators. Names are compared exactly: case-sensitive, with no Unicode
normalisation (spec §7.2). Every entry carries:

- `name`: the exact string, to match a result to a file;
- `shown`: the same through `display_safe`, the only form to display;
- `index`: the position in the given `files` list. For `files` entries it is
  the position in the record's list, and `given_index` is the given file it
  was compared with, or `null`.

A page displays only `shown`, and matches results to its files only by
`index`, `given_index` or the exact `name`. The display form of one name can
be another legal name: `a\b` is shown as `a\\b`.

**The two hashes** are compared where spec §7.3 puts them:

> **`learned_state_hash`** is the named-set digest (§7.2) of the components,
> each a member named by its `name` whose SHA-256 is its `hash`.

> **`model_hash`** is the named-set digest of every file the model is
> distributed as. When the components are every file, it equals
> `learned_state_hash`.

> `model_hash` covers files a record need not carry: only a holder of exactly
> those files, knowing which they are, can check it.

- **`learned_state_hash.computed`** is the named-set digest of the components
  the record lists, each named by its name with the SHA-256 of the given file
  of that name. It is `null` when a listed file is missing or given twice, or
  when the record's own names are not a valid set.
- **`model_hash.computed`** is the named-set digest of every file given: the
  reviewer is the holder §7.3 names, and the files given are the files they
  hold. It is `null` when a given name is refused.
- **A record may list only some files** (§7.3: "An issuer MAY list only the
  files it names as the model's learned state"). Its listed files are then
  checked against `learned_state_hash`, and the model as a whole against
  `model_hash`, from every file given.
- **An extra file** changes `model_hash.computed`, as it changes the folder:
  a `.gitattributes` or `.DS_Store` beside the model makes `model_hash` not
  match, and `extra` names it. Leave it out and check again. Extra files never
  change `learned_state_hash.computed`.

**Each listed file:**

- `match`: the same SHA-256 and the same size;
- `mismatch`: either one differs;
- `missing`: no file of that name was given;
- `duplicate`: the name was given twice; neither copy was used.

**Refused names** go into `refused_names`:

- a name §7.2 refuses carries §7.2's reason, spelled exactly: `empty`,
  `empty-segment`, `dot-segment` or `dotdot-segment`;
- a name given more than once is refused at every place it was given, as
  `not-ascending` (a set repeats no name), with `indexes`, every place it was
  given;
- a name that is not a sequence of Unicode scalar values (a JavaScript string
  with a lone surrogate) is refused as `not-unicode`. §7.2 requires a tool to
  refuse such a name but gives no reason name for it; this is vmr-check's.
  Its `shown` writes each lone surrogate as `\u{..}`.

**`near_miss`** is a hint, computed in `vmr-check.js`. It pairs a missing
listed file with an extra given file whose name is the same under Unicode
normalisation (`unicode-form`, for example a macOS NFD copy), or the same
apart from letter case (`case`). It explains why a file that looks present is
missing; matching stays exact. Look-alike characters from other scripts are
not detected.

**Engine profile.** A record in a registered profile (`snn-compact-v1`, the
KHALM engine's) is refused as `check_files.unsupported_profile`: its model
hash is the engine state's, not a digest of files.

## Errors

**Bad input never throws.** A call that cannot use an input returns:

```js
{ refusal: { id, input, detail } }
```

| Field | What it holds |
|---|---|
| `input` | the argument at fault: `record`, `trust_store`, `authority_store`, `pack`, `at`, `files`, `expected_fingerprint`, `attestation_level` or `request` |
| `id` | the refusing library's stable id wherever one exists (see below) |
| `detail` | the library's words, through `display_safe` |

Where `id` comes from:

- **A trust store:** the loader's `trust_store.*` (trust-store format §3).
- **A pack:** `policy_pack.*` (policy-pack format §3) or `pack_signature.*`.
- **A record that cannot be read:** the verifier's first failing check for
  those bytes, such as `input.form` or `json.structure`.
- **An authority store:** `authority_store.issuers` and
  `authority_store.issuer_key`, as `vmr` names them.
- **Ids `vmr-check` adds:**
  - `evaluation_time.range`: `at` is not a whole second within the years
    0000 to 9999;
  - `check_files.digest`: a given `sha256` is not `sha256:` and 64 lower-case
    hex digits;
  - `check_files.size`: a given `size` is not a whole number from 0 to 2^53 - 1;
  - `check_files.unsupported_profile`;
  - `store.fingerprint_mismatch` and `store.integrity`;
  - `attestation_level.unknown`;
  - `request.malformed`: only a caller that bypasses `vmr-check.js` can cause
    it.

A record that can be read but does not verify is not a refusal. It is a
report with `outcome` `failed` that names the first failing check.

**A call throws only on misuse.** That means an argument of the wrong type:

- a record that is not a `Uint8Array`;
- an `at` that is not a number;
- a file entry that is not `{ name: string, sha256: string, size: number }`;
- `authorityStore` or `requireSignedPack` without a `pack`;
- `storeForEmbeddedKey` without an `expectedFingerprint` string;
- a hasher used after `finish()`.

`load` rejects for a module it cannot fetch or instantiate, or one whose
SHA-256 is not `expectedSha256`.

## Proof

| What | Where |
|---|---|
| Every published vector through the built module | `vmr/crates/vmr-check/js/test/parity.test.mjs` (Node, standard library only) |
| What the native libraries answer for those vectors | `vmr/crates/vmr-check/tests/data/parity.json`, generated and pinned by `vmr/crates/vmr-check/tests/parity.rs` |
| The same answers as `vmr` | `vmr/crates/vmr-check/tests/cli_agreement.rs` |
| The calls, misuse and mutated input that must never trap | `vmr/crates/vmr-check/js/test/api.test.mjs`, `vmr/crates/vmr-check/tests/api.rs`, `vmr/crates/vmr-check/tests/robustness.rs` |

The parity test covers these vectors:

- **verification:** every one, the same report bytes as the library;
- **trust-store loader:** the same store identity or refusal;
- **policy:** the 131 verifiable cases re-signed with test key A first, and
  the rest as published;
- **pack loader and pack signature:** the same evaluation or refusal;
- **model hash:** the cases about files, each through `checkFiles`. The
  `named-set-v1` training-record cases are not a model's files.

To build and test:

```
cargo build --release -p vmr-check --target wasm32-unknown-unknown --manifest-path vmr/Cargo.toml
VMR_CHECK_WASM=vmr/target/wasm32-unknown-unknown/release/vmr_check.wasm \
  node --test vmr/crates/vmr-check/js/test/parity.test.mjs vmr/crates/vmr-check/js/test/api.test.mjs
```

Regenerate the parity file only when a library's answer is meant to change.
Review the diff like a vector change:

```
VMR_WRITE_PARITY=1 cargo test -p vmr-check --test parity -- --ignored
```

**Footprint:**

```
cargo tree -p vmr-check --target wasm32-unknown-unknown -e normal,build
```

- It shows no `vmr-ffi`, `bindgen`, `cc`, networking crate or JavaScript glue
  crate.
- It shows `getrandom` only with its `custom` feature, and the source
  registered there always fails.
- The community CI checks this list.
