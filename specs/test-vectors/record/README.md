# Record test vectors (v0.1)

The committed vector `example-v0.1.json` is the cross-implementation
contract for the Verifiable Model Record v0.1 format. Any implementation can prove conformance by
re-emitting the canonical signed payload byte-for-byte and verifying the
signature. The byte-level rules an implementer needs (JCS, what is signed,
ES256 `r‖s` + low-s, key ids, Merkle construction, verification order) are
in [`../../record-format-v0.1.md`](../../record-format-v0.1.md); the
structure is [`../../record-schema/v0.1.json`](../../record-schema/v0.1.json).

## What the vector contains

* `record` — a full 9-section record JSON, built from REAL engine state:
  CUDA `DISCRETE_RESERVOIR` engine, 1 agent, 64×128×16, seeded by the
  engine's own generators — `EngineRng` (seed 42) for the motor-post rows,
  `seed_reservoir`'s LCG (15/0/75/0x5EED0001) for the rest — so regenerating
  the vector is byte-stable across machines and operating systems (verified
  on Windows and Linux). The record is built for agent 0 with
  `serialize_state(0)`; for this one-agent engine that is the same bytes as
  `serialize_state(-1)`.
* What the run does **not** do: the 16 training frames recorded in
  `learning_provenance` are fed through 16 *frozen* ticks, and frozen
  stepping is inference-only — it never changes learned state. The learned
  state is therefore the freshly seeded one, the engine's golden state, and
  `learned_state_hash` is its SHA-256
  (`sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435`).
  `emit_vector` asserts both facts before writing the file; the ticks show
  that frozen inference leaves the attested state alone, nothing more.
* The policy section is illustrative. `policy_compliance` (and
  `deployment_context.policy_pack_id`) declares a neutral example pack,
  `example-policy-pack-v1`, as `compliant`, with four example results —
  `example-data-residency`, `example-source-screening`,
  `example-export-control`, `example-audit-trail`, each `pass`, with the
  SHA-256 of `evidence-1` … `evidence-4` as its evidence hash. A test vector
  names no real authority: the pack and rule ids were made neutral on
  2026-09-12 (the format document's revision
  history gives the old and new `signed_payload_hash`).
* `expected.signed_payload` — the JCS (RFC 8785) canonical serialization of
  the record **with the `signature` section removed**. This string is
  what the ES256 signature covers (as a COSE_Sign1 Sig_structure) and what
  `signed_payload_hash` hashes.
* `expected.signed_payload_hash` — `sha256:<hex>` of the signed payload.
* The signature (`record.signature.signature`) is `base64url:` + the raw
  64-byte low-s `r‖s`, the same bytes a COSE_Sign1 envelope of this record
  carries; the key ids are the RFC 7638 thumbprint URN of the embedded JWK.
  Both were revised on 2026-09-11 before publication — see the format
  document's revision history.

## Signing key

Secret scalar = `SHA-256("khalm v0.1 test-vector signing key")` —
derived, never generated, so the vector is reproducible. The public key is
embedded in `record.issuer.public_key`. **Test-only; never use for
anything real.**

## Regeneration

The vector is regenerated from the engine's real state by the authors' engine
build, which needs a CUDA GPU; the committed bytes are the contract. Checking
needs neither: the conformance tests run against the committed file.

The vector changes only when the record format or the engine's canonical state
changes, or by a decision on its content (as on 2026-09-12, the neutral example
pack), each change in its own commit with its explanation.

## The general description: `example-general-v0.1.json`

`example-v0.1.json` is a record in the KHALM engine profile
(`model_format` `snn-compact-v1`, spec §7.4). `example-general-v0.1.json` is
the same contract for the general model description (spec §7.3), which any
model from any vendor uses. An implementation that does not know the engine
conforms on this file alone.

* `files` — the four synthetic files of a model distributed in the layout of
  an open-weight transformer: `config.json`,
  `model-00001-of-00002.safetensors`, `model-00002-of-00002.safetensors` and
  `tokenizer.json`. Each carries its text, `size_bytes` and `sha256`. They are
  not a real model, and no model or vendor is named.
* `record` — issued by a party that holds the files and deploys the model,
  and that does not hold the model's training records:
  * `model_identity`:
    * `model_format` `safetensors` selects the general description;
    * the four files are the components, in name order;
    * `learned_state_hash` and `model_hash` are their named-set digest,
      `sha256:06923b03…0f33a7` (spec §7.2), which binds each file's name;
    * `parameter_count` and `architecture` are the issuer's claims.
  * `learning_provenance`: `training_input_disclosure` `not-held`, so
    `training_input_digest` and `training_input_merkle_root` are `""` and
    `training_input_count` is 0 (spec §8.4). No epochs, training times,
    residency or collection period are stated, and the environment's values
    are `""`.
  * `policy_compliance`: `indeterminate` with no results, as spec §7.6
    recommends for an issuer that evaluated no pack.
  * `lineage`: `initial`.
* `expected.signed_payload` and `expected.signed_payload_hash` — as for
  `example-v0.1.json`. The signing key is the same test-only key.

Regenerate, without a GPU or the engine:

```
cd vmr
VMR_WRITE_VECTORS=1 cargo test -p vmr-record --test general_vector -- --ignored
```

`general_vector_is_reproducible` fails if the file drifts from the generator.
`the_general_vector_is_a_consistent_signed_general_record` checks four
things: the file's texts hash to the components, the model hash equals a value
computed independently with Python's `hashlib`, the record passes
`format.schema` and `format.consistency`, and its signature verifies.
Named-set digests and the digests of `named-set-v1` records have their own
vectors in [`../model-hash/`](../model-hash/).
