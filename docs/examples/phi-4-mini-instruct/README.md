# Example record: microsoft/Phi-4-mini-instruct

This folder holds a signed record of one well-known open-weight model,
`microsoft/Phi-4-mini-instruct` at commit `cfbefac`, made by `vmr` from the
model's files.

**Microsoft did not make, sign or endorse this record.** An example signer
made it: a party that downloaded the 21 files of the repository at that commit,
named here `did:web:example.org`. It is signed with a **published test key**,
derived from a label written in this repository's tests, so anyone can sign
with that key. The record shows how a record of any model is made and checked;
it says nothing about who stands behind the model.

## What is here

| File | What it is |
|---|---|
| `record.vmr` | the record, COSE_Sign1 (the form to distribute) |
| `record.json` | the same record as JSON |
| `trust-store.json` | a trust store that trusts the test key for `did:web:example.org` |
| `files.json` | every file of the model: its name, size and SHA-256 |
| `manifest.json` | the signer's statements, as given to `vmr record emit` |
| `parameter_count.py` | how the signer counted the parameters |

The model files themselves are not in this repository. They are MIT-licensed
and published by Microsoft on Hugging Face.

## Check it

```
vmr record verify --record record.vmr --trust-store trust-store.json
```

Verification is offline. It answers one question: is this a well-formed
record, signed by a key this trust store trusts for `did:web:example.org`?
With this trust store the answer is yes, which proves only that the test key
signed it.

To check the record against the model itself, download the repository at
commit `cfbefac` and compare:

```
vmr model hash --model <the downloaded folder>
```

The `Model hash` it prints must equal the record's `model_hash`. Every file is
hashed under its path in the folder, hidden files included. Without the model,
`files.json` lists every file's name, size and SHA-256, and the record's
`model_hash` is the named-set digest of that list
(`specs/record-format-v0.1.md` §7.2), which anyone can recompute from the
specification.

## What the record states

- **From the files** (computed by `vmr`, never typed in): `model_hash`, the
  named-set digest of all 21 files (`specs/record-format-v0.1.md` §7.2); and
  every file as a component, with its size and SHA-256.
- **The signer's statements**, which `vmr` signs as given and does not check:
  - `model_format` `safetensors`;
  - the architecture, from the model's `config.json`;
  - `parameter_count` 3,836,021,760, from `parameter_count.py`, which adds up
    the tensor shapes in the two safetensors headers.
- **What this signer cannot know**, stated as such:
  - the training data is `not-held`, so nothing about training is committed;
  - there is no deployment;
  - the policy is `indeterminate`, with no rule evaluated.

## How it was made

From the model folder at that commit, each file first checked against the
checksum the hub's own listing gives for it: 3 files by SHA-256 (their LFS
object ids: the two shards and `tokenizer.json`) and 18 by git blob SHA-1.
That check was of the download; the record itself states no such check:

```
VMR_HEADLINE_MODEL_DIR=<the model folder> cargo test -p vmr-cli --test headline_record -- --ignored write_headline_record
```

`the_committed_headline_record_is_what_vmr_emits_today` re-emits the record
from the folder and compares every file here byte for byte. It was run on
Windows and on Linux, and both give the same bytes.
