# Example record: the VMR demo assistant

This folder holds a signed record of a small model that was fine-tuned for this
example, and whose weights are public:

<https://huggingface.co/KHALM-LLC/vmr-demo-assistant>, revision
`e01c9ed8f4862f055f32ac7c133cd89e2e986f8d`.

The other example here, `phi-4-mini-instruct/`, records a model someone else
published: its signer downloaded the files and can state almost nothing about
how they were made. This one is the opposite end. The signer trained the model,
so the record states how it was made, and every reference pack in
`specs/policy-packs/` reads it as compliant. Read the two together to see what
a record can and cannot carry.

**It is a demonstration, and labelled as one.** The issuer is
`did:web:example.org`, signing with a key generated for this example; nobody
should trust that identity for anything. The model is a 0.5-billion-parameter
assistant, fine-tuned from `Qwen/Qwen2.5-0.5B-Instruct` on 200 question-and-
answer pairs about VMR, for four passes, until its mean loss was 0.03. It
largely recites what it was taught. It is not a product, and it is not for
production, legal or compliance use.

## What is here

| File | What it is |
|---|---|
| `record.vmr` | the record, COSE_Sign1 (the form to distribute) |
| `trust-store.json` | a trust store that trusts the demo key for `did:web:example.org` |
| `manifest.json` | the signer's statements, as given to `vmr record emit` |
| `training-records/` | the 200 question-and-answer pairs the model was trained on |
| `train-log.json` | the training run: settings, loss per pass, software, and three sample answers |
| `software-environment.txt` | the training software, hashed into the record |
| `data-governance.md`, `human-oversight.md` | the two documents the record commits to by hash |
| `pack-results.txt` | the five reference packs run against this record |

The weights are not in this repository; they are on Hugging Face at the
revision above.

## Check the record

```
vmr record verify --record record.vmr --trust-store trust-store.json
```

Verification is offline, and it answers one question: is this a well-formed
record, signed by a key this trust store trusts for `did:web:example.org`? With
this trust store the answer is yes — which proves only that the demo key signed
it.

To grade it against a pack:

```
vmr record verify --record record.vmr --trust-store trust-store.json \
  --policy-pack ../../../specs/policy-packs/khalm-reading-eu-ai-act-2026.json
```

## Check the record against the published weights

**Without downloading them.** The record names one component,
`model.safetensors`, with its SHA-256
`e226d6b5159f073813b2f449a86f9f36728dff722cc2a50278ceeb119c3226d6`. Hugging
Face publishes its own digest of the file it stores, at

```
https://huggingface.co/api/models/KHALM-LLC/vmr-demo-assistant/revision/e01c9ed8f4862f055f32ac7c133cd89e2e986f8d?blobs=true
```

where `lfs.sha256` for `model.safetensors` is that same value. The seven other
recorded files are listed there too, the small ones by git blob id, which you
can compare against `git hash-object` of your own copy. None of this downloads
a gigabyte.

**With them.** The record's `model_hash` covers the **eight** files the record
lists:

```
LICENSE  README.md  chat_template.jinja  config.json  generation_config.json
model.safetensors  tokenizer.json  tokenizer_config.json
```

The Hugging Face repository holds nine. The Hub added a `.gitattributes` of its
own when the files went up, and `specs/record-format-v0.1.md` §7.2 hashes every
file in the folder and excludes nothing by name. So hashing a clone gives a
different answer. Put exactly the eight files in a folder of their own, then:

```
vmr model hash --model <that folder>
```

which prints
`sha256:9593074221d9dd4e8595f1480e814157562150ac09d02c9bf14368bb5ec73ebf`, the
record's `model_hash`.

That mismatch is worth understanding rather than working around: a `model_hash`
is a statement about a named set of files, not about a repository. Add a file
to the folder and it is a different set, so it is a different hash. A record
travels with the set it describes.

## What the record states

- **From the files** (computed by `vmr`, never typed in):
  - `model_hash`, the named-set digest of the eight files;
  - `learned_state_hash`
    `sha256:118785d96399c6d6c957fff4a8d08b1d0f5eaee635afb7683beef50045a2d6c3`,
    over the one declared component, `model.safetensors` — the weights alone,
    without the tokenizer and the configuration;
  - the training input: 200 records, the named-set digest
    `sha256:57165e8de8a5101ff470f9a4fa582cdc1d6ca128e1cb11d61005c0b96b604337`
    and the Merkle root
    `sha256:fae12baeade9c7e85135ddc12630be35f45e563a2b1961513d1d57d8980a5a13`,
    so any one of the files in `training-records/` can later be proven to be in
    the set the model was trained on.
- **The signer's statements**, which `vmr` signs as given and does not check:
  - `derived_from`: a fine-tune of `Qwen/Qwen2.5-0.5B-Instruct`, by its hash;
  - the training software (transformers 5.14.1, torch 2.11.0+cu128), the
    accelerator software (CUDA 12.8) and the accelerator (an RTX 5070 Ti), with
    `software-environment.txt` hashed into the record;
  - when the data was collected, and that it is synthetic;
  - `data-governance.md` and `human-oversight.md`, by hash. `human-oversight.md`
    says a person at KHALM reviews the model's sample answers before it is shown
    in public, and that the model is not shown if a reviewed answer is wrong.
    Those answers are in `train-log.json`, so a reader can see what was
    reviewed.

    **That review was done on 2026-09-16, and all three answers were found
    right — but not in the order the document states.** The weights went up on
    Hugging Face a few hours before the review finished. Everything the document
    promises has happened; the sequence it promises had already been broken by
    the time it did. It is written down here rather than quietly left out,
    because it is the plainest lesson this folder has to offer: a governance
    document you commit to by hash stops being a description of your intentions
    and becomes a statement a reader is entitled to hold you to — and the first
    party this one caught was the issuer who signed it.
- **What it does not state**: no trusted execution environment and no hardware
  identity, no deployment, no parameter count, and no data residency. Its own
  `policy_compliance` is `indeterminate` with no rule evaluated — the grading
  below is done by running a pack here, not read out of the record.

## What "compliant" means here

All five reference packs return compliant (`pack-results.txt`). That is the pack
author's reading of the cited text, applied to what this record can show. It is
not a legal finding, not a certification, and no pack can check that a statement
is true — `docs/POLICY_PACKS.md` sets out what these packs do and do not mean,
and who may write one.

One rule fails, and it should: RATS's *recommended* hardware-rooted measurement,
because the training ran on an ordinary GPU with no trusted execution
environment, and the record says so. A recommended rule that fails does not make
the record non-compliant; it tells you what the evidence does not reach.

## Reproducing it

The 200 training records are here in full, so anyone can read exactly what the
model was taught and recompute the record's count, digest and Merkle root over
them.

Retraining is a different matter. A re-run will not in general produce
byte-identical weights, so it would have a different `model_hash`, and the
record above would not describe it. This example is made to be *checked*, not
to be re-derived.
