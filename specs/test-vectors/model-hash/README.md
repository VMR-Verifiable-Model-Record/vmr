# Model-hash vectors — the named-set digest and training records

`cases.json` holds the expected results of the rules of
[`record-format-v0.1.md`](../../record-format-v0.1.md) §7.2 (names, the
member encoding and the named-set digest) and §8.2–§8.3 (the digest and Merkle
root of `named-set-v1` training records). A verifier never computes these: a
party holding a model's files, or its training records, does. An
implementation that hashes models or records conforms if it reproduces every
case.

## The rules, in one place

- **Name.** One or more segments joined by `/`. No segment is empty, `.` or
  `..`. Names are compared exactly: no case folding, no Unicode normalisation.
- **Order.** A set is written in ascending order of its names' UTF-8 bytes
  (Unicode scalar value order), none repeated.
- **Member encoding.** `E(n, b)` = the name's UTF-8 byte length as a u64
  big-endian ‖ the name's UTF-8 bytes ‖ SHA-256(b).
- **Named-set digest.** `sha256:` + hex(SHA-256(E(n_1, b_1) ‖ … ‖ E(n_k, b_k))).
  The digest of no members is the SHA-256 of no bytes.
- **`named-set-v1` records.** `training_input_count` is the number of records,
  `training_input_digest` their named-set digest, and
  `training_input_merkle_root` the root of §8.3's tree whose leaf data is each
  record's member encoding, in name order.

## Case kinds

| `kind` | Given | Expected |
|---|---|---|
| `named-set-digest` | `members`: each `name`, its bytes as `bytes_hex`, and their `sha256` | `digest` |
| `named-set-digests` | `sets`: two or more named sets of members | a digest for each set, no two of them equal (in `digest-rename-versus-swap`, `original`, `renamed` and `swapped`) |
| `name` | `name` | `accepted`, and a `reason` when refused: `empty`, `empty-segment`, `dot-segment` or `dotdot-segment` |
| `set-refused` | `names`, in the order given | `refused_at`, the index of the first name that does not come after the one before it, and `reason` `not-ascending` |
| `named-set-records` | `record_format` `named-set-v1`, `members` | `training_input_count`, `training_input_digest`, `training_input_merkle_root` |

`digest-rename-versus-swap` is why names are bound: over
the members' SHA-256s alone, `{a: X, b: Y}` renamed to `{b: Y, c: X}` and
swapped to `{a: Y, b: X}` would share one digest. OpenSSF Model Signing v1.0
computes its root digest that way, so its root digest is not this digest; a
manifest of its `files` kind with SHA-256 lists the names and digests from
which this digest follows.

**Added on 2026-09-14** (spec §7.2). Six cases follow
the 27 earlier ones, each unchanged:
- `name-accepted-backslash` and `name-accepted-nfd`: a name is taken as the
  file system stores it. A `\` inside a name is a name character, and a name
  in NFD is not normalised.
- `digest-nfc-versus-nfd`: one byte string under the NFC and under the NFD
  spelling of `modèle.bin` gives two digests.
- `digest-case-twins`: `Tokenizer.json` and `tokenizer.json` are two members;
  the one file a case-insensitive file system would keep is another set.
- `digest-separator-order` and `set-refused-path-part-order`: `a-b.bin`,
  `a.bin`, `a/x.bin` is the set's order, since `-` and `.` sort before `/`.
  The order by path parts, `a/x.bin` first, which OpenSSF Model Signing's
  library uses, is refused, so a converter from such a manifest re-sorts.

What no JSON vector can hold, a tool follows from §7.2's text:
- a tool given one file names it by its own name, with no directory, and a
  tool given a folder names every file by its path in that folder, even when
  the folder holds one file;
- a file whose name is not a sequence of Unicode scalar values (bytes that
  are not UTF-8, an unpaired surrogate) makes the tool refuse the folder;
- a link (a symbolic link, or any other entry the file system resolves to
  another path, such as a Windows directory junction) that resolves to a
  file is hashed as that file, under the link's own name, and any other link
  makes the tool refuse the folder;
- one folder gives one digest only with the same names and the same bytes: a
  copy that rewrites names (NFD, `\` in an archive, a case-insensitive file
  system), adds files (a clone's `.git`, a download cache, `.DS_Store`),
  converts line endings, or writes each link as a small file holding its
  target (a checkout that cannot create links) is another set of files.

## How it was generated

By the vmr-record crate's generator:

```
VMR_WRITE_VECTORS=1 cargo test -p vmr-record --test model_hash_vectors -- --ignored
```

It computes each expected digest and root from the definitions above (the
encodings concatenated, and the level-by-level Merkle construction), not
through the library's streaming `NamedSetDigest` or `MerkleStream`, which the
replay test `every_model_hash_vector_gives_its_expected_result` then checks.
Refusal reasons are written by hand. When the file was first written, every
case was recomputed independently with Python's `hashlib`. The file
regenerates byte for byte anywhere; `model_hash_vectors_are_reproducible`
fails if it drifts. No engine and no randomness.

The member bytes are synthetic. No real model, data set or vendor is named.
