# Audit-log test vectors v0.1

The cross-implementation contract of
[`../../audit-log-format-v0.1.md`](../../audit-log-format-v0.1.md). One file,
`cases.json`.

An implementation conforms when, for every case, it accepts what the case
marks `"accept"` and refuses the others with the refusal id in `"expect"`
(the `<namespace>.<name>` ids of the format document).

These vectors are CC0-1.0, as the other test vectors of this repository are.

## Structure

- `environment` — the fixed setup the cases share: the audit key's key id, the
  lines of a two-entry log (an `enforcer.started` and an `export.granted` of
  the `khalm-vmr.enforcer` profile, §5.2), and a signed checkpoint of that log.
- `logs` — a whole log file, read as §4.4 reads it: a valid log, a line that is
  not its JCS form, two lines swapped, a wrong `previous_root`, a torn tail,
  and a line that repeats a member. `raw` is the file's bytes, line feeds
  included.
- `entries` — one line, read on its own. A case with a `profile` member is for
  an implementation that has that profile (today only `khalm-vmr.enforcer`);
  every other case is the core's (§5.1), which accepts any `kind` §4.1's
  grammar allows and any object as its `detail`. The same foreign kind is
  accepted by the core and refused by the profile.
- `checkpoints` — a checkpoint verified on its own under the environment's
  audit key (§6), including its size, syntax, version, signature section,
  wrong key and invalid signature.
- `inclusion_proofs` and `consistency_proofs` — the proofs of §7 and §8 over a
  five-entry log, verified under the same key with no clock and no file.

A case with a `raw` string is fed verbatim, which is how the size, syntax and
repeated-member cases work; otherwise the document is the case's `checkpoint`
or `proof` member, and an implementation serialises it as it would receive it.

**One row has no case here.** An inclusion proof over §7's 262 144-byte limit
would put a quarter of a megabyte of padding in this file, so
`vmr-audit-log`'s `tests/limits.rs` checks that row instead. Every other
refusal id of §§4 to 8 has a case.

## The keys

Every key is derived from a fixed label, for tests only:
`sha256(label)` is the secret scalar. The labels are the ones the sovereignty
vectors used before the audit log was split out of them (task 10.13), so every
case that moved kept its signed bytes.

## Regenerating

    VMR_WRITE_VECTORS=1 cargo test -p vmr-audit-log --test vectors -- --ignored

in its own commit. `audit_log_vectors_are_reproducible` fails when the
committed bytes differ from a fresh generation, and every case is replayed by
`vmr/crates/vmr-audit-log/tests/vectors.rs`.
