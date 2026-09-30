# A `vmr.agent` log written by another runtime

This example shows that any agent runtime, in any language, can write a
Verifiable Model Record audit log of the `vmr.agent` profile
(`specs/audit-profile-agent-v0.1.md`) with free software. The runtime starts
`vmr log seal` and writes one JSON object a line to it. `vmr` computes the
keyed digests, writes each entry and syncs it to the disk, then answers each
line.

`seal_session.py` is such a runtime, in Python with the standard library
only. It plays one small session:

- two tools registered;
- a turn;
- a call the `dispatch` gate permitted, which a person (`staff:4711`, a
  pseudonymous id) approved, and which then ran;
- a call the `guard` gate refused (`guard.not_requested`);
- the session's end.

It checks every answer, then copies the log's three public files here.

| File | What it is |
|---|---|
| `log.jsonl` | the audit log: 14 entries, one JSON line each, with no content, only keyed digests |
| `checkpoint.json` | the audit key's signed checkpoint over all 14 entries, made after `session.ended` |
| `audit-key.pub.json` | the audit key's public key file: what an auditor pins |

The audit key (`audit-key.pem`) and the content secret (`content-secret`)
stayed in a temporary directory, which the script deleted. They are not here,
and nobody can compute a new digest for this log.

## Verify it

```
vmr log verify --profile vmr.agent --log log.jsonl --audit-key audit-key.pub.json --checkpoint checkpoint.json
```

The first line of the output is `Audit log verified: 14 entries; 1 checkpoint
signed by the pinned audit key covers entries 0 to 13`. After it come the
entries' own statements: 1 session, 2 calls proposed, 1 refused by `guard`,
1 approval granted.

## Check one disclosed item

Entry 4 (`call.proposed`) holds the digest of the arguments the model
generated for `get_weather`. The script's run disclosed that one item: it
printed the item key with `vmr log disclose`, before the content secret was
deleted.

- item key: `11200c6264981efb8fbbdcd4e3ce185d1db9dcda617e774843dff5c578b0cd3d`
- content: `{"city": "Oslo", "day": "tomorrow"}`

Anyone can check the item without the secret. `arguments.txt` holds exactly
the disclosed content, and this command works in every shell:

```
vmr log check-item --log log.jsonl --index 4 --member arguments_digest --item-key 11200c6264981efb8fbbdcd4e3ce185d1db9dcda617e774843dff5c578b0cd3d --content-file arguments.txt
```

In bash or zsh the content can also be given inline:

```
vmr log check-item --log log.jsonl --index 4 --member arguments_digest --item-key 11200c6264981efb8fbbdcd4e3ce185d1db9dcda617e774843dff5c578b0cd3d --content-text '{"city": "Oslo", "day": "tomorrow"}'
```

Windows PowerShell 5.1 drops the inner double quotes when it passes such an
argument to a program, so the inline form does not match there. Use the file.

The output starts `Item matches: entry 4's arguments_digest is the digest of
this content under this item key`. Change one character of the content and it
says `Item does NOT match`, and the exit code is 3. The item key opens this one
digest and no other.

## Run it again

```
python seal_session.py --vmr path/to/vmr --out some/dir
```

Each run makes a new audit key, a new content secret and a new session id,
and so a different log. The interface it codes against, the input and output
lines of `vmr log seal`, is in `docs/CLI.md`.
