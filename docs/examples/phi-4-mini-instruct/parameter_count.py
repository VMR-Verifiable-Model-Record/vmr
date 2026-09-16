#!/usr/bin/env python3
"""The parameter count the headline record states (docs/dev/task-10.13a.md §5.5).

vmr reads no model format (D13a-9): a record's parameter_count is the issuer's
statement. This script is how this example's issuer counted: it reads only the
JSON header at the start of each `.safetensors` file of the model folder (an
8-byte little-endian length, then that many bytes of JSON naming every tensor
with its shape) and adds up the element count of every tensor stored. It never
reads a tensor's data. Python's standard library only.

    python parameter_count.py <model folder>

prints {"files": {<name>: <count>}, "parameter_count": <sum>} as JSON. For
microsoft/Phi-4-mini-instruct @ cfbefac the folder holds two shards; tensors
the model ties (its output layer shares the input embedding) are stored once,
so they are counted once.
"""

import json
import os
import struct
import sys

MAX_HEADER_BYTES = 100 * 1024 * 1024  # the safetensors format's own limit


def tensor_counts(path):
    """{tensor name: element count} from the header of one .safetensors file."""
    with open(path, "rb") as f:
        raw = f.read(8)
        if len(raw) != 8:
            raise ValueError("{}: shorter than a safetensors header".format(path))
        (length,) = struct.unpack("<Q", raw)
        if length > MAX_HEADER_BYTES:
            raise ValueError("{}: a header of {} bytes is over the format's limit".format(path, length))
        header = json.loads(f.read(length).decode("utf-8"))
    counts = {}
    for name, info in header.items():
        if name == "__metadata__":
            continue
        n = 1
        for dim in info["shape"]:
            n *= dim
        counts[name] = n
    return counts


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    folder = argv[1]
    names = sorted(n for n in os.listdir(folder) if n.endswith(".safetensors"))
    if not names:
        print("no .safetensors file in {}".format(folder))
        return 1
    files, seen, total = {}, set(), 0
    for name in names:
        counts = tensor_counts(os.path.join(folder, name))
        repeated = seen.intersection(counts)
        if repeated:
            raise ValueError("tensor {} is stored in more than one file".format(sorted(repeated)[0]))
        seen.update(counts)
        files[name] = sum(counts.values())
        total += files[name]
    print(json.dumps({"files": files, "parameter_count": total}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
