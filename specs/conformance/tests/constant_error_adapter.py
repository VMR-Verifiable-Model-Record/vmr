#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""An adapter that answers `{"result": "error"}` to every case, whatever it
is: no refusal identifier, no hash, nothing else.

It exists for one test (QA QR-02, 2026-09-16). Before the fix round, the
runner compared a pack-loader refusal identifier only when the answer
volunteered one, so this adapter passed 61 of the 73 pack-loader cases and
the whole refusal taxonomy of policy-pack format §3 went untested. An
adapter descriptor now declares whether the implementation reports those
identifiers, and one that says it does is compared on every refusal case, so
this adapter fails them.

It proves nothing about any implementation, and it is not a conformance
adapter: it answers no operation correctly.
"""
import sys


def main():
    sys.stdin.buffer.read()
    sys.stdout.write('{"result": "error"}\n')


if __name__ == "__main__":
    main()
