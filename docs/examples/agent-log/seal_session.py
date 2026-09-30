#!/usr/bin/env python3
"""Play one small agent session into a vmr.agent audit log through `vmr log seal`.

The proof that a runtime in any language can write the log with free
software: this script uses Python's standard library only, starts
`vmr log seal`, writes one JSON object a line to it, and checks every answer.
The session: two tools registered, a turn, one call permitted by a person and
run, one call refused by the `guard` gate, and the session's end.

    python seal_session.py --vmr path/to/vmr [--out DIR]

It starts the log in a temporary directory (`vmr log init`), seals the
session, prints one disclosure (an item key and its content), and copies the
three public files -- log.jsonl, checkpoint.json and audit-key.pub.json -- to
--out (default: this script's directory). The audit key and the content
secret stay in the temporary directory, which is deleted: they are never
copied anywhere.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

APPROVER = "staff:4711"  # a pseudonymous id the deployment resolves, never a name


def sha256_of(text):
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class Sealer:
    """`vmr log seal` on a pipe: one event in, one answer out."""

    def __init__(self, vmr, directory):
        self.proc = subprocess.Popen(
            [vmr, "log", "seal", "--dir", directory],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            encoding="utf-8",
            bufsize=1,
        )
        self.next_index = 0

    def send(self, kind, detail, content=None):
        event = {"kind": kind, "detail": detail}
        if content is not None:
            event["content"] = content
        self.proc.stdin.write(json.dumps(event) + "\n")
        self.proc.stdin.flush()
        answer = json.loads(self.proc.stdout.readline())
        if answer != {"index": self.next_index}:
            sys.exit("unexpected answer to %s: %r" % (kind, answer))
        self.next_index += 1
        return answer["index"]

    def close(self):
        self.proc.stdin.close()
        if self.proc.wait() != 0:
            sys.exit("vmr log seal exited with %d" % self.proc.returncode)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--vmr", default="vmr", help="the vmr binary")
    parser.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)))
    args = parser.parse_args()

    work = tempfile.mkdtemp(prefix="vmr-agent-log-")
    try:
        directory = os.path.join(work, "log")
        subprocess.run([args.vmr, "log", "init", "--dir", directory], check=True, stdout=subprocess.DEVNULL)

        session = uuid.uuid4().urn
        sealer = Sealer(args.vmr, directory)
        settings = json.dumps({"temperature": 0.2, "max_tokens": 512}, sort_keys=True)
        sealer.send("session.started", {
            "session_id": session,
            "runtime": "example-runtime 0.1",
            "model": "example-model",
            "configuration_hash": sha256_of(settings),
        })
        sealer.send("tool.registered", {"session_id": session, "tool": "get_weather", "provider": "example-tools"})
        sealer.send("tool.registered", {"session_id": session, "tool": "send_email", "provider": "example-tools"})
        sealer.send("turn.started", {"session_id": session, "turn": 0},
                    {"input_digest": {"text": "What is the weather in Oslo tomorrow?"}})

        # Call 0: permitted by dispatch, approved by a person, run.
        arguments = '{"city": "Oslo", "day": "tomorrow"}'
        proposed = sealer.send("call.proposed", {"session_id": session, "call": 0, "turn": 0, "tool": "get_weather"},
                               {"arguments_digest": {"text": arguments}})
        sealer.send("gate.decided", {"session_id": session, "call": 0, "gate": "dispatch", "decision": "permitted"})
        sealer.send("approval.requested", {"session_id": session, "call": 0},
                    {"presented_digest": {"text": "Allow get_weather for Oslo, tomorrow?"}})
        sealer.send("approval.granted", {"session_id": session, "call": 0, "approver": APPROVER, "latency_ms": 2300})
        sealer.send("gate.decided", {"session_id": session, "call": 0, "gate": "approval", "decision": "permitted"})
        sealer.send("call.executed", {"session_id": session, "call": 0, "outcome": "ok"},
                    {"result_digest": {"json": {"forecast": "rain", "temp_c": 7}}})

        # Call 1: refused by the guard gate (the user asked for no e-mail).
        sealer.send("call.proposed", {"session_id": session, "call": 1, "turn": 0, "tool": "send_email"},
                    {"arguments_digest": {"text": '{"to": "someone@example.org", "body": "..."}'}})
        sealer.send("gate.decided", {"session_id": session, "call": 1, "gate": "guard", "decision": "refused",
                                     "refusal": "guard.not_requested"})
        sealer.send("call.refused", {"session_id": session, "call": 1, "gate": "guard",
                                     "refusal": "guard.not_requested"})
        sealer.send("session.ended", {"session_id": session, "outcome": "completed"})
        sealer.close()

        # One disclosure: the holder hands over this item key and the content.
        item_key = subprocess.run(
            [args.vmr, "log", "disclose", "--dir", directory, "--index", str(proposed), "--member", "arguments_digest"],
            check=True, stdout=subprocess.PIPE, encoding="utf-8",
        ).stdout.strip()
        print("sealed %d entries; session %s" % (sealer.next_index, session))
        print("disclosure: entry %d arguments_digest" % proposed)
        print("  item key: %s" % item_key)
        print("  content:  %s" % arguments)

        os.makedirs(args.out, exist_ok=True)
        for name in ("log.jsonl", "checkpoint.json", "audit-key.pub.json"):
            shutil.copyfile(os.path.join(directory, name), os.path.join(args.out, name))
        print("copied log.jsonl, checkpoint.json and audit-key.pub.json to %s" % args.out)
    finally:
        # The audit key and the content secret go with the directory.
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
