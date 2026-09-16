#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A test adapter for the VMR conformance runner: it answers every case from
the suite's own expected values, so the runner's plumbing and pass rule can be
tested without any implementation. It proves nothing about any implementation.

Environment switches (each a comma-separated list of "<set>/<case id>"):
    ORACLE_BREAK        answer the case wrongly
    ORACLE_UNSUPPORTED  answer {"unsupported": true}
    ORACLE_GARBAGE      write text that is not JSON
    ORACLE_SLEEP        sleep 30 seconds first
    ORACLE_CORE_ONLY=1  answer {"unsupported": true} to every case not tagged "core"
    ORACLE_ISSUE        the issuer answer: "json" (default), "cose",
                        "wrong-model-hash", "high-s" or "bad-signature"
    ORACLE_SUITE        the suite file (default: the committed suite)
    ORACLE_UNSIGNED=refusal
                        answer the pack-signature cases whose expected state
                        is `unsigned` with the refusal form policy-pack
                        format §3 also allows (QA QR-07)
    ORACLE_NO_REFUSAL_IDS=1
                        drop the `refusal` member from every pack-loader
                        answer, as an implementation that reports no refusal
                        identifiers would (QA QR-02)
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import run  # noqa: E402


def listed(name, key):
    return key in [k for k in os.environ.get(name, "").split(",") if k]


def issuer_answer(case):
    rec = json.loads(json.dumps(case.expected["record"]))
    payload = case.expected["signed_payload"].encode("utf-8")
    kid = rec["signature"]["signing_key_id"].encode("utf-8")
    rs = bytearray(run.b64url_decode(rec["signature"]["signature"][len("base64url:"):]))
    mode = os.environ.get("ORACLE_ISSUE", "json")
    if mode == "cose":
        return {"form": "cose", "bytes_hex": run.cose_envelope(kid, payload, bytes(rs)).hex()}
    if mode == "wrong-model-hash":
        rec["model_identity"]["model_hash"] = "sha256:" + "0" * 64
    elif mode == "high-s":
        s = int.from_bytes(rs[32:], "big")
        rs[32:] = (run.N - s).to_bytes(32, "big")
    elif mode == "bad-signature":
        rs[5] ^= 1
    rec["signature"]["signature"] = "base64url:" + run.b64url_encode(bytes(rs))
    return {"form": "json", "bytes_hex": json.dumps(rec, ensure_ascii=False).encode("utf-8").hex()}


def main():
    request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    key = request["case"]
    set_name, case_id = key.split("/", 1)
    if listed("ORACLE_SLEEP", key):
        time.sleep(30)
    if listed("ORACLE_GARBAGE", key):
        sys.stdout.write("this is not JSON\n")
        return
    if listed("ORACLE_UNSUPPORTED", key):
        sys.stdout.write('{"unsupported": true, "reason": "switched off"}\n')
        return
    suite = run.load_suite(os.environ.get("ORACLE_SUITE") or run.DEFAULT_SUITE, check_pins=False)
    case = run.find_case(suite, set_name, case_id)
    if os.environ.get("ORACLE_CORE_ONLY") == "1" and case.tag != "core":
        sys.stdout.write('{"unsupported": true, "reason": "core only"}\n')
        return
    answer = issuer_answer(case) if set_name == "issue" else json.loads(json.dumps(case.expected))
    if (set_name == "pack-signature" and os.environ.get("ORACLE_UNSIGNED") == "refusal"
            and isinstance(answer.get("pack_signature"), dict)
            and answer["pack_signature"].get("state") == "unsigned"):
        answer = {"pack_payload_hash": answer.get("pack_payload_hash"), "refusal": run.UNSIGNED_REFUSAL}
    if set_name == "pack-loader" and os.environ.get("ORACLE_NO_REFUSAL_IDS") == "1":
        answer.pop("refusal", None)
    if listed("ORACLE_BREAK", key):
        if set_name == "verify":
            answer["check"] = "json.syntax" if answer.get("check") != "json.syntax" else "input.form"
        else:
            answer = {"broken": True}
    sys.stdout.write(json.dumps(answer, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
