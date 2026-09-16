#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes the VMR conformance suite's generated files from the committed vectors.

    python build_suite.py            # write conformance/suite.json and conformance/issuer-cases.json
    python build_suite.py --check    # exit 1 if either file is stale

* conformance/issuer-cases.json: the issuer cases, built only from
  test-vectors/record/example-general-v0.1.json: its files, its record and its
  test-only key. No implementation computes any expected value.
* conformance/suite.json: "files" (a SHA-256 pin of every file a case reads),
  "sets" (every case of every set, in the vectors' order, each tagged "core",
  "profile:<name>" or "profile-gated:<name>") and
  "general_checks_on_engine_records". Its other members (versions, roles and
  their required_profiles, profiles) are kept as the file has them: they are
  edited by hand.

A case is tagged "profile:snn-compact-v1" when a record it holds (the input, a
predecessor, a policy case's record or its context's predecessors) holds the
JSON string "snn-compact-v1", compared exactly as spec §7.1 compares
model_format: as its model_format, or inside a model_identity written some
other way (fail-model-identity-as-array writes it as an array). Every other
case is "core". "general_checks_on_engine_records" lists the tagged cases
that test a rule of the general format rather than the profile's own rules
(record-format §7.4): the cases to copy onto general-description records if
the profile becomes optional.

GATED_CASES names the one case retagged "profile-gated:<name>" instead of
plain "profile:<name>" (QA gap 1, the owner, 2026-09-16). Every other
profile-tagged case is skipped outright by a run that neither claims nor
requires its profile (run.py's is_skipped), so record-format §7.1's rule that
an implementation MUST answer "unsupported", not invalid or a real verdict,
for a registered profile it does not implement has no case anywhere that
reaches an adapter to exercise it. A "profile-gated" case is never skipped:
run.py requires {"unsupported": true} from a run that does not claim (or
have required) its profile, and the case's own recorded answer from one that
does - so an implementation that does support snn-compact-v1 (KHALM's
included) is still checked for real, exactly as today.

This reuses "verify/pass-vector-json", the suite's own committed
snn-compact-v1 vector, already a real, passing engine-profile record - rather
than a second, made-up "registered" profile identifier invented only for this
test. The alternative (rejected): register a test-only "example" profile
identifier in record-format-v0.1.md so a synthetic model_format would count
as "registered" under §7.1's own text. That would grow the specification with
a profile it does not really have, for a rule that snn-compact-v1 - the one
profile v0.1 actually registers - already exercises correctly: KHALM's
adapter, which claims snn-compact-v1, must still answer this case for real,
and an adapter claiming no profile (QA's second adapter included) must answer
it unsupported. See docs/handoffs/2026-09-16-conformance-gaps.md.
"""
import base64
import copy
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SPECS = os.path.dirname(HERE)
PROFILE = "snn-compact-v1"
KEY_LABEL = b"khalm v0.1 test-vector signing key"
JSON_STRING = re.compile(rb'"((?:[^"\\]|\\.)*)"')
SUITE = "conformance/suite.json"
ISSUER = "conformance/issuer-cases.json"

HEADER = {
    "suite": "vmr-conformance",
    "suite_version": "0.1.1",
    "specification_version": "0.1",
    "protocol": "vmr-conformance/0.1",
    "roles": {
        # No role requires a profile (the owner, 2026-09-16, QA QR-09): an
        # implementation that supports no registered profile can be
        # conformant. The list is here as well as in suite.json so that a
        # regeneration from scratch cannot restore the requirement.
        "verifier": {"required_profiles": [], "sets": ["record-payload", "verify", "trust-store"]},
        "issuer": {"required_profiles": [], "sets": ["issue", "model-hash"]},
        "policy-evaluator": {"required_profiles": [],
                             "sets": ["policy-evaluation", "pack-loader", "pack-signature"]},
    },
    "profiles": {
        PROFILE: {"status": "defined", "specification": "record-format-v0.1.md §7.4"},
        "audit-log": {"status": "planned", "specification": "the audit-log document split from "
                      "sovereignty-format-v0.1.md; its cases join a later suite version"},
    },
}

SETS = [
    ("record-payload", "record.signed_payload", None),
    ("verify", "record.verify", "test-vectors/verify/cases.json"),
    ("trust-store", "trust_store.load", "test-vectors/trust-store/cases.json"),
    ("issue", "record.issue", ISSUER),
    ("model-hash", "model_hash", "test-vectors/model-hash/cases.json"),
    ("policy-evaluation", "policy.evaluate", "test-vectors/policy/cases.json"),
    ("pack-loader", "policy_pack.load", "test-vectors/policy/pack-loader.json"),
    ("pack-signature", "policy_pack.signature", "test-vectors/policy/pack-signature.json"),
]
RECORD_VECTORS = ["example-v0.1", "example-general-v0.1"]


def read(rel):
    with open(os.path.join(SPECS, rel), "rb") as f:
        return f.read()


def render(doc):
    return (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def doc_bytes(d):
    data = bytes.fromhex(d["hex"]) if "hex" in d else d["text"].encode("utf-8")
    return data + b" " * d.get("append_spaces", 0)


def names_profile(data):
    for m in JSON_STRING.finditer(data):
        try:
            if json.loads(b'"' + m.group(1) + b'"') == PROFILE:
                return True
        except ValueError:
            continue
    return False


def issuer_doc():
    g = json.loads(read("test-vectors/record/example-general-v0.1.json"))
    record = g["record"]
    declared = copy.deepcopy(record)
    del declared["signature"]
    for k in ("public_key", "key_id"):
        del declared["issuer"][k]
    for k in ("learned_state_components", "learned_state_hash", "model_hash"):
        del declared["model_identity"][k]
    for k in ("training_input_count", "training_input_digest", "training_input_merkle_root"):
        del declared["learning_provenance"][k]
    files = []
    for f in g["files"]:
        data = f["text"].encode("utf-8")
        if "sha256:" + hashlib.sha256(data).hexdigest() != f["sha256"]:
            raise SystemExit("the general vector's file %s does not hash to its sha256" % f["name"])
        files.append({"name": f["name"], "bytes_hex": data.hex()})
    key = dict(record["issuer"]["public_key"])
    key["d"] = base64.urlsafe_b64encode(hashlib.sha256(KEY_LABEL).digest()).rstrip(b"=").decode("ascii")
    case = {
        "id": "issue-general-open-weights-not-held",
        "description": "The general conformance vector's model (four synthetic files, not a real model) described "
                       "by a party that holds the files and not the training records. Given the declared members, "
                       "the files, the names of the components and the key, an issuer makes the vector's record: "
                       "the components' hashes and sizes, learned_state_hash and model_hash (named-set digests, "
                       "spec §7.2, §7.3), the training commitment of a not-held disclosure (§8.4), the issuer's "
                       "public key and key id (§5), and a low-s ES256 signature (§4). Its signature may differ "
                       "from the vector's; every other byte of the signed payload may not.",
        "input": {"declared": declared, "model_files": files,
                  "learned_state_components": [c["name"] for c in record["model_identity"]["learned_state_components"]],
                  "training_records": None, "signing_key": key},
        "expected": {"record": record, "signed_payload": g["expected"]["signed_payload"],
                     "signed_payload_hash": g["expected"]["signed_payload_hash"]},
    }
    return {
        "vector_version": "0.1",
        "description": "VMR conformance issuer cases v0.1 (CC0-1.0), built by specs/conformance/build_suite.py "
                       "from test-vectors/record/example-general-v0.1.json only. The signing key is the vectors' "
                       "test-only key: its secret scalar is SHA-256(\"khalm v0.1 test-vector signing key\"). Never "
                       "use it for anything real.",
        "cases": [case],
    }


def case_records(set_name, rel, raw_doc):
    """(id, [record bytes]) for every case of a set, in order."""
    if set_name == "record-payload":
        for cid in RECORD_VECTORS:
            yield cid, [read("test-vectors/record/%s.json" % cid)]
        return
    for c in raw_doc["cases"]:
        records = []
        if set_name == "verify":
            records = [doc_bytes(c["input"])] + [doc_bytes(p) for p in c["previous"]]
        elif set_name == "policy-evaluation":
            records = [c["record"]["text"].encode("utf-8")]
            records += [p["text"].encode("utf-8") for p in (c.get("context") or {}).get("predecessors", [])]
        elif set_name == "issue":
            records = [json.dumps(c["expected"]["record"]).encode("utf-8")]
        yield c["id"], records


# Cases of the profile's own rules that name it in no id, and so have no
# general-description twin (the owner, 2026-09-16): the general description
# does not check parameter_count (spec §7.3), and a policy case over the
# committed engine artifact cannot be described generally without ceasing to
# be that artifact. The verify generator keeps the same list.
PROFILE_ONLY_CASES = {("verify", "fail-consistency-parameter-count")}

# QA gap 1 (the owner, 2026-09-16): the one case retagged "profile-gated:
# <name>" instead of "profile:<name>", so it is never skipped - see the
# module docstring. "verify/pass-vector-json" is already a real, passing
# snn-compact-v1 record; the check below catches the vector drifting away
# from that profile without anyone updating this mapping.
GATED_CASES = {("verify", "pass-vector-json"): PROFILE}


def profile_own(set_name, case_id, doc=None):
    """A case of the profile's own rules (§7.4), or the profile's vector: one
    with no general-description twin."""
    if (set_name, case_id) in PROFILE_ONLY_CASES:
        return True
    if (set_name, case_id) == ("record-payload", "example-v0.1"):
        return True
    if set_name == "policy-evaluation":
        return case_id.endswith("-demo-record")
    return set_name == "verify" and "profile" in case_id


def outputs():
    issuer = render(issuer_doc())
    try:
        existing = json.loads(read(SUITE))
    except FileNotFoundError:
        existing = HEADER
    suite = {k: existing.get(k, v) for k, v in HEADER.items()}
    files, sets, general = {}, {}, []
    for rel in ["test-vectors/record/%s.json" % v for v in RECORD_VECTORS]:
        files[rel] = read(rel)
    stores = "test-vectors/verify/trust-stores"
    for name in sorted(os.listdir(os.path.join(SPECS, stores))):
        files[stores + "/" + name] = read(stores + "/" + name)
    for set_name, operation, rel in SETS:
        raw_doc = None
        if rel is not None:
            data = issuer if rel == ISSUER else read(rel)
            files[rel] = data
            raw_doc = json.loads(data)
        tags = {}
        for cid, records in case_records(set_name, rel, raw_doc):
            if cid in tags:
                raise SystemExit("%s: case id %s repeated" % (set_name, cid))
            tags[cid] = "profile:" + PROFILE if any(names_profile(r) for r in records) else "core"
            gate = GATED_CASES.get((set_name, cid))
            if gate is not None:
                if tags[cid] != "profile:" + gate:
                    raise SystemExit("%s/%s: expected to name the profile %s (GATED_CASES)"
                                     % (set_name, cid, gate))
                tags[cid] = "profile-gated:" + gate
            if tags[cid] != "core" and not profile_own(set_name, cid, raw_doc):
                general.append(set_name + "/" + cid)
        sets[set_name] = {"operation": operation, "file": rel, "cases": tags}
    suite["files"] = {rel: "sha256:" + hashlib.sha256(files[rel]).hexdigest() for rel in sorted(files)}
    suite["sets"] = sets
    suite["general_checks_on_engine_records"] = general
    return {ISSUER: issuer, SUITE: render(suite)}


def main():
    check = sys.argv[1:] == ["--check"]
    stale = []
    for rel, data in outputs().items():
        path = os.path.join(SPECS, rel)
        try:
            current = read(rel)
        except FileNotFoundError:
            current = None
        if current != data:
            stale.append(rel)
            if not check:
                with open(path, "wb") as f:
                    f.write(data)
    for rel in stale:
        print(("stale: " if check else "wrote: ") + rel)
    return 1 if check and stale else 0


if __name__ == "__main__":
    sys.exit(main())
