#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The VMR conformance runner, for the Verifiable Model Record specification v0.1.

    python run.py ADAPTER.json [--report FILE] [--jobs N] [--timeout SECONDS]
                               [--set NAME[,NAME...]] [--suite FILE]

It runs every case of the roles an adapter descriptor claims through the
adapter's command, one process per case: a JSON request on standard input, one
JSON object on standard output. It compares only the members the
specifications make contract, prints a summary and, with --report, writes the
JSON report. Python 3.8 or later, standard library only; it needs no
implementation's code, KHALM's included. The protocol, the roles and the pass
rule are in README.md next to this file.

Exit status: 0 when the implementation is conformant (or, for a partial run
with --set, when every case run passed); 1 otherwise; 2 when the suite, the
adapter descriptor or the arguments cannot be used.
"""
import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from collections import namedtuple

PROTOCOL = "vmr-conformance/0.1"
HERE = os.path.dirname(os.path.abspath(__file__))
SPECS = os.path.dirname(HERE)
DEFAULT_SUITE = os.path.join(HERE, "suite.json")
ANCHOR_ROLES = ("verifier", "issuer")
Case = namedtuple("Case", "set id tag operation input expected")
Handler = namedtuple("Handler", "operation cases compare")


class SuiteError(Exception):
    """The suite, the adapter descriptor or the arguments cannot be used."""


# ---------------------------------------------------------------- JSON and bytes

def strict_json(text):
    """Parse JSON, refusing a repeated member, NaN and Infinity."""
    def pairs(items):
        obj = {}
        for k, v in items:
            if k in obj:
                raise ValueError("repeated member " + json.dumps(k))
            obj[k] = v
        return obj

    def constant(name):
        raise ValueError("not JSON: " + name)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def same(a, b):
    """JSON equality that keeps types apart (true is not 1, 1 is not 1.0)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return a == b


def difference(a, b, path=""):
    """The JSON pointer of the first place a and b differ, or None."""
    if type(a) is not type(b):
        return path or "/"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                return path + "/" + k
            d = difference(a[k], b[k], path + "/" + k)
            if d is not None:
                return d
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return path or "/"
        for i, (x, y) in enumerate(zip(a, b)):
            d = difference(x, y, "%s/%d" % (path, i))
            if d is not None:
                return d
        return None
    return None if a == b else (path or "/")


def show(value):
    """A value as ASCII JSON: safe to print, whatever an adapter wrote."""
    return json.dumps(value, ensure_ascii=True)


def sha256_tag(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    if not isinstance(text, str) or not set(text) <= B64URL or len(text) % 4 == 1:
        raise ValueError("not base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64url_encode(data) != text:
        raise ValueError("not canonical base64url")
    return data


# ---------------------------------------------------------------- ES256 (P-256), verification only

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def on_curve(point):
    x, y = point
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x + 3 * x - B) % P == 0


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def point_mul(k, point):
    result = None
    for bit in bin(k)[2:]:
        result = point_add(result, result)
        if bit == "1":
            result = point_add(result, point)
    return result


def es256_verify(x, y, message, rs):
    """ECDSA P-256 / SHA-256 over message; rs is r || s, low-s required (spec §4.2)."""
    if len(rs) != 64 or not on_curve((x, y)):
        return False
    r, s = int.from_bytes(rs[:32], "big"), int.from_bytes(rs[32:], "big")
    if not (1 <= r < N and 1 <= s < N) or s > N // 2:
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, N - 2, N)
    point = point_add(point_mul(e * w % N, G), point_mul(r * w % N, (x, y)))
    return point is not None and point[0] % N == r


def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    return bytes([major << 5 | 26]) + n.to_bytes(4, "big")


def _bstr(data):
    return _head(2, len(data)) + data


def sig_structure(kid, payload):
    """The bytes ES256 signs (spec §4.1)."""
    protected = b"\xa2\x01\x26\x04" + _bstr(kid)
    return b"\x84" + _head(3, 10) + b"Signature1" + _bstr(protected) + b"\x40" + _bstr(payload)


def cose_envelope(kid, payload, rs):
    """The one COSE form of a record (spec §4.4)."""
    return b"\x84" + _bstr(b"\xa2\x01\x26\x04" + _bstr(kid)) + b"\xa0" + _bstr(payload) + _bstr(rs)


# ---------------------------------------------------------------- the sets: requests and comparisons

#: The most bytes an adapter's answer may hold. A conformance answer is a
#: small JSON object - the largest here is the issuer's record, a few
#: kilobytes - so a megabyte is generous, and an adapter that streams for
#: ever no longer fills this process's memory (QA QR-34).
MAX_ANSWER_BYTES = 1_048_576


def _read(rel):
    """A file the suite names, under specs/ and nowhere else (QA QR-34): a
    suite is data, so a path of its own that climbed out of the tree, or an
    absolute one, is refused before it is opened."""
    if rel.startswith(("/", "\\")) or ".." in rel.replace("\\", "/").split("/") or os.path.isabs(rel):
        raise SuiteError("the suite names the path %s, which is not inside specs/" % show(rel))
    path = os.path.normpath(os.path.join(SPECS, rel))
    if os.path.commonpath([os.path.abspath(path), os.path.abspath(SPECS)]) != os.path.abspath(SPECS):
        raise SuiteError("the suite names the path %s, which is not inside specs/" % show(rel))
    with open(path, "rb") as f:
        return f.read()


def _vector(suite_set):
    return json.loads(_read(suite_set["file"]).decode("utf-8"))


def _doc(d):
    data = bytes.fromhex(d["hex"]) if "hex" in d else d["text"].encode("utf-8")
    return data + b" " * d.get("append_spaces", 0)


def _bytes(data, **extra):
    return dict(extra, bytes_hex=data.hex())


def _members(expected, answer, names):
    for n in names:
        if not same(answer.get(n), expected.get(n)):
            return "%s %s; expected %s" % (n, show(answer.get(n)), show(expected.get(n)))
    return None


def _record_payload_cases(suite_set):
    for cid in suite_set["cases"]:
        doc = json.loads(_read("test-vectors/record/%s.json" % cid).decode("utf-8"))
        text = json.dumps(doc["record"], ensure_ascii=False, indent=2).encode("utf-8")
        yield cid, {"record": _bytes(text)}, {"signed_payload": doc["expected"]["signed_payload"],
                                              "signed_payload_hash": doc["expected"]["signed_payload_hash"],
                                              "key_id": doc["record"]["issuer"]["key_id"]}


def _verify_cases(suite_set):
    for c in _vector(suite_set)["cases"]:
        store = _read("test-vectors/verify/trust-stores/%s.json" % c["trust_store"])
        yield c["id"], {
            "record": _bytes(_doc(c["input"]), form=c["input"]["form"]),
            "trust_store": _bytes(store),
            "evaluation_time": c["evaluation_time"],
            "previous": [_bytes(_doc(p), form=p["form"]) for p in c["previous"]],
            "require_complete_lineage": c["require_complete_lineage"],
        }, {"verdict": c["expected"]["verdict"], "check": c["expected"].get("check"),
            "lineage": c["expected"].get("lineage")}


def _cmp_verify(expected, answer, options):
    return _members(expected, answer, ["verdict", "check"] + (["lineage"] if expected["lineage"] else []))


def _trust_store_cases(suite_set):
    for c in _vector(suite_set)["cases"]:
        yield c["id"], {"store": _bytes(_doc(c["input"]))}, c["expected"]


def _cmp_trust_store(expected, answer, options):
    return _members(expected, answer, ["result", "sha256" if expected["result"] == "ok" else "kind"])


def _model_hash_cases(suite_set):
    for c in _vector(suite_set)["cases"]:
        yield c["id"], {k: v for k, v in c.items() if k not in ("id", "description", "expected")}, c["expected"]


def _cmp_model_hash(expected, answer, options):
    return _members(expected, answer, list(expected))


def _issue_cases(suite_set):
    for c in _vector(suite_set)["cases"]:
        yield c["id"], c["input"], c["expected"]


def _cmp_issue(expected, answer, options):
    want = expected["record"]
    kid = want["signature"]["signing_key_id"].encode("utf-8")
    payload = expected["signed_payload"].encode("utf-8")
    if not isinstance(answer.get("bytes_hex"), str):
        return "no bytes_hex"
    try:
        data = bytes.fromhex(answer["bytes_hex"])
    except ValueError:
        return "bytes_hex is not hex"
    form = answer.get("form")
    if form == "json":
        try:
            record = strict_json(data.decode("utf-8"))
        except ValueError as e:
            return "the record is not JSON: %s" % show(str(e))
        if not isinstance(record, dict) or not isinstance(record.get("signature"), dict):
            return "the record has no signature section"
        body = {k: v for k, v in record.items() if k != "signature"}
        at = difference(body, {k: v for k, v in want.items() if k != "signature"})
        if at is not None:
            return "the record differs from the expected record at %s" % show(at)
        sig = record["signature"]
        if sorted(sig) != sorted(want["signature"]):
            return "signature section members %s" % show(sorted(sig))
        for n in ("algorithm", "signed_payload_hash", "signing_key_id"):
            if not same(sig[n], want["signature"][n]):
                return "signature.%s %s; expected %s" % (n, show(sig[n]), show(want["signature"][n]))
        text = sig["signature"]
        if not isinstance(text, str) or not text.startswith("base64url:"):
            return "signature.signature does not start with \"base64url:\""
        try:
            rs = b64url_decode(text[len("base64url:"):])
        except ValueError as e:
            return "signature.signature: %s" % e
    elif form == "cose":
        prefix = cose_envelope(kid, payload, bytes(64))[:-66]
        if len(data) != len(prefix) + 66 or not data.startswith(prefix + b"\x58\x40"):
            return "not the canonical COSE envelope (spec §4.4) of the expected record"
        rs = data[-64:]
    else:
        return "form %s; expected \"json\" or \"cose\"" % show(form)
    x = int.from_bytes(b64url_decode(want["issuer"]["public_key"]["x"]), "big")
    y = int.from_bytes(b64url_decode(want["issuer"]["public_key"]["y"]), "big")
    if not es256_verify(x, y, sig_structure(kid, payload), rs):
        return "the signature is not a low-s ES256 signature of the record under the issuer's key (spec §4.1, §4.2)"
    return None


def _policy_cases(suite_set):
    for c in _vector(suite_set)["cases"]:
        context = c.get("context")
        if context is not None:
            context = {"lineage_outcome": context["lineage_outcome"],
                       "predecessors": [{"signed_payload_hash": p["signed_payload_hash"],
                                         "record": _bytes(p["text"].encode("utf-8"))}
                                        for p in context["predecessors"]]}
        yield c["id"], {"pack": _bytes(c["pack"]["text"].encode("utf-8")),
                        "record": _bytes(c["record"]["text"].encode("utf-8")),
                        "evaluation_time": c["evaluation_time"], "context": context}, c["expected"]


def _cmp_policy(expected, answer, options):
    reason = _members(expected, answer, ["pack_payload_hash", "overall", "indeterminate", "policy_compliance"])
    if reason:
        return reason
    got = answer.get("results")
    if not isinstance(got, list) or len(got) != len(expected["results"]):
        return "results %s; expected %d results" % (show(got), len(expected["results"]))
    for i, (g, w) in enumerate(zip(got, expected["results"])):
        if not isinstance(g, dict):
            return "results[%d] is not an object" % i
        reason = _members(w, g, ["rule_id", "rule_type", "severity", "status", "evidence_hash"])
        if reason:
            return "results[%d]: %s" % (i, reason)
    return None


def _pack_loader_cases(suite_set):
    for c in _vector(suite_set)["cases"]:
        yield c["id"], {"pack": _bytes(_doc(c["pack"]))}, c["expected"]


def _cmp_pack_loader(expected, answer, options):
    if expected["result"] == "ok":
        return _members(expected, answer, ["result", "pack_payload_hash"])
    # Policy-pack format §9 leaves the identifiers optional, so the ADAPTER
    # DESCRIPTOR says whether this implementation reports them (QA QR-02).
    # When it does, every refusal case's identifier is compared, so an
    # adapter that answers "error" to everything without an identifier can no
    # longer pass the refusal taxonomy; when it does not, it must report
    # none, and its claim says the taxonomy was not exercised.
    reason = _members(expected, answer, ["result"])
    if reason is not None:
        return reason
    if options["reports_refusal_identifiers"]:
        return _members(expected, answer, ["refusal"])
    if answer.get("refusal") is not None:
        return ("refusal %s given, and the adapter descriptor says this implementation reports no refusal "
                "identifiers" % show(answer["refusal"]))
    return None


def _pack_signature_cases(suite_set):
    for c in _vector(suite_set)["cases"]:
        store = c["authority_store"]
        yield c["id"], {
            "pack": _bytes(c["pack"]["text"].encode("utf-8")),
            "trust_store": _bytes(c["trust_store"]["text"].encode("utf-8")),
            "authority_store": None if store is None else _bytes(store["text"].encode("utf-8")),
            "evaluation_time": c["evaluation_time"],
            "require_signed_pack": c["require_signed_pack"],
        }, {k: v for k, v in c["expected"].items() if k != "exit_code"}  # exit_code is one CLI's, not contract


#: Policy-pack format §184: a checker MAY refuse every unsigned pack and
#: report `pack_signature.unsigned` where the reference CLI reports the state
#: `unsigned`. Both answers conform, so the runner accepts either (QA QR-07).
UNSIGNED_REFUSAL = "pack_signature.unsigned"


def _cmp_pack_signature(expected, answer, options):
    if (isinstance(expected.get("pack_signature"), dict) and expected["pack_signature"].get("state") == "unsigned"
            and answer.get("refusal") == UNSIGNED_REFUSAL and answer.get("pack_signature") is None):
        # The refusing form: the payload hash is compared only when given,
        # since a checker that refuses the pack need not report one.
        return None if answer.get("pack_payload_hash") is None else _members(expected, answer, ["pack_payload_hash"])
    outcome, other = ("pack_signature", "refusal") if "pack_signature" in expected else ("refusal", "pack_signature")
    reason = _members(expected, answer, ["pack_payload_hash", outcome])
    if reason is None and answer.get(other) is not None:
        reason = "%s %s given; expected %s %s" % (other, show(answer[other]), outcome, show(expected[outcome]))
    return reason


HANDLERS = {
    "record-payload": Handler("record.signed_payload", _record_payload_cases,
                              lambda e, a, o: _members(e, a, ["signed_payload", "signed_payload_hash", "key_id"])),
    "verify": Handler("record.verify", _verify_cases, _cmp_verify),
    "trust-store": Handler("trust_store.load", _trust_store_cases, _cmp_trust_store),
    "issue": Handler("record.issue", _issue_cases, _cmp_issue),
    "model-hash": Handler("model_hash", _model_hash_cases, _cmp_model_hash),
    "policy-evaluation": Handler("policy.evaluate", _policy_cases, _cmp_policy),
    "pack-loader": Handler("policy_pack.load", _pack_loader_cases, _cmp_pack_loader),
    "pack-signature": Handler("policy_pack.signature", _pack_signature_cases, _cmp_pack_signature),
}


# ---------------------------------------------------------------- suite, descriptor, cases

def load_suite(path=DEFAULT_SUITE, check_pins=True):
    try:
        with open(path, "rb") as f:
            raw = f.read()
        suite = strict_json(raw.decode("utf-8"))
    except (OSError, ValueError) as e:
        raise SuiteError("cannot read the suite %s: %s" % (path, e))
    if suite.get("protocol") != PROTOCOL:
        raise SuiteError("the suite speaks %s; this runner speaks %s" % (show(suite.get("protocol")), PROTOCOL))
    for name, s in suite["sets"].items():
        if name not in HANDLERS or HANDLERS[name].operation != s["operation"]:
            raise SuiteError("this runner does not know the set %s (%s)" % (show(name), show(s.get("operation"))))
    if check_pins:
        for rel, pin in suite["files"].items():
            try:
                data = _read(rel)
            except OSError as e:
                raise SuiteError("cannot read %s: %s" % (rel, e))
            if sha256_tag(data) != pin:
                raise SuiteError("%s does not match the suite's pin: these are not the vectors suite %s names"
                                 % (rel, suite["suite_version"]))
    # QA QR-11: a required profile that contributes no case would pass
    # vacuously, because a role's profile map is built from the tags its cases
    # carry. That is a suite the runner cannot honour, not a pass.
    for role, spec in suite["roles"].items():
        tags = {t for n in spec["sets"] for t in suite["sets"][n]["cases"].values()}
        named = {tag_profile(t) for t in tags} - {None}
        for p in spec["required_profiles"]:
            if p not in named:
                raise SuiteError("the role %s requires the profile %s, and no case of its sets is tagged with it: "
                                 "the requirement would pass vacuously" % (show(role), show(p)))
    suite["_sha256"] = sha256_tag(raw)
    return suite


def cases_of_set(suite, name):
    s, h = suite["sets"][name], HANDLERS[name]
    out = []
    for cid, request_input, expected in h.cases(s):
        if cid not in s["cases"]:
            raise SuiteError("%s/%s is in the vectors but not in the suite" % (name, cid))
        out.append(Case(name, cid, s["cases"][cid], h.operation, request_input, expected))
    if [c.id for c in out] != list(s["cases"]):
        raise SuiteError("the suite's %s cases are not the vectors' cases" % name)
    return out


def find_case(suite, name, case_id):
    return next(c for c in cases_of_set(suite, name) if c.id == case_id)


def load_adapter(path, suite):
    try:
        with open(path, "rb") as f:
            d = strict_json(f.read().decode("utf-8"))
    except (OSError, ValueError) as e:
        raise SuiteError("cannot read the adapter descriptor %s: %s" % (path, e))
    ok = (isinstance(d, dict) and d.get("adapter_version") == "0.1"
          and isinstance(d.get("implementation"), dict)
          and all(isinstance(d["implementation"].get(k), str) for k in ("name", "version"))
          and isinstance(d.get("command"), list) and d["command"] and all(isinstance(c, str) for c in d["command"])
          and isinstance(d.get("roles"), list) and set(d["roles"]) <= set(suite["roles"])
          and isinstance(d.get("profiles"), list) and set(d["profiles"]) <= set(suite["profiles"]))
    if ok:
        # QA QR-02: policy-pack format §9 leaves the refusal identifiers
        # optional, so a descriptor that claims policy-evaluator (the only
        # role whose sets run policy_pack.load) says whether this
        # implementation reports them; silence there is no longer a pass. QA
        # gap 3 (the owner, 2026-09-16): a verifier- or issuer-only adapter
        # never runs a pack-loader case, so the field describes nothing of
        # its behaviour; it may omit it, and false - "reports none" - is
        # assumed.
        claims_pack_loader = "policy-evaluator" in d["roles"]
        stated = "reports_refusal_identifiers" in d
        ok = isinstance(d.get("reports_refusal_identifiers", False), bool) and (stated or not claims_pack_loader)
    if not ok:
        raise SuiteError("the adapter descriptor %s is not as README.md describes (adapter_version \"0.1\", "
                         "implementation name and version, command, roles and profiles this suite defines, "
                         "reports_refusal_identifiers true or false, required when roles includes "
                         "\"policy-evaluator\")" % path)
    d.setdefault("reports_refusal_identifiers", False)
    base = os.path.dirname(os.path.abspath(path))
    command = []
    for i, item in enumerate(d["command"]):
        value = sys.executable if item == "{python}" else os.path.expandvars(item)
        if "$" in value or re.search(r"%[A-Za-z_][A-Za-z0-9_]*%", value):
            raise SuiteError("the adapter command's %s names an environment variable that is not set" % show(item))
        if i == 0 and not os.path.isabs(value) and ("/" in value or os.sep in value):
            value = os.path.join(base, value)
        command.append(value)
    if not (os.path.isfile(command[0]) or shutil.which(command[0])):
        raise SuiteError("the adapter command %s is not found" % show(command[0]))
    return d, command, base


def run_case(case, command, cwd, timeout, options):
    request = {"protocol": PROTOCOL, "operation": case.operation, "case": case.set + "/" + case.id,
               "input": case.input}
    data = json.dumps(request, ensure_ascii=False).encode("utf-8")
    try:
        p = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd,
                           timeout=timeout)
        if len(p.stdout) > MAX_ANSWER_BYTES:
            return "error", None, "the answer is longer than %d bytes" % MAX_ANSWER_BYTES
    except subprocess.TimeoutExpired:
        return "error", None, "no answer within %g seconds" % timeout
    except OSError as e:
        return "error", None, "the adapter command could not start: %s" % show(str(e))
    try:
        answer = strict_json(p.stdout.decode("utf-8"))
        if not isinstance(answer, dict):
            raise ValueError("not an object")
    except ValueError as e:
        tail = p.stderr.decode("utf-8", "replace")[-300:]
        return "error", None, "the answer is not one JSON object (%s; exit status %d; standard error ends %s)" % (
            show(str(e)), p.returncode, show(tail))
    # QA gap 1 (the owner, 2026-09-16): a "profile-gated:<name>" case is sent
    # whether or not <name> is active (is_skipped never skips it). Record
    # format §7.1 requires {"unsupported": true} from a run that does not
    # claim (or have required) <name> - and, unlike an ordinary "unsupported"
    # answer, that is the correct, passing answer here, not a failure. A run
    # that does claim <name> is held to the case's own recorded answer, same
    # as any other case of that profile.
    gated = case.tag.startswith(GATED_PREFIX)
    unclaimed = gated and tag_profile(case.tag) not in options["active"]
    if answer.get("unsupported") is True:
        if unclaimed:
            return "pass", answer, None
        return "unsupported", answer, "the adapter does not support this case: %s" % show(answer.get("reason"))
    if unclaimed:
        return "fail", answer, ("record format §7.1: model_format names the registered profile %s, which this "
                                "run does not claim; the answer must be {\"unsupported\": true}"
                                % show(tag_profile(case.tag)))
    if "adapter_error" in answer:
        return "error", answer, "the adapter reported an error: %s" % show(answer["adapter_error"])
    try:
        reason = HANDLERS[case.set].compare(case.expected, answer, options)
    except (KeyError, TypeError, AttributeError, ValueError) as e:
        reason = "the answer is malformed: %s" % show(repr(e))
    return ("pass" if reason is None else "fail"), answer, reason


# ---------------------------------------------------------------- verdicts and the report

def active_profiles(suite, claimed_roles, claimed_profiles):
    """The profiles a run exercises: every claimed one, and every one a
    claimed role requires. A case of any other profile is skipped (QA QR-10):
    with no role requiring a profile since 2026-09-16, an implementation that
    does not claim one would otherwise be reported conformant while hundreds
    of its cases were listed as failures."""
    active = set(claimed_profiles)
    for name, spec in suite["roles"].items():
        if name in claimed_roles:
            active |= set(spec["required_profiles"])
    return active


#: A case tagged "profile-gated:<name>" is never skipped (QA gap 1, the
#: owner, 2026-09-16): unlike a plain "profile:<name>" case, it is sent to
#: the adapter whether or not <name> is active, so record-format §7.1's
#: "unsupported, not invalid" rule for a registered profile an implementation
#: does not claim has a case that actually reaches one. See build_suite.py's
#: module docstring (GATED_CASES) for which case this is and why.
GATED_PREFIX = "profile-gated:"


def tag_profile(tag):
    """The profile a case's tag names ("profile:<name>" or "profile-gated:
    <name>"), or None for "core"."""
    if tag == "core":
        return None
    prefix = GATED_PREFIX if tag.startswith(GATED_PREFIX) else "profile:"
    return tag[len(prefix):]


def is_skipped(case, active):
    if case.tag.startswith(GATED_PREFIX):
        return False
    return case.tag != "core" and tag_profile(case.tag) not in active


def verdicts(suite, cases, results, claimed_roles, claimed_profiles, partial, reports_refusals=True):
    passed = lambda c: results.get((c.set, c.id), (None,))[0] == "pass"  # noqa: E731
    roles = {}
    for name, spec in suite["roles"].items():
        entry = {"claimed": name in claimed_roles, "required_profiles": spec["required_profiles"], "passed": None}
        if entry["claimed"] and not partial:
            in_role = [c for c in cases if c.set in spec["sets"]]
            core = [c for c in in_role if c.tag == "core"]
            entry["core"] = {"cases": len(core), "passed": sum(map(passed, core))}
            entry["profiles"] = {}
            for p in sorted({tag_profile(c.tag) for c in in_role if c.tag != "core"}):
                pc = [c for c in in_role if tag_profile(c.tag) == p]
                ran = sum(1 for c in pc if (c.set, c.id) in results)  # a "profile-gated" case runs even if p is not active
                entry["profiles"][p] = {"cases": len(pc), "passed": sum(map(passed, pc)),
                                        "required": p in spec["required_profiles"], "skipped": len(pc) - ran}
            # A "profile-gated" case gates the role's pass/fail whether or not
            # its profile is active (QA gap 1): either answer can be correct,
            # but only one is, and getting it wrong is not a silent skip.
            gated = [c for c in in_role if c.tag.startswith(GATED_PREFIX)]
            entry["passed"] = (entry["core"]["passed"] == entry["core"]["cases"]
                               and all(v["passed"] == v["cases"] for v in entry["profiles"].values() if v["required"])
                               and all(map(passed, gated)))
        roles[name] = entry
    profiles = {}
    for name in suite["profiles"]:
        entry = {"claimed": name in claimed_profiles, "passed": None}
        if entry["claimed"] and not partial:
            pc = [c for c in cases if tag_profile(c.tag) == name]
            entry["cases"], entry["passed_cases"] = len(pc), sum(map(passed, pc))
            entry["passed"] = bool(pc) and entry["passed_cases"] == len(pc)
        profiles[name] = entry
    conformant = (not partial and any(r in claimed_roles for r in ANCHOR_ROLES)
                  and all(roles[r]["passed"] for r in claimed_roles)
                  and all(profiles[p]["passed"] for p in claimed_profiles))
    claim = None
    if conformant:
        claim = "VMR v%s conformant (vmr-conformance suite %s): %s" % (
            suite["specification_version"], suite["suite_version"],
            ", ".join(r for r in suite["roles"] if r in claimed_roles))
        if claimed_profiles:
            claim += "; profiles: " + ", ".join(p for p in suite["profiles"] if p in claimed_profiles)
        else:
            claim += "; no profile"
        if not reports_refusals:
            claim += "; pack-loader refusal identifiers not reported"
    return roles, profiles, conformant, claim


def summary(report):
    plain = lambda s: show(s)[1:-1]  # noqa: E731
    impl = report["implementation"]
    lines = ["VMR conformance suite %s, specification v%s" % (report["suite_version"], report["specification_version"]),
             "Implementation: %s %s" % (plain(impl["name"]), plain(impl["version"]))]
    for name, e in report["roles"].items():
        if not e["claimed"]:
            lines.append("Role %s: not claimed" % name)
        elif e["passed"] is None:
            lines.append("Role %s: not evaluated (partial run)" % name)
        else:
            parts = ["core %d of %d" % (e["core"]["passed"], e["core"]["cases"])]
            for p, v in e["profiles"].items():
                if v["skipped"] == v["cases"]:
                    parts.append("%s %d skipped (not claimed)" % (p, v["skipped"]))
                else:
                    # QA gap 1: a "profile-gated" case of this profile still
                    # ran (and so is not part of "skipped"), whether or not
                    # the profile itself is claimed.
                    extra = " (%d skipped)" % v["skipped"] if v["skipped"] else ""
                    parts.append("%s %d of %d%s%s" % (p, v["passed"], v["cases"],
                                                       " (required)" if v["required"] else "", extra))
            lines.append("Role %s: %s; %s" % (name, "passed" if e["passed"] else "FAILED", "; ".join(parts)))
    for name, e in report["profiles"].items():
        if e["claimed"] and e["passed"] is not None:
            lines.append("Profile %s: %s; %d of %d" % (name, "passed" if e["passed"] else "FAILED",
                                                       e["passed_cases"], e["cases"]))
    skipped = [c for c in report["cases"] if c["result"] == "skipped"]
    bad = [c for c in report["cases"] if c["result"] not in ("pass", "skipped")]
    run_count = len(report["cases"]) - len(skipped)
    lines.append("Cases: %d run, %d passed, %d skipped" % (run_count, run_count - len(bad), len(skipped)))
    for c in bad[:50]:
        lines.append("  %s/%s: %s: %s" % (c["set"], c["id"], c["result"], plain(c["reason"])))
    if len(bad) > 50:
        lines.append("  and %d more; the JSON report lists every case" % (len(bad) - 50))
    if report["partial"]:
        lines.append("Result: partial run (%s); a partial run makes no claim" % ", ".join(report["sets_run"]))
    elif report["conformant"]:
        lines.append("Result: " + report["claim"])
    else:
        lines.append("Result: not conformant")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the VMR conformance suite through an implementation's adapter.")
    ap.add_argument("adapter", help="the adapter descriptor (README.md, \"The adapter\")")
    ap.add_argument("--report", help="write the JSON report to this file")
    ap.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1), help="cases run at once")
    ap.add_argument("--timeout", type=float, default=120.0, help="seconds each case may take")
    ap.add_argument("--set", help="run only these sets, comma-separated; a partial run makes no claim")
    ap.add_argument("--suite", default=DEFAULT_SUITE, help="another suite file (for testing the runner)")
    args = ap.parse_args(argv)
    try:
        suite = load_suite(args.suite)
        descriptor, command, cwd = load_adapter(args.adapter, suite)
        partial = bool(args.set)
        if partial:
            names = [s for s in args.set.split(",") if s]
            unknown = [s for s in names if s not in suite["sets"]]
            if unknown:
                raise SuiteError("no set named %s" % ", ".join(show(s) for s in unknown))
        else:
            names = [s for r, spec in suite["roles"].items() if r in descriptor["roles"] for s in spec["sets"]]
        if not names:
            raise SuiteError("the adapter claims no role, so there is nothing to run")
        cases = [c for n in names for c in cases_of_set(suite, n)]
    except SuiteError as e:
        sys.stderr.write("vmr-conformance: %s\n" % e)
        return 2
    started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    active = active_profiles(suite, descriptor["roles"], descriptor["profiles"])
    options = {"reports_refusal_identifiers": descriptor["reports_refusal_identifiers"], "active": active}
    to_run = [c for c in cases if not is_skipped(c, active)]
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = {pool.submit(run_case, c, command, cwd, args.timeout, options): c for c in to_run}
        for f in concurrent.futures.as_completed(futures):
            c = futures[f]
            results[(c.set, c.id)] = f.result()
    roles, profiles, conformant, claim = verdicts(suite, cases, results, descriptor["roles"],
                                                  descriptor["profiles"], partial,
                                                  descriptor["reports_refusal_identifiers"])
    with open(os.path.abspath(__file__), "rb") as f:
        runner_hash = sha256_tag(f.read())
    report = {
        "report_version": "0.1", "protocol": PROTOCOL, "suite": suite["suite"],
        "suite_version": suite["suite_version"], "specification_version": suite["specification_version"],
        "suite_sha256": suite["_sha256"], "runner_sha256": runner_hash, "files": suite["files"],
        "implementation": descriptor["implementation"],
        "claimed": {"roles": descriptor["roles"], "profiles": descriptor["profiles"],
                    "reports_refusal_identifiers": descriptor["reports_refusal_identifiers"]},
        "partial": partial, "sets_run": names, "started_at": started,
        "platform": platform.platform(), "python": platform.python_version(),
        "roles": roles, "profiles": profiles, "conformant": conformant, "claim": claim, "cases": [],
    }
    for c in cases:
        if (c.set, c.id) not in results:
            report["cases"].append({"set": c.set, "id": c.id, "tag": c.tag, "result": "skipped",
                                    "reason": "the profile %s is neither required nor claimed"
                                              % tag_profile(c.tag)})
            continue
        result, answer, reason = results[(c.set, c.id)]
        entry = {"set": c.set, "id": c.id, "tag": c.tag, "result": result}
        if result != "pass":
            entry.update(reason=reason, expected=c.expected, answer=answer)
        report["cases"].append(entry)
    if args.report:
        with open(args.report, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(report, ensure_ascii=True, indent=1) + "\n")
    sys.stdout.write(summary(report))
    if partial:
        return 0 if all(c["result"] in ("pass", "skipped") for c in report["cases"]) else 1
    return 0 if conformant else 1


if __name__ == "__main__":
    sys.exit(main())
