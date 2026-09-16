# SPDX-License-Identifier: Apache-2.0
"""Tests of the VMR conformance suite and runner. Standard library only:

    python -m unittest discover -s specs/conformance/tests -v

The runner is exercised against tests/oracle_adapter.py, which answers from
the suite's expected values; no implementation is needed.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CONF = os.path.dirname(HERE)
SPECS = os.path.dirname(CONF)
sys.path.insert(0, CONF)

import build_suite  # noqa: E402
import run  # noqa: E402

PROFILE = "snn-compact-v1"
ALL_ROLES = ["verifier", "issuer", "policy-evaluator"]


def read_json(rel):
    with open(os.path.join(SPECS, rel), encoding="utf-8") as f:
        return json.load(f)


def runner(tmp, roles, profiles, args=(), env=None, suite=None, adapter="oracle_adapter.py",
           reports_refusal_identifiers=True):
    descriptor = os.path.join(tmp, "adapter.json")
    with open(descriptor, "w", encoding="utf-8") as f:
        json.dump({"adapter_version": "0.1", "implementation": {"name": "oracle", "version": "test"},
                   "command": ["{python}", os.path.join(HERE, adapter)],
                   "roles": roles, "profiles": profiles,
                   "reports_refusal_identifiers": reports_refusal_identifiers}, f)
    report = os.path.join(tmp, "report.json")
    cmd = [sys.executable, os.path.join(CONF, "run.py"), descriptor, "--report", report] + list(args)
    if suite:
        cmd += ["--suite", suite]
    e = dict(os.environ, PYTHONUTF8="1", **(env or {}))
    if suite:
        e["ORACLE_SUITE"] = suite
    p = subprocess.run(cmd, capture_output=True, env=e, timeout=1800)
    doc = None
    if os.path.exists(report):
        with open(report, encoding="utf-8") as f:
            doc = json.load(f)
    return p, doc


def case_result(doc, key):
    return next(c for c in doc["cases"] if c["set"] + "/" + c["id"] == key)


class SuiteTests(unittest.TestCase):
    def test_generated_files_are_current(self):
        for rel, data in build_suite.outputs().items():
            with open(os.path.join(SPECS, rel), "rb") as f:
                self.assertEqual(f.read(), data, rel + " is stale: run build_suite.py")

    def test_every_vector_case_is_in_its_set_once_in_order(self):
        suite = run.load_suite(run.DEFAULT_SUITE)
        total = 0
        for name in suite["sets"]:
            cases = run.cases_of_set(suite, name)
            self.assertEqual([c.id for c in cases], list(suite["sets"][name]["cases"]), name)
            total += len(cases)
        self.assertEqual(total, 2 + 428 + 52 + 1 + 33 + 291 + 73 + 40)

    def test_a_changed_vector_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            suite = read_json("conformance/suite.json")
            suite["files"]["test-vectors/verify/cases.json"] = "sha256:" + "0" * 64
            path = os.path.join(tmp, "suite.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(suite, f)
            with self.assertRaises(run.SuiteError):
                run.load_suite(path)

    def test_tags(self):
        sets = read_json("conformance/suite.json")["sets"]
        tag = lambda s, i: sets[s]["cases"][i]  # noqa: E731
        p = "profile:" + PROFILE
        g = "profile-gated:" + PROFILE
        # QA gap 1 (the owner, 2026-09-16): this one case is never skipped -
        # see build_suite.py's GATED_CASES and its module docstring.
        self.assertEqual(tag("verify", "pass-vector-json"), g)
        self.assertEqual(tag("verify", "fail-issuer-as-array"), p)
        self.assertEqual(tag("verify", "fail-profile-identifier-added"), p)
        self.assertEqual(tag("verify", "fail-empty"), "core")
        self.assertEqual(tag("verify", "pass-general-open-weights-not-held-cose"), "core")
        self.assertEqual(tag("verify", "pass-general-profile-look-alike"), "core")
        self.assertEqual(tag("verify", "fail-profile-identifier-case"), "core")
        self.assertEqual(tag("verify", "pass-general-fine-tune-chain-across-issuers"), "core")
        self.assertEqual(tag("record-payload", "example-v0.1"), p)
        self.assertEqual(tag("record-payload", "example-general-v0.1"), "core")
        self.assertEqual(tag("trust-store", "ok-basic"), "core")
        self.assertEqual(tag("pack-signature", "unsigned"), "core")
        self.assertEqual(sum(1 for t in sets["verify"]["cases"].values() if t == p), 170)
        self.assertEqual(sum(1 for t in sets["verify"]["cases"].values() if t == g), 1)
        self.assertEqual(sum(1 for t in sets["policy-evaluation"]["cases"].values() if t == p), 137)
        # The general-description copies are core (the owner, 2026-09-16).
        self.assertEqual(tag("verify", "pass-vector-json-general-record"), "core")
        self.assertEqual(tag("policy-evaluation", "data-residency-pass-general-record"), "core")
        for s in sets.values():
            self.assertTrue(set(s["cases"].values()) <= {"core", p, g})

    def test_no_role_requires_a_profile(self):
        # The owner, 2026-09-16 (QA QR-09): supporting a registered profile is
        # not a condition of conformance. build_suite.py's HEADER says the
        # same, so a regeneration from scratch cannot restore the requirement.
        suite = read_json("conformance/suite.json")
        for role in ALL_ROLES:
            self.assertEqual(suite["roles"][role]["required_profiles"], [], role)
            self.assertEqual(build_suite.HEADER["roles"][role]["required_profiles"], [], role)
        self.assertEqual(sorted(suite["roles"]), sorted(ALL_ROLES))
        self.assertEqual(suite["specification_version"], "0.1")

    def test_general_checks_on_engine_records(self):
        # Every case of a general rule that the committed set tests on an
        # engine record has a general-description twin, tagged core, so a
        # profile-blind implementation is held to all of them (the owner,
        # 2026-09-16).
        suite = read_json("conformance/suite.json")
        listed = suite["general_checks_on_engine_records"]
        self.assertEqual(len(listed), 293)
        for key in listed:
            s, i = key.split("/", 1)
            # A "profile-gated" case (QA gap 1) is still a profile-tagged
            # engine-record case for this purpose: it too has a general twin.
            self.assertIn(suite["sets"][s]["cases"][i], ("profile:" + PROFILE, "profile-gated:" + PROFILE), key)
            twin = i + "-general-record"
            self.assertEqual(suite["sets"][s]["cases"].get(twin), "core", twin)
        self.assertIn("verify/fail-issuer-as-array", listed)
        self.assertIn("policy-evaluation/" + next(iter(suite["sets"]["policy-evaluation"]["cases"])), listed)
        self.assertNotIn("verify/fail-profile-extra-component", listed)
        self.assertNotIn("record-payload/example-v0.1", listed)
        # A case of the profile's own rules has, and can have, no twin: the
        # general description does not check parameter_count, and the
        # committed engine artifact cannot be described generally.
        self.assertNotIn("verify/fail-consistency-parameter-count", listed)
        self.assertNotIn("policy-evaluation/reference-khalm-reading-eu-ai-act-2026-demo-record", listed)


class Es256Tests(unittest.TestCase):
    def setUp(self):
        doc = read_json("test-vectors/record/example-general-v0.1.json")
        rec = doc["record"]
        self.x = int.from_bytes(run.b64url_decode(rec["issuer"]["public_key"]["x"]), "big")
        self.y = int.from_bytes(run.b64url_decode(rec["issuer"]["public_key"]["y"]), "big")
        self.kid = rec["signature"]["signing_key_id"].encode("utf-8")
        self.payload = doc["expected"]["signed_payload"].encode("utf-8")
        self.rs = run.b64url_decode(rec["signature"]["signature"][len("base64url:"):])

    def test_the_committed_signature_verifies(self):
        self.assertTrue(run.es256_verify(self.x, self.y, run.sig_structure(self.kid, self.payload), self.rs))

    def test_a_changed_payload_or_signature_fails(self):
        self.assertFalse(run.es256_verify(self.x, self.y, run.sig_structure(self.kid, self.payload + b" "), self.rs))
        bad = bytearray(self.rs)
        bad[40] ^= 1
        self.assertFalse(run.es256_verify(self.x, self.y, run.sig_structure(self.kid, self.payload), bytes(bad)))

    def test_high_s_fails(self):
        s = int.from_bytes(self.rs[32:], "big")
        high = self.rs[:32] + (run.N - s).to_bytes(32, "big")
        self.assertFalse(run.es256_verify(self.x, self.y, run.sig_structure(self.kid, self.payload), high))

    def test_the_issuer_case_key_is_the_vector_key(self):
        case = read_json("conformance/issuer-cases.json")["cases"][0]
        jwk = case["input"]["signing_key"]
        d = int.from_bytes(run.b64url_decode(jwk["d"]), "big")
        self.assertEqual(run.b64url_decode(jwk["d"]), hashlib.sha256(b"khalm v0.1 test-vector signing key").digest())
        self.assertEqual(run.point_mul(d, run.G), (self.x, self.y))

    def test_the_cose_envelope_prefix_is_the_spec_text(self):
        env = run.cose_envelope(self.kid, self.payload, self.rs)
        self.assertEqual(env[:9].hex(), "84585ea20126045858")
        self.assertEqual(base64.b16encode(run.sig_structure(self.kid, b"")[:14]).decode().lower(),
                         "846a5369676e617475726531585e")


class RunnerTests(unittest.TestCase):
    def test_the_oracle_passes_every_role_and_the_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, doc = runner(tmp, ALL_ROLES, [PROFILE])
            self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace")[-2000:])
            self.assertTrue(doc["conformant"])
            self.assertEqual(doc["claim"], "VMR v0.1 conformant (vmr-conformance suite %s): verifier, issuer, "
                             "policy-evaluator; profiles: snn-compact-v1" % doc["suite_version"])
            self.assertEqual(len(doc["cases"]), 920)
            self.assertTrue(all(c["result"] == "pass" for c in doc["cases"]))
            self.assertEqual(doc["roles"]["verifier"]["core"], {"cases": 310, "passed": 310})
            self.assertIn(b"Result: VMR v0.1 conformant", p.stdout)

    def test_a_wrong_check_id_fails_the_verifier_role(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, doc = runner(tmp, ["verifier"], [], env={"ORACLE_BREAK": "verify/fail-empty"})
            self.assertEqual(p.returncode, 1)
            self.assertFalse(doc["roles"]["verifier"]["passed"])
            self.assertFalse(doc["conformant"])
            self.assertIsNone(doc["claim"])
            c = case_result(doc, "verify/fail-empty")
            self.assertEqual(c["result"], "fail")
            self.assertIn("check", c["reason"])
            self.assertIn(b"verify/fail-empty", p.stdout)

    def test_unsupported_garbage_and_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"ORACLE_UNSUPPORTED": "model-hash/digest-one-file",
                   "ORACLE_GARBAGE": "model-hash/name-accepted-leading-dot",
                   "ORACLE_SLEEP": "model-hash/set-refused-repeated"}
            p, doc = runner(tmp, ["issuer"], [], args=["--set", "model-hash", "--timeout", "3"], env=env)
            self.assertEqual(p.returncode, 1)
            self.assertEqual(case_result(doc, "model-hash/digest-one-file")["result"], "unsupported")
            self.assertEqual(case_result(doc, "model-hash/name-accepted-leading-dot")["result"], "error")
            self.assertEqual(case_result(doc, "model-hash/set-refused-repeated")["result"], "error")
            self.assertTrue(doc["partial"])
            self.assertIsNone(doc["claim"])

    def test_the_issuer_answer_is_checked(self):
        for mode, expected in [("json", "pass"), ("cose", "pass"), ("wrong-model-hash", "fail"),
                               ("high-s", "fail"), ("bad-signature", "fail")]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                p, doc = runner(tmp, ["issuer"], [], args=["--set", "issue"], env={"ORACLE_ISSUE": mode})
                c = doc["cases"][0]
                self.assertEqual(c["result"], expected, c.get("reason"))
                self.assertEqual(p.returncode, 0 if expected == "pass" else 1)

    def test_a_profile_blind_implementation_is_conformant_and_nothing_is_listed_as_failing(self):
        # QA QR-09 and QR-10 (the owner, 2026-09-16). An adapter that supports
        # no profile claims none, passes, and its summary says the profile's
        # cases were SKIPPED - not "267 run, 149 passed" with the rest listed
        # as failures.
        with tempfile.TemporaryDirectory() as tmp:
            p, doc = runner(tmp, ["verifier"], [], env={"ORACLE_CORE_ONLY": "1"})
            out = p.stdout.decode("utf-8", "replace")
            self.assertEqual(p.returncode, 0, out[-2000:])
            self.assertTrue(doc["roles"]["verifier"]["passed"])
            self.assertTrue(doc["conformant"])
            self.assertEqual(doc["claim"], "VMR v0.1 conformant (vmr-conformance suite %s): verifier; no profile"
                             % doc["suite_version"])
            skipped = [c for c in doc["cases"] if c["result"] == "skipped"]
            self.assertTrue(skipped)
            self.assertTrue(all(c["tag"] == "profile:" + PROFILE for c in skipped))
            self.assertFalse([c for c in doc["cases"] if c["result"] not in ("pass", "skipped")])
            self.assertIn("%d skipped" % len(skipped), out)

    def test_a_claimed_profile_is_run_and_a_failing_one_is_not_conformant(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, doc = runner(tmp, ["verifier"], [PROFILE], env={"ORACLE_CORE_ONLY": "1"})
            self.assertEqual(p.returncode, 1)
            self.assertFalse(doc["profiles"][PROFILE]["passed"])
            self.assertIsNone(doc["claim"])
            self.assertFalse([c for c in doc["cases"] if c["result"] == "skipped"])

    def test_the_gated_case_requires_unsupported_only_when_the_profile_is_not_claimed(self):
        # QA gap 1 (the owner, 2026-09-16): "verify/pass-vector-json" is
        # retagged "profile-gated:snn-compact-v1" (build_suite.py's
        # GATED_CASES) instead of the plain "profile:snn-compact-v1" every
        # other engine-record case carries, so is_skipped never skips it:
        # record-format §7.1's "unsupported, not invalid" rule for a
        # registered profile an implementation does not claim finally has a
        # case that reaches an adapter.
        key = "verify/pass-vector-json"
        with tempfile.TemporaryDirectory() as tmp:
            # Blind to the profile, and correctly declines: conformant, and
            # the case is a real pass, not a silent skip.
            p, doc = runner(tmp, ["verifier"], [], env={"ORACLE_UNSUPPORTED": key})
            self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace")[-2000:])
            self.assertTrue(doc["conformant"])
            self.assertEqual(case_result(doc, key)["result"], "pass")

        with tempfile.TemporaryDirectory() as tmp:
            # Blind to the profile, but answers for real instead of
            # declining (the oracle's ordinary behaviour: it does not know it
            # is meant to be "blind"): fails, even though the value given is
            # the right one - a claim of no support must say so.
            p, doc = runner(tmp, ["verifier"], [])
            self.assertEqual(p.returncode, 1)
            self.assertFalse(doc["conformant"])
            c = case_result(doc, key)
            self.assertEqual(c["result"], "fail")
            self.assertIn("unsupported", c["reason"])

        with tempfile.TemporaryDirectory() as tmp:
            # Claims the profile: must answer properly, not decline it.
            p, doc = runner(tmp, ["verifier"], [PROFILE], env={"ORACLE_UNSUPPORTED": key})
            self.assertEqual(p.returncode, 1)
            self.assertFalse(doc["conformant"])
            self.assertEqual(case_result(doc, key)["result"], "unsupported")
            self.assertFalse(doc["profiles"][PROFILE]["passed"])

        with tempfile.TemporaryDirectory() as tmp:
            # Claims the profile and answers for real: passes, same as any
            # other case of a claimed profile.
            p, doc = runner(tmp, ["verifier"], [PROFILE])
            self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace")[-2000:])
            self.assertTrue(doc["conformant"])
            self.assertEqual(case_result(doc, key)["result"], "pass")

    def test_a_required_profile_with_no_case_is_a_configuration_error(self):
        # QA QR-11: a role's profile map is built from the tags its cases
        # carry, so a required profile that contributes nothing would pass
        # silently. `audit-log` is in the suite as planned, with no case.
        with tempfile.TemporaryDirectory() as tmp:
            suite = read_json("conformance/suite.json")
            suite["roles"]["verifier"]["required_profiles"] = ["audit-log"]
            path = os.path.join(tmp, "suite.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(suite, f)
            with self.assertRaises(run.SuiteError):
                run.load_suite(path, check_pins=False)
            p, _ = runner(tmp, ["verifier"], [], suite=path)
            self.assertEqual(p.returncode, 2)
            self.assertIn(b"audit-log", p.stderr)

    def test_an_adapter_that_answers_error_to_everything_fails_the_pack_loader_set(self):
        # QA QR-02: before the fix round this adapter passed 61 of the 73
        # pack-loader cases, because the refusal identifier was compared only
        # when the answer volunteered one.
        with tempfile.TemporaryDirectory() as tmp:
            p, doc = runner(tmp, ["policy-evaluator"], [], args=["--set", "pack-loader"],
                            adapter="constant_error_adapter.py")
            self.assertEqual(p.returncode, 1)
            self.assertEqual(len(doc["cases"]), 73)
            self.assertFalse([c for c in doc["cases"] if c["result"] == "pass"])

    def test_an_adapter_may_report_no_refusal_identifiers_and_its_claim_says_so(self):
        # Policy-pack format section 9 leaves them optional. Such an adapter
        # passes, its report records the silence, and it must then report none.
        with tempfile.TemporaryDirectory() as tmp:
            p, doc = runner(tmp, ["policy-evaluator"], [PROFILE], args=["--set", "pack-loader"],
                            env={"ORACLE_NO_REFUSAL_IDS": "1"}, reports_refusal_identifiers=False)
            self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace")[-2000:])
            self.assertFalse(doc["claimed"]["reports_refusal_identifiers"])
            # Declaring silence and then reporting an identifier is a failure.
            p, doc = runner(tmp, ["policy-evaluator"], [PROFILE], args=["--set", "pack-loader"],
                            reports_refusal_identifiers=False)
            self.assertEqual(p.returncode, 1)
            # And an adapter that declares it reports them must report them.
            p, doc = runner(tmp, ["policy-evaluator"], [PROFILE], args=["--set", "pack-loader"],
                            env={"ORACLE_NO_REFUSAL_IDS": "1"})
            self.assertEqual(p.returncode, 1)

    def test_either_answer_for_an_unsigned_pack_passes(self):
        # QA QR-07: policy-pack format allows a checker that refuses every
        # unsigned pack and reports pack_signature.unsigned where the
        # reference CLI reports the state `unsigned`.
        with tempfile.TemporaryDirectory() as tmp:
            for env in ({}, {"ORACLE_UNSIGNED": "refusal"}):
                p, doc = runner(tmp, ["policy-evaluator"], [PROFILE], args=["--set", "pack-signature"], env=env)
                self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace")[-2000:])
                for cid in ("unsigned", "unsigned-with-an-authority"):
                    self.assertEqual(case_result(doc, "pack-signature/" + cid)["result"], "pass", (env, cid))

    def test_reports_refusal_identifiers_is_optional_unless_policy_evaluator_is_claimed(self):
        # QA gap 3 (the owner, 2026-09-16): the field describes only
        # policy_pack.load's refusal identifiers, so a descriptor that never
        # claims policy-evaluator (and so never runs a pack-loader case) may
        # omit it - false ("reports none") is assumed. QA QR-02's protection
        # stands for a descriptor that does claim the role: it must still say.
        with tempfile.TemporaryDirectory() as tmp:
            descriptor = os.path.join(tmp, "adapter.json")
            with open(descriptor, "w", encoding="utf-8") as f:
                json.dump({"adapter_version": "0.1", "implementation": {"name": "x", "version": "1"},
                           "command": ["{python}", os.path.join(HERE, "oracle_adapter.py")],
                           "roles": ["verifier"], "profiles": []}, f)
            report = os.path.join(tmp, "report.json")
            p = subprocess.run([sys.executable, os.path.join(CONF, "run.py"), descriptor, "--report", report,
                                "--set", "record-payload"], capture_output=True,
                               env=dict(os.environ, PYTHONUTF8="1"))
            self.assertEqual(p.returncode, 0, p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace"))
            with open(report, encoding="utf-8") as f:
                doc = json.load(f)
            self.assertFalse(doc["claimed"]["reports_refusal_identifiers"])

        with tempfile.TemporaryDirectory() as tmp:
            descriptor = os.path.join(tmp, "adapter.json")
            with open(descriptor, "w", encoding="utf-8") as f:
                json.dump({"adapter_version": "0.1", "implementation": {"name": "x", "version": "1"},
                           "command": ["{python}", os.path.join(HERE, "oracle_adapter.py")],
                           "roles": ["policy-evaluator"], "profiles": []}, f)
            p = subprocess.run([sys.executable, os.path.join(CONF, "run.py"), descriptor], capture_output=True,
                               env=dict(os.environ, PYTHONUTF8="1"))
            self.assertEqual(p.returncode, 2)
            self.assertIn(b"reports_refusal_identifiers", p.stderr)

    def test_a_bad_descriptor_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            descriptor = os.path.join(tmp, "adapter.json")
            with open(descriptor, "w", encoding="utf-8") as f:
                json.dump({"adapter_version": "0.1", "implementation": {"name": "x", "version": "1"},
                           "command": ["${VMR_CONFORMANCE_TEST_UNSET_VARIABLE}"], "roles": ["verifier"],
                           "profiles": [], "reports_refusal_identifiers": True}, f)
            p = subprocess.run([sys.executable, os.path.join(CONF, "run.py"), descriptor], capture_output=True,
                               env=dict(os.environ, PYTHONUTF8="1"))
            self.assertEqual(p.returncode, 2)
            self.assertIn(b"VMR_CONFORMANCE_TEST_UNSET_VARIABLE", p.stderr)


if __name__ == "__main__":
    unittest.main()
