//! 7.5 — the published policy vectors through the `vmr` binary, in both
//! builds (docs/dev/phase7.md P7-6). The default build (no engine) is what a third
//! party runs; G5-5 crossed the build boundary for verification, and this
//! crosses it for policy.
//!
//! A case marked `verifiable` holds a well-formed v0.1 record. It is
//! re-signed with the verification vectors' key A, which `ts-basic` trusts
//! for its issuer (signing changes no member a rule reads), and verified with
//! the case's pack at the case's evaluation time. Every rule's id, status,
//! severity and evidence hash must be the vector's, and the exit code the one
//! the overall status implies (P6-13). Before any case, `vmr --version` must
//! name this test's build (plan R4).
//!
//! A case in a verification context (P6-17; the format document's §5 and
//! §9) is replayed with its predecessors as `--previous`, immediate
//! predecessor first. They are signed with key A as they stand, so the
//! verifier establishes the case's lineage outcome, which the report must
//! show. A verifiable case without a context is an initial record.

use crate::common::*;
use crate::support::*;
use serde_json::{json, Value};
use vmr_record::timestamp::Timestamp;
use vmr_record::Record;

#[test]
fn every_verifiable_policy_vector_gives_its_expected_evaluation_through_vmr() {
    let s = Scratch::new("cross-policy-vectors");
    let store = s.write("trust-store.json", vector_store("ts-basic"));

    // Plan R4: the vmr under test is this build's. Both builds make a binary
    // named vmr (P7-3), and this is the one cross_impl test compiled in both
    // (a build that extends vmr-cli takes this file by path), so a target
    // directory both used could hand it the other binary (task 10.13a, R2).
    // The harness says what this build's version adds to its name and
    // version: its own words, whichever build it is, told apart because each
    // build's words are its own (QA13-11, D11f-5).
    let version = vmr(&["--version"]);
    version.expect_code(0);
    let name_and_version = format!("vmr {}", env!("CARGO_PKG_VERSION"));
    let this_build = match BUILD_WORDS {
        Some(words) => version.stdout.starts_with(&name_and_version) && version.stdout.contains(words),
        None => version.stdout.trim_end() == name_and_version,
    };
    assert!(this_build, "the vmr under test is not this test's build ({BUILD_WORDS:?}):\n{}", version.transcript());

    let (mut replayed, mut with_previous, mut with_indeterminate) = (0, 0, 0);
    for case in policy_cases() {
        if case["verifiable"] != true {
            continue;
        }
        let id = case["id"].as_str().unwrap();
        let expected = &case["expected"];

        let mut record =
            Record::from_json(case["record"]["text"].as_str().unwrap()).unwrap_or_else(|e| panic!("{id}: {e}"));
        reissue_with(&mut record, KEY_A);
        let record_file = s.write(&format!("{id}.record.json"), record.to_json().unwrap());
        let pack_file = s.write(&format!("{id}.pack.json"), case["pack"]["text"].as_str().unwrap());
        let at = case["evaluation_time"].as_str().unwrap();

        let mut args: Vec<String> =
            ["record", "verify", "--record", &record_file, "--trust-store", &store, "--at", at, "--policy-pack", &pack_file, "--json"]
                .map(String::from)
                .to_vec();
        let context = &case["context"];
        let predecessors = context["predecessors"].as_array().map(Vec::as_slice).unwrap_or_default();
        for (i, predecessor) in predecessors.iter().enumerate() {
            let file = s.write(&format!("{id}.previous-{i}.json"), predecessor["text"].as_str().unwrap());
            args.extend(["--previous".to_string(), file]);
        }
        with_previous += usize::from(!predecessors.is_empty());

        let run = vmr(&strs(&args));
        let accepted = expected["overall"] == "pass";
        run.expect_code(if accepted { 0 } else { 4 });
        let report: Value = serde_json::from_str(&run.stdout).unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(report["verdict"], "pass", "{id}: {}", report["failure"]);
        let outcome = if context.is_null() { &Value::from("initial") } else { &context["lineage_outcome"] };
        assert_eq!(report["lineage"]["status"], *outcome, "{id}: verification establishes the case's lineage outcome");

        let evaluation = &report["policy"]["evaluation"];
        assert_eq!(evaluation["state"], "evaluated", "{id}");
        assert_eq!(evaluation["policy_pack_id"], expected["policy_compliance"]["policy_pack_id"], "{id}");
        assert_eq!(evaluation["status"], overall_status(&expected["overall"]), "{id}");
        let rules = evaluation["rules"].as_array().unwrap();
        let want = expected["results"].as_array().unwrap();
        assert_eq!(rules.len(), want.len(), "{id}");
        for (got, want) in rules.iter().zip(want) {
            for name in ["rule_id", "status", "severity", "evidence_hash"] {
                assert_eq!(got[name], want[name], "{id}: {name} of {}", got["rule_id"]);
            }
        }

        // QA Q7-14: three policy_compliance sections must be one. The section
        // the format document's §8 builds from this report's rules; the one
        // vmr-policy's own conversion builds from the same case, in its
        // context; and the vector's. A conversion that kept an indeterminate
        // rule (mutation M2) is caught here, in both builds.
        let from_report = json!({
            "policy_pack_id": evaluation["policy_pack_id"],
            "evaluated_at": at,
            "results": rules
                .iter()
                .filter(|r| r["status"] != "indeterminate")
                .map(|r| json!({"rule_id": r["rule_id"], "status": r["status"], "evidence_hash": r["evidence_hash"]}))
                .collect::<Vec<_>>(),
            "overall_status": evaluation["status"],
        });
        assert_eq!(from_report, expected["policy_compliance"], "{id}: §8's section, built from the report");
        let pack = vmr_policy::load_pack(case["pack"]["text"].as_str().unwrap()).unwrap_or_else(|e| panic!("{id}: {e}"));
        let payload: Value = serde_json::from_str(case["record"]["text"].as_str().unwrap()).unwrap();
        let t = Timestamp::parse(at).unwrap();
        let library = match policy_context(&case) {
            Some(c) => pack.evaluate_in_context(&payload, &c, t),
            None => pack.evaluate(&payload, t),
        };
        assert_eq!(
            serde_json::to_value(library.to_policy_compliance()).unwrap(),
            expected["policy_compliance"],
            "{id}: vmr-policy's to_policy_compliance"
        );
        with_indeterminate += usize::from(rules.iter().any(|r| r["status"] == "indeterminate"));
        replayed += 1;
    }
    assert!(replayed >= 20, "only {replayed} verifiable policy vectors were replayed");
    assert!(
        with_indeterminate >= 1,
        "no replayed case has an indeterminate rule, so nothing shows that the section omits one"
    );
    assert!(with_previous >= 1, "no verifiable policy vector was replayed with its predecessors (--previous)");
}

#[test]
fn every_pack_loader_vector_gives_its_expected_result_through_vmr() {
    // docs/TASKS.md 6.16 (docs/dev/task-6.16.md A16-23): a pack the loader
    // refuses is exit 1 before anything is verified, and the message names the
    // refusal's identifier; a pack that loads is evaluated, and the report
    // carries its payload hash.
    let s = Scratch::new("cross-pack-loader");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let doc = policy_vector_file("pack-loader.json");
    let mut refused = 0;
    for (i, case) in doc["cases"].as_array().unwrap().iter().enumerate() {
        let id = case["id"].as_str().unwrap();
        // Its text, or its hex where the bytes are not UTF-8 or start with a
        // byte order mark.
        let mut bytes = match (case["pack"].get("text"), case["pack"].get("hex")) {
            (Some(text), None) => text.as_str().unwrap().as_bytes().to_vec(),
            (None, Some(hex)) => hex_bytes(hex.as_str().unwrap()),
            other => panic!("{id}: a pack has exactly one of text and hex: {other:?}"),
        };
        if let Some(n) = case["pack"]["append_spaces"].as_u64() {
            bytes.resize(bytes.len() + usize::try_from(n).unwrap(), b' ');
        }
        let pack = s.write(&format!("loader-{i}.json"), &bytes);
        let run = vmr(&["record", "verify", "--record", &record, "--trust-store", &store, "--at", T, "--policy-pack", &pack, "--json"]);
        let expected = &case["expected"];
        match expected["result"].as_str().unwrap() {
            "ok" => {
                assert!(run.code == 0 || run.code == 4, "{id}: {}", run.transcript());
                let report: Value = serde_json::from_str(&run.stdout).unwrap_or_else(|e| panic!("{id}: {e}"));
                assert_eq!(report["policy"]["evaluation"]["policy_pack_payload_hash"], expected["pack_payload_hash"], "{id}");
            }
            "error" => {
                run.expect_code(1);
                assert!(run.stdout.is_empty(), "{id}: {}", run.transcript());
                let refusal = expected["refusal"].as_str().unwrap();
                assert!(run.stderr.contains(&format!("cannot be used: {refusal}: ")), "{id}: expected {refusal}:\n{}", run.transcript());
                refused += 1;
            }
            other => panic!("{id}: result {other}"),
        }
    }
    assert!(refused >= 12, "only {refused} refused packs were replayed");
}

#[test]
fn every_pack_signature_vector_gives_its_exit_code_and_state_through_vmr() {
    // docs/TASKS.md 6.16 (docs/dev/task-6.16.md A16-24): each case through
    // `vmr record verify --policy-pack` for the conformance record, which
    // every case's trust store trusts: the exit code, and the report's
    // pack_signature and payload hash, or the refusal's identifier.
    let s = Scratch::new("cross-pack-signature");
    let record = s.write("record.json", vector().to_json().unwrap());
    let doc = policy_vector_file("pack-signature.json");
    let (mut evaluated, mut refused) = (0, 0);
    for (i, case) in doc["cases"].as_array().unwrap().iter().enumerate() {
        let id = case["id"].as_str().unwrap();
        let pack = s.write(&format!("pack-{i}.json"), case["pack"]["text"].as_str().unwrap());
        let store = s.write(&format!("trust-store-{i}.json"), case["trust_store"]["text"].as_str().unwrap());
        let at = case["evaluation_time"].as_str().unwrap();
        let mut args: Vec<String> =
            ["record", "verify", "--record", &record, "--trust-store", &store, "--at", at, "--policy-pack", &pack, "--json"]
                .map(String::from)
                .to_vec();
        if !case["authority_store"].is_null() {
            let authorities = s.write(&format!("authority-store-{i}.json"), case["authority_store"]["text"].as_str().unwrap());
            args.extend(["--authority-store".to_string(), authorities]);
        }
        if case["require_signed_pack"].as_bool().unwrap() {
            args.push("--require-signed-pack".to_string());
        }
        let run = vmr(&strs(&args));
        let expected = &case["expected"];
        run.expect_code(i32::try_from(expected["exit_code"].as_i64().unwrap()).unwrap());
        if run.code == 0 {
            let report: Value = serde_json::from_str(&run.stdout).unwrap_or_else(|e| panic!("{id}: {e}"));
            let evaluation = &report["policy"]["evaluation"];
            assert_eq!(evaluation["pack_signature"], expected["pack_signature"], "{id}");
            assert_eq!(evaluation["policy_pack_payload_hash"], expected["pack_payload_hash"], "{id}");
            evaluated += 1;
        } else {
            assert!(run.stdout.is_empty(), "{id}: {}", run.transcript());
            let refusal = expected["refusal"].as_str().unwrap();
            assert!(run.stderr.contains(&format!("cannot be used: {refusal}: ")), "{id}: expected {refusal}:\n{}", run.transcript());
            refused += 1;
        }
    }
    assert!(evaluated >= 3 && refused >= 8, "{evaluated} evaluated, {refused} refused");
}

/// The bytes a vector's lower-case `hex` stands for.
fn hex_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')), "not lower-case hex");
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}
