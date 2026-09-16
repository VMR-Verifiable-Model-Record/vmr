// tests/determinism.rs — Law 1 in this crate: the same pack, the same
// record and the same evaluation time give the same Evaluation, member for
// member, across runs, across instances, across threads, and whatever order
// the pack's own JSON members were written in. An evaluation that varied
// would make every embedded policy_compliance unreproducible.

mod common;

use common::*;
use serde_json::{json, Value};
use vmr_policy::vmr_record::hash::{format_hash, sha256};

#[test]
fn the_same_inputs_give_the_same_evaluation() {
    let record = conformance_record();
    for pack_id in REFERENCE_PACKS {
        let a = reference_pack(pack_id).evaluate(&record, now());
        let b = reference_pack(pack_id).evaluate(&record, now());
        assert_eq!(a, b, "{pack_id}");
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "{pack_id} serializes differently"
        );
    }
}

#[test]
fn the_packs_text_form_does_not_reach_the_result() {
    // A pack re-indented, or with a character written as a \u escape, is the
    // same pack: an authority's formatting cannot change an evaluation, and
    // it cannot change the bytes its signature covers either (JCS, P6-8).
    let record = conformance_record();
    for pack_id in REFERENCE_PACKS {
        let committed = reference_pack(pack_id);
        let document: Value = serde_json::from_str(&pack_text(pack_id)).unwrap();
        let compact = document.to_string();
        let escaped =
            compact.replace("KHALM reference", &format!("KHALM {}u0072eference", '\u{5c}'));
        assert_ne!(escaped, compact);
        for text in [compact, escaped] {
            assert_ne!(text, pack_text(pack_id));
            let rewritten =
                vmr_policy::load_pack(&text).unwrap_or_else(|e| panic!("{pack_id}: {e}"));
            assert_eq!(
                committed.evaluate(&record, now()),
                rewritten.evaluate(&record, now()),
                "{pack_id}"
            );
            assert_eq!(committed.payload_hash(), rewritten.payload_hash(), "{pack_id}");
        }
    }
}

#[test]
fn threads_reach_the_same_result() {
    let record = conformance_record();
    let expected = eu_pack().evaluate(&record, now());
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let record = record.clone();
            std::thread::spawn(move || eu_pack().evaluate(&record, now()))
        })
        .collect();
    for handle in handles {
        assert_eq!(handle.join().expect("no panic in an evaluator"), expected);
    }
}

#[test]
fn only_the_evaluation_time_moves_when_only_the_evaluation_time_moves() {
    let record = conformance_record();
    let early = eu_pack().evaluate(&record, at("2026-09-09T00:00:00Z"));
    let late = eu_pack().evaluate(&record, at("2030-01-01T00:00:00Z"));
    assert_ne!(early.evaluated_at, late.evaluated_at);
    assert_eq!(early.results, late.results, "no rule reads the evaluation time");
    assert_eq!(early.overall, late.overall);
}

/// How deep the child below nests its value: far past any stack a thread is
/// given, so a recursive walk over it cannot survive by luck.
const DEEP: usize = 100_000;

#[test]
fn a_deep_value_at_a_read_member_is_answered_not_crashed() {
    // Law 9 (QA Q6-04). serde_json parses no document that deep, so only a
    // library caller can hand the evaluator such a value; a recursive walk
    // over it overflows the stack, and that aborts the whole process, which
    // no test can catch in-process. So the evaluation runs in a child: this
    // test binary, re-run on the ignored test below.
    let exe = std::env::current_exe().expect("the path of this test binary");
    let output = std::process::Command::new(exe)
        .args(["--exact", "deep_value_child", "--ignored", "--nocapture", "--test-threads=1"])
        .output()
        .expect("the child runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "the child's evaluation did not finish ({:?})\n--- stdout\n{stdout}\n--- stderr\n{stderr}",
        output.status
    );
}

#[test]
#[ignore = "run in a child process by a_deep_value_at_a_read_member_is_answered_not_crashed"]
fn deep_value_child() {
    let mut deep = json!("software");
    for _ in 0..DEEP {
        deep = Value::Array(vec![deep]);
    }
    let mut record = conformance_record();
    record["issuer"]["attestation_level"] = deep;

    let pack = eu_pack();
    let evaluation = pack.evaluate(&record, now());
    let usual = pack.evaluate(&conformance_record(), now());
    assert_eq!(evaluation.results.len(), usual.results.len());
    for (result, expected) in evaluation.results.iter().zip(&usual.results) {
        if result.rule_type == "attestation_level" {
            assert_eq!(result.status, vmr_policy::Status::Indeterminate, "{}", result.detail);
            assert!(result.detail.contains("/issuer/attestation_level"), "{}", result.detail);
            // Not read, so it contributes what an absent member does.
            assert_eq!(result.evidence_hash, format_hash(&sha256(b"null")));
        } else {
            assert_eq!(result, expected, "a rule that does not read the deep member");
        }
    }
    dismantle(record["issuer"]["attestation_level"].take());
}

/// Drop a deep value one level at a time: serde_json drops recursively, so
/// letting the value go out of scope would overflow this test's own stack.
fn dismantle(mut value: Value) {
    let mut pending = Vec::new();
    loop {
        match &mut value {
            Value::Array(items) => pending.append(items),
            Value::Object(members) => pending.extend(std::mem::take(members).into_iter().map(|(_, v)| v)),
            _ => {}
        }
        match pending.pop() {
            Some(next) => value = next,
            None => break,
        }
    }
}

#[test]
fn an_empty_record_is_answered_rather_than_refused() {
    // Garbage in, an evaluation out: nothing panics and nothing is a Fail
    // the record did not earn. The one Fail an empty object earns is a
    // documentation rule's: it declares no documentation member, and an
    // absent member fails (task 10.11a, D11-4). Those rules are recommended,
    // so the overall stays Indeterminate. A record that is not an object
    // declares nothing, and no rule fails it.
    for record in [json!({}), json!(null), json!([]), json!("not an object"), json!(7)] {
        let evaluation = eu_pack().evaluate(&record, now());
        assert_eq!(evaluation.results.len(), eu_pack().rules.len(), "{record}");
        assert_eq!(evaluation.overall, vmr_policy::Status::Indeterminate, "{record}");
        let mut earned = 0;
        for result in &evaluation.results {
            if result.status != vmr_policy::Status::Fail {
                continue;
            }
            assert!(
                record.is_object()
                    && result.rule_type == "documentation_declared"
                    && result.severity == vmr_policy::Severity::Recommended
                    && result.detail.contains("declares that it pins no"),
                "{record}: {}: {}",
                result.rule_id,
                result.detail
            );
            earned += 1;
        }
        assert_eq!(earned, if record.is_object() { 2 } else { 0 }, "{record}");
    }
}
