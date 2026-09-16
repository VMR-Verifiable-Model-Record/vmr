// tests/inv_verify_determinism.rs — the invariant "verification is
// deterministic" (Phase 4 task 4.7; TASKS "test_inv_verify_determinism";
// proposed as DEV_PLAN Invariant 11). A report is a function of the input
// bytes, the trust store's content, T, the ordered predecessors and the
// options - nothing else: not the run, not the Verifier instance, not the
// order or formatting of the trust-store file, not the thread. The
// cross-process leg is Gate 4 (vmr-provenance/tests/gate4_two_process.rs).

mod common;
#[path = "common/generate.rs"]
mod generate;

use generate::input_bytes;
use serde_json::Value;
use vmr_record::timestamp::Timestamp;
use vmr_verify::report::{CheckId, Verdict};
use vmr_verify::{TrustStore, Verifier, VerifyOptions};

fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs/test-vectors")
}

fn store_text(name: &str) -> String {
    std::fs::read_to_string(vectors_dir().join(format!("verify/trust-stores/{name}.json"))).unwrap()
}

fn cases() -> Vec<Value> {
    let text = std::fs::read_to_string(vectors_dir().join("verify/cases.json")).unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    doc["cases"].as_array().unwrap().clone()
}

/// The same store with its issuers and each issuer's keys reversed, and
/// every object's members written in reverse order, compact: every order
/// and layout changed, no value changed.
fn permuted(store: &str) -> String {
    fn write_reversed(v: &Value, out: &mut String) {
        match v {
            Value::Object(members) => {
                out.push('{');
                for (i, (k, val)) in members.iter().rev().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(k).unwrap());
                    out.push(':');
                    write_reversed(val, out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_reversed(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut doc: Value = serde_json::from_str(store).unwrap();
    let issuers = doc["issuers"].as_array_mut().unwrap();
    issuers.reverse();
    for i in issuers.iter_mut() {
        i["keys"].as_array_mut().unwrap().reverse();
    }
    let mut out = String::new();
    write_reversed(&doc, &mut out);
    out
}

/// Run one vector case against `store`, returning its report as JSON.
fn run(case: &Value, store: TrustStore) -> String {
    let verifier = Verifier::new(store);
    let input = input_bytes(&case["input"]);
    let previous: Vec<Vec<u8>> = case["previous"].as_array().unwrap().iter().map(input_bytes).collect();
    let refs: Vec<&[u8]> = previous.iter().map(Vec::as_slice).collect();
    let t = Timestamp::parse(case["evaluation_time"].as_str().unwrap()).unwrap();
    let opts = VerifyOptions::new(t)
        .with_previous(&refs)
        .require_complete_lineage(case["require_complete_lineage"].as_bool().unwrap());
    verifier.verify(&input, &opts).to_json().unwrap()
}

fn load(text: &str) -> TrustStore {
    TrustStore::from_json(text.as_bytes()).unwrap()
}

#[test]
fn every_vector_case_gives_byte_identical_reports_across_runs_and_verifiers() {
    for case in cases() {
        let text = store_text(case["trust_store"].as_str().unwrap());
        let first = run(&case, load(&text));
        let second = run(&case, load(&text));
        assert_eq!(first, second, "{}", case["id"]);
        // And the same Verifier twice.
        let verifier = Verifier::new(load(&text));
        let input = input_bytes(&case["input"]);
        let t = Timestamp::parse(case["evaluation_time"].as_str().unwrap()).unwrap();
        let a = verifier.verify(&input, &VerifyOptions::new(t)).to_json().unwrap();
        let b = verifier.verify(&input, &VerifyOptions::new(t)).to_json().unwrap();
        assert_eq!(a, b, "{}", case["id"]);
    }
}

#[test]
fn the_order_and_layout_of_the_trust_store_file_change_nothing() {
    // Issuers and keys reversed, members in reverse order, compact: the
    // canonical identity is the same, so the WHOLE report is identical.
    for name in ["ts-basic", "ts-rotated", "ts-two-keys", "ts-rotation-window", "ts-a2-revoked"] {
        let original = store_text(name);
        let shuffled = permuted(&original);
        assert_ne!(shuffled, original);
        assert_eq!(load(&shuffled).sha256(), load(&original).sha256(), "{name}");
    }
    for case in cases() {
        let original = store_text(case["trust_store"].as_str().unwrap());
        let a = run(&case, load(&original));
        let b = run(&case, load(&permuted(&original)));
        assert_eq!(a, b, "{}", case["id"]);
    }
}

#[test]
fn reports_do_not_depend_on_the_thread() {
    // Law 1: no thread-order dependence. Every case verified on four threads
    // at once, all sharing one Verifier per store (Verifier is Sync).
    let all = cases();
    let verifiers: std::collections::BTreeMap<String, Verifier> = all
        .iter()
        .map(|c| c["trust_store"].as_str().unwrap().to_string())
        .map(|name| {
            let v = Verifier::new(load(&store_text(&name)));
            (name, v)
        })
        .collect();
    let run_all = || -> Vec<String> {
        all.iter()
            .map(|c| {
                let verifier = &verifiers[c["trust_store"].as_str().unwrap()];
                let input = input_bytes(&c["input"]);
                let previous: Vec<Vec<u8>> = c["previous"].as_array().unwrap().iter().map(input_bytes).collect();
                let refs: Vec<&[u8]> = previous.iter().map(Vec::as_slice).collect();
                let t = Timestamp::parse(c["evaluation_time"].as_str().unwrap()).unwrap();
                let opts = VerifyOptions::new(t)
                    .with_previous(&refs)
                    .require_complete_lineage(c["require_complete_lineage"].as_bool().unwrap());
                verifier.verify(&input, &opts).to_json().unwrap()
            })
            .collect()
    };
    let expected = run_all();
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..4).map(|_| s.spawn(run_all)).collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), expected);
        }
    });
}

#[test]
fn the_evaluation_time_really_is_an_input() {
    // On either side of issued_at (2026-09-10T00:00:00Z) the result differs;
    // nothing else changes it.
    let p = common::json_of(&common::vector());
    let verifier = Verifier::new(common::basic_store());
    let at = |t: &str| verifier.verify(&p, &VerifyOptions::new(Timestamp::parse(t).unwrap()));
    let before = at("2026-09-09T23:59:59Z");
    let after = at("2026-09-10T00:00:00Z");
    assert_eq!(before.verdict, Verdict::Fail);
    assert_eq!(before.failure.unwrap().check, CheckId::TimeNotFuture);
    assert_eq!(after.verdict, Verdict::Pass);
    // Only T and the time check's detail differ between two passing times.
    let (a, b) = (at("2026-09-11T00:00:00Z"), at("2030-01-01T00:00:00Z"));
    assert_eq!(a.verdict, b.verdict);
    assert_ne!(a.evaluation_time, b.evaluation_time);
    let differing: Vec<CheckId> = a.checks.iter().zip(&b.checks).filter(|(x, y)| x != y).map(|(x, _)| x.id).collect();
    assert_eq!(differing, [CheckId::TimeNotFuture]);
}
