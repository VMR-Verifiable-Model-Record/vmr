// tests/log.rs — `logVerifier` and `checkItem`, natively: the answers the
// built module gives (js/test/log.test.mjs holds it to the same ones).
//
//  (1) every audit-log vector that is a whole log (the core vectors' logs and
//      one-line entries, the vmr.agent profile's entries) gives its declared
//      result: "accept" is the outcome chain_only, anything else the outcome
//      failed with that refusal id;
//  (2) docs/examples/agent-log/ verifies with the counts `vmr log verify`
//      prints, the same whatever the chunking, and fails for one changed
//      byte;
//  (3) checkItem agrees with the example README's disclosure;
//  (4) the framed requests of js/vmr-check.js reach the same answers.

mod common;

use common::*;
use serde_json::{json, Value};
use vmr_check::api;
use vmr_check::log::{check_item, CheckItemRequest, LogRequest, LogSession};

fn example(name: &str) -> Vec<u8> {
    std::fs::read(repo().join("docs/examples/agent-log").join(name)).unwrap()
}

fn run(req: &LogRequest<'_>, log: &[u8], chunk: usize) -> Value {
    let mut session = LogSession::new(req);
    for piece in log.chunks(chunk.max(1)) {
        if !session.update(piece) {
            break;
        }
    }
    session.finish()
}

/// Every whole-log case of the two vector files: (id, profile, bytes, expect).
fn whole_log_cases() -> Vec<(String, String, Vec<u8>, String)> {
    let mut out = Vec::new();
    let core = vector_file("audit-log/cases.json");
    for case in core["logs"].as_array().unwrap() {
        let raw = case["raw"].as_str().unwrap().as_bytes().to_vec();
        out.push((case["id"].as_str().unwrap().into(), "core".into(), raw, case["expect"].as_str().unwrap().into()));
    }
    let agent = vector_file("audit-profile-agent/cases.json");
    let entries = core["entries"].as_array().unwrap().iter().map(|c| (c, c["profile"].as_str().unwrap_or("core")));
    let agent_entries = agent["entries"].as_array().unwrap().iter().map(|c| (c, "vmr.agent"));
    for (case, profile) in entries.chain(agent_entries) {
        // One line, read as a log of one entry.
        let mut raw = case["raw"].as_str().unwrap().as_bytes().to_vec();
        raw.push(b'\n');
        out.push((case["id"].as_str().unwrap().into(), profile.into(), raw, case["expect"].as_str().unwrap().into()));
    }
    out
}

#[test]
fn every_whole_log_vector_gives_its_declared_result() {
    let cases = whole_log_cases();
    assert_eq!(cases.len(), 6 + 12 + 74, "the vector files changed: review this test");
    for (id, profile, raw, expect) in cases {
        let answer = run(&LogRequest { profile: Some(&profile), ..LogRequest::default() }, &raw, 1 << 20);
        if expect == "accept" {
            assert_eq!(answer["outcome"], "chain_only", "{id}: {answer}");
            assert_eq!(answer["refusal"], Value::Null, "{id}");
        } else {
            assert_eq!(answer["outcome"], "failed", "{id}: {answer}");
            assert_eq!(answer["refusal"]["id"], expect.as_str(), "{id}: {answer}");
        }
    }
}

#[test]
fn the_example_agent_log_verifies_with_the_counts_vmr_prints() {
    let (key, cp, log) = (example("audit-key.pub.json"), example("checkpoint.json"), example("log.jsonl"));
    let req = LogRequest { profile: Some("vmr.agent"), audit_key: Some(&key), checkpoints: vec![&cp], ..LogRequest::default() };
    let answer = run(&req, &log, 1 << 20);
    assert_eq!(answer["outcome"], "verified", "{answer}");
    assert_eq!(answer["entries"], 14);
    assert_eq!(answer["headline"], "14 entries; 1 checkpoint signed by the pinned audit key covers entries 0 to 13");
    assert_eq!(answer["uncovered"], Value::Null);
    assert_eq!(answer["checkpoints"], json!([{ "source": "checkpoints[0]", "tree_size": 14, "issued_at": "2026-09-30T08:42:26Z", "covers_whole_log": true }]));
    let summary = &answer["summary"];
    assert_eq!(summary["statements_of"], "the log's writer");
    assert_eq!((summary["sessions"].clone(), summary["calls_proposed"].clone()), (json!(1), json!(2)));
    assert_eq!(summary["refused_by_gate"], json!({ "guard": 1 }));
    assert_eq!(summary["approvals_granted"], 1);
    for chunk in [1, 7] {
        assert_eq!(run(&req, &log, chunk), answer, "chunks of {chunk}");
    }
    // Without the checkpoint, only the chain; under the core profile, the
    // statements say nothing about the entries' meaning was checked.
    let chain = run(&LogRequest { audit_key: Some(&key), ..LogRequest::default() }, &log, 4096);
    assert_eq!(chain["outcome"], "chain_only");
    assert_eq!(chain["uncovered"], json!({ "from": 0, "to": 13 }));
    let checked: Vec<&str> = chain["checked"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
    assert!(checked.iter().any(|s| s.ends_with("nothing about what the entries mean is checked")), "{checked:?}");
    assert!(checked.iter().any(|s| s.ends_with("no signature was checked")), "{checked:?}");
    assert_eq!(chain["summary"], Value::Null);
    // One changed byte.
    let mut changed = log.clone();
    let at = changed.len() / 2;
    changed[at] ^= 1;
    assert_eq!(run(&req, &changed, 1 << 20)["outcome"], "failed");
}

#[test]
fn check_item_agrees_with_the_example_readme() {
    let log = example("log.jsonl");
    let content = example("arguments.txt");
    let item_key = "11200c6264981efb8fbbdcd4e3ce185d1db9dcda617e774843dff5c578b0cd3d";
    let req = |member, item_key, content| CheckItemRequest { log: &log, index: 4, member, item_key, content };
    let answer = check_item(&req("arguments_digest", item_key, &content));
    assert_eq!(answer["matches"], true, "{answer}");
    assert_eq!(answer["label"], "call.proposed/arguments_digest/4");
    assert_eq!(check_item(&req("arguments_digest", item_key, b"{\"city\": \"Oslo\"}"))["matches"], false);
    assert_eq!(check_item(&req("nope", item_key, &content))["refusal"]["id"], "check_item.no_digest");
    assert_eq!(check_item(&req("arguments_digest", "11zz", &content))["refusal"]["id"], "check_item.item_key");
    let missing = check_item(&CheckItemRequest { log: &log, index: 99, member: "arguments_digest", item_key, content: &content });
    assert_eq!(missing["refusal"]["id"], "check_item.no_entry");
}

fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

#[test]
fn the_framed_requests_reach_the_same_answers() {
    let (key, cp, log) = (example("audit-key.pub.json"), example("checkpoint.json"), example("log.jsonl"));
    let header = br#"{"profile":"vmr.agent","audit_key":true,"checkpoints":1,"checkpoints_jsonl":true}"#;
    let mut session = api::log_session(&framed(&[header, &key, &cp, &cp]));
    session.update(&log);
    let answer = session.finish();
    assert_eq!(answer["outcome"], "verified", "{answer}");
    assert_eq!(answer["checkpoints"][1]["source"], "checkpointsJsonl line 1");
    // A header that does not match its frames, and a profile that is not one.
    let mut broken = api::log_session(&framed(&[header, &key]));
    assert!(!broken.update(&log));
    assert_eq!(broken.finish()["refusal"]["id"], "request.malformed");
    let unknown = api::log_session(&framed(&[br#"{"profile":"acme.x"}"#])).finish();
    assert_eq!(unknown["refusal"]["id"], "profile.unknown");
    // checkItem as op 6.
    let item = br#"{"index":4,"member":"arguments_digest","item_key":"11200c6264981efb8fbbdcd4e3ce185d1db9dcda617e774843dff5c578b0cd3d"}"#;
    let answer: Value =
        serde_json::from_slice(&api::call(api::OP_CHECK_ITEM, &framed(&[item, &log, &example("arguments.txt")]))).unwrap();
    assert_eq!(answer["matches"], true, "{answer}");
}
