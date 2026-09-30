// tests/cli_log_verify.rs — `vmr log verify`: the Community tool reads an
// audit log (specs/audit-log-format-v0.1.md).
//
// What these tests hold to:
//
//  (1) a log is read line by line as it streams from the file, and the first
//      refusal is the answer, with the format's own id (§4.4) and exit 3;
//  (2) a checkpoint is checked under the pinned audit key (§6) and against
//      the log (§6, last paragraph): the log holds at least tree_size
//      entries and its root over them is root_hash;
//  (3) the output never claims more than was checked (§5.1): under the core
//      profile it says nothing about what the entries mean was checked, and
//      without a checkpoint it says no signature was checked;
//  (4) a file that cannot be read is an input error (exit 1).
//
// Every log and checkpoint is built with the format crate (LogBuilder,
// checkpoint::build_signed), never written by hand.

mod common;
use common::*;
use serde_json::{json, Value};
use vmr_audit_log::checkpoint;
use vmr_audit_log::log::LogBuilder;
use vmr_audit_log::profile::CORE;
use vmr_audit_log::profiles::khalm_enforcer;
use vmr_audit_log::profiles::vmr_agent;
use vmr_audit_log::profiles::vmr_agent::digest::ContentSecret;
use vmr_audit_log::vmr_record::hash::{format_hash, sha256};
use vmr_audit_log::vmr_record::canonical::jcs;
use vmr_audit_log::vmr_record::jwk::key_id;
use vmr_audit_log::vmr_record::timestamp::Timestamp;
use vmr_audit_log::MAX_CHECKPOINT_BYTES;
use vmr_cli::keys::PublicKeyFile;

/// The log's audit key, and a key that is not it (test-only, derived).
const AUDIT: &str = "vmr-cli log verify tests: the audit key (test-only)";
const OTHER: &str = "vmr-cli log verify tests: another key (test-only)";

fn at(text: &str) -> Timestamp {
    Timestamp::parse(text).unwrap()
}

/// A log of `n` entries of kind `test.tick` (any kind the core allows), as
/// its builder and its file's bytes.
fn core_log(n: u64) -> (LogBuilder, Vec<u8>) {
    let mut log = LogBuilder::new(key_id(key(AUDIT).verifying_key()));
    let mut file = Vec::new();
    for i in 0..n {
        let entry = log.append(at("2026-09-30T09:00:00Z"), "test.tick", json!({ "n": i }), &CORE).unwrap();
        file.extend_from_slice(entry.canonical.as_bytes());
        file.push(b'\n');
    }
    (log, file)
}

/// A checkpoint over the first `size` entries of `log`, signed by `label`'s
/// key in its own name, as a file's bytes.
fn checkpoint_of(log: &LogBuilder, size: u64, label: &str) -> Vec<u8> {
    let signer = key(label);
    let root = log.root_at(size).unwrap();
    let doc = checkpoint::build_signed(&key_id(signer.verifying_key()), size, &root, at("2026-09-30T12:00:00Z"), &signer)
        .unwrap();
    serde_json::to_vec(&doc).unwrap()
}

/// The audit key's public key file, as `vmr key export` writes it.
fn audit_key_file(s: &Scratch) -> String {
    s.write("audit-key.json", serde_json::to_vec_pretty(&PublicKeyFile::of(key(AUDIT).verifying_key())).unwrap())
}

/// The file's lines, without their line feeds.
fn lines(file: &[u8]) -> Vec<String> {
    String::from_utf8(file.to_vec()).unwrap().lines().map(str::to_string).collect()
}

fn file_of(lines: &[String]) -> Vec<u8> {
    lines.iter().flat_map(|l| format!("{l}\n").into_bytes()).collect()
}

#[test]
fn a_log_and_its_checkpoints_verify_and_the_output_says_what_each_covers() {
    let s = Scratch::new("log-verify-good");
    // Over a mebibyte, so the log is read in more than one piece.
    let (log, file) = core_log(6_000);
    assert!(file.len() > 1024 * 1024);
    let log_path = s.write("audit.jsonl", &file);
    let key_file = audit_key_file(&s);
    let early = s.write("cp-4.json", checkpoint_of(&log, 4, AUDIT));
    let late = s.write("cp-5000.json", checkpoint_of(&log, 5_000, AUDIT));

    let run = vmr(&["log", "verify", "--log", &log_path, "--audit-key", &key_file, "--checkpoint", &early, "--checkpoint", &late]);
    run.expect_code(0);
    let out = &run.stdout;
    assert!(out.starts_with("Audit log verified: 6000 entries"), "{}", run.transcript());
    assert!(out.contains("2 checkpoints signed by the pinned audit key"), "{}", run.transcript());
    assert!(out.contains(&key_id(key(AUDIT).verifying_key())), "{}", run.transcript());
    assert!(out.contains("covers entries 0 to 3"), "{}", run.transcript());
    assert!(out.contains("covers entries 0 to 4999"), "{}", run.transcript());
    assert!(out.contains("entries 5000 to 5999 are in no checkpoint given"), "{}", run.transcript());
    assert!(out.contains(&vmr_audit_log::vmr_record::hash::format_hash(&log.root())), "{}", run.transcript());

    // A checkpoint of the whole log leaves nothing uncovered.
    let whole = s.write("cp-all.json", checkpoint_of(&log, 6_000, AUDIT));
    let run = vmr(&["log", "verify", "--log", &log_path, "--audit-key", &key_file, "--checkpoint", &whole]);
    run.expect_code(0);
    assert!(run.stdout.contains("covers entries 0 to 5999, the whole log"), "{}", run.transcript());
    assert!(!run.stdout.contains("in no checkpoint"), "{}", run.transcript());
}

#[test]
fn under_the_core_profile_the_output_says_what_was_not_checked() {
    // Audit-log format §5.1: a reader that accepts a log under the core
    // profile has checked less, and MUST NOT report more.
    let s = Scratch::new("log-verify-core");
    let (log, file) = core_log(5);
    let log_path = s.write("audit.jsonl", &file);
    let key_file = audit_key_file(&s);
    let cp = s.write("cp.json", checkpoint_of(&log, 5, AUDIT));
    let run = vmr(&["log", "verify", "--log", &log_path, "--audit-key", &key_file, "--checkpoint", &cp]);
    run.expect_code(0);
    assert!(run.stdout.contains("Profile:      core"), "{}", run.transcript());
    assert!(run.stdout.contains("nothing about what the entries mean"), "{}", run.transcript());

    // Without a checkpoint only the chain is checked, and it says so, with or
    // without the key.
    for args in [
        vec!["log", "verify", "--log", log_path.as_str()],
        vec!["log", "verify", "--log", log_path.as_str(), "--audit-key", key_file.as_str()],
    ] {
        let run = vmr(&args);
        run.expect_code(0);
        assert!(run.stdout.starts_with("Audit log verified: 5 entries; its chain only"), "{}", run.transcript());
        assert!(run.stdout.contains("no signature was checked"), "{}", run.transcript());
        assert!(!run.stdout.contains("signed by the pinned audit key"), "{}", run.transcript());
    }
}

#[test]
fn a_named_profile_checks_the_entries_kinds_and_the_core_one_does_not() {
    let s = Scratch::new("log-verify-profile");
    let mut log = LogBuilder::new(key_id(key(AUDIT).verifying_key()));
    let mut file = Vec::new();
    for count in [3u64, 1] {
        let entry = log
            .append(at("2026-09-30T09:00:00Z"), "events.dropped", json!({ "count": count }), &khalm_enforcer::PROFILE)
            .unwrap();
        file.extend_from_slice(entry.canonical.as_bytes());
        file.push(b'\n');
    }
    let enforcer_log = s.write("enforcer.jsonl", &file);
    let run = vmr(&["log", "verify", "--log", &enforcer_log, "--profile", "khalm-vmr.enforcer"]);
    run.expect_code(0);
    assert!(run.stdout.contains("Profile:      khalm-vmr.enforcer"), "{}", run.transcript());
    assert!(run.stdout.contains("each entry's kind and detail"), "{}", run.transcript());

    // A kind the core allows and the profile does not know.
    let (_, file) = core_log(2);
    let core_path = s.write("core.jsonl", &file);
    vmr(&["log", "verify", "--log", &core_path]).expect_code(0);
    let run = vmr(&["log", "verify", "--log", &core_path, "--profile", "khalm-vmr.enforcer"]);
    run.expect_code(3);
    assert!(run.stdout.contains("audit_entry.structure"), "{}", run.transcript());

    // A profile this build does not have is a usage error.
    vmr(&["log", "verify", "--log", &core_path, "--profile", "acme.unknown"]).expect_code(1);
}

#[test]
fn a_tampered_line_is_refused_with_the_formats_id() {
    let s = Scratch::new("log-verify-tampered");
    let (_, file) = core_log(6);
    let original = lines(&file);

    // Line 2 rewritten in canonical form: it reads as an entry, and line 3's
    // previous_root no longer names the root before it.
    let mut changed = original.clone();
    let mut value: Value = serde_json::from_str(&changed[2]).unwrap();
    value["detail"]["n"] = json!(999);
    changed[2] = jcs(&value);
    let path = s.write("changed.jsonl", file_of(&changed));
    let run = vmr(&["log", "verify", "--log", &path]);
    run.expect_code(3);
    assert!(run.stdout.starts_with("Audit log NOT verified: audit_log.previous_root"), "{}", run.transcript());
    assert!(run.stdout.contains("line 3's previous_root"), "{}", run.transcript());
    assert!(run.stdout.contains("3 entries accepted before the refusal"), "{}", run.transcript());

    // The same line with a space the canonical form does not have.
    let mut spaced = original.clone();
    spaced[4] = spaced[4].replacen(',', ", ", 1);
    let path = s.write("spaced.jsonl", file_of(&spaced));
    let run = vmr(&["log", "verify", "--log", &path]);
    run.expect_code(3);
    assert!(run.stdout.contains("audit_entry.not_canonical"), "{}", run.transcript());
}

#[test]
fn a_torn_tail_is_refused() {
    let s = Scratch::new("log-verify-torn");
    let (_, mut file) = core_log(3);
    file.pop();
    let path = s.write("torn.jsonl", &file);
    let run = vmr(&["log", "verify", "--log", &path]);
    run.expect_code(3);
    assert!(run.stdout.contains("audit_log.torn_tail"), "{}", run.transcript());
}

#[test]
fn a_checkpoint_signed_by_another_key_is_refused() {
    let s = Scratch::new("log-verify-wrong-key");
    let (log, file) = core_log(4);
    let path = s.write("audit.jsonl", &file);
    let key_file = audit_key_file(&s);
    let cp = s.write("other.json", checkpoint_of(&log, 4, OTHER));
    let run = vmr(&["log", "verify", "--log", &path, "--audit-key", &key_file, "--checkpoint", &cp]);
    run.expect_code(3);
    assert!(run.stdout.starts_with("Audit log NOT verified: checkpoint.wrong_key"), "{}", run.transcript());
    assert!(run.stdout.contains("'"), "names the checkpoint file: {}", run.transcript());
}

#[test]
fn a_checkpoint_that_is_not_of_this_log_is_refused() {
    let s = Scratch::new("log-verify-not-in-log");
    let (_, file) = core_log(10);
    let path = s.write("audit.jsonl", &file);
    let key_file = audit_key_file(&s);

    // Another log of the same key and size: signed, and not this log's root.
    let mut other = LogBuilder::new(key_id(key(AUDIT).verifying_key()));
    for i in 0..10u64 {
        other.append(at("2026-09-30T09:00:00Z"), "test.tock", json!({ "n": i }), &CORE).unwrap();
    }
    let cp = s.write("other-log.json", checkpoint_of(&other, 10, AUDIT));
    let run = vmr(&["log", "verify", "--log", &path, "--audit-key", &key_file, "--checkpoint", &cp]);
    run.expect_code(3);
    assert!(run.stdout.contains("log_verify.checkpoint_not_in_log"), "{}", run.transcript());
    assert!(run.stdout.contains("is not its root_hash"), "{}", run.transcript());

    // A checkpoint over more entries than the log holds: a log cut short.
    for i in 10..12u64 {
        other.append(at("2026-09-30T09:00:00Z"), "test.tock", json!({ "n": i }), &CORE).unwrap();
    }
    let cp = s.write("longer.json", checkpoint_of(&other, 12, AUDIT));
    let run = vmr(&["log", "verify", "--log", &path, "--audit-key", &key_file, "--checkpoint", &cp]);
    run.expect_code(3);
    assert!(run.stdout.contains("log_verify.checkpoint_not_in_log"), "{}", run.transcript());
    assert!(run.stdout.contains("covers 12 entries; the log holds 10"), "{}", run.transcript());
}

#[test]
fn an_oversized_checkpoint_is_refused_before_it_is_parsed() {
    let s = Scratch::new("log-verify-cp-size");
    let (_, file) = core_log(2);
    let path = s.write("audit.jsonl", &file);
    let key_file = audit_key_file(&s);
    let cp = s.write("big.json", vec![b'{'; MAX_CHECKPOINT_BYTES + 1]);
    let run = vmr(&["log", "verify", "--log", &path, "--audit-key", &key_file, "--checkpoint", &cp]);
    run.expect_code(3);
    assert!(run.stdout.contains("checkpoint.size"), "{}", run.transcript());
}

#[test]
fn a_file_that_cannot_be_read_is_an_input_error() {
    let s = Scratch::new("log-verify-missing");
    let (log, file) = core_log(2);
    let path = s.write("audit.jsonl", &file);
    let key_file = audit_key_file(&s);
    let cp = s.write("cp.json", checkpoint_of(&log, 2, AUDIT));
    let missing = s.arg("missing.jsonl");

    let run = vmr(&["log", "verify", "--log", &missing]);
    run.expect_code(1);
    assert!(run.stderr.contains("cannot read audit log"), "{}", run.transcript());
    vmr(&["log", "verify", "--log", &path, "--audit-key", &key_file, "--checkpoint", &missing]).expect_code(1);
    vmr(&["log", "verify", "--log", &path, "--audit-key", &missing, "--checkpoint", &cp]).expect_code(1);
    // A checkpoint needs the key it is checked under.
    vmr(&["log", "verify", "--log", &path, "--checkpoint", &cp]).expect_code(1);
    // A record is not a public key file.
    let not_a_key = s.write("not-a-key.json", &file);
    vmr(&["log", "verify", "--log", &path, "--audit-key", &not_a_key, "--checkpoint", &cp]).expect_code(1);
}

#[test]
fn the_help_lists_the_exit_codes_log_verify_returns() {
    let run = vmr(&["log", "verify", "--help"]);
    run.expect_code(0);
    let table = run.stdout.split("Exit codes:").nth(1).unwrap_or_default().to_string();
    let codes: Vec<u8> =
        (0..=4u8).filter(|code| table.lines().any(|line| line.starts_with(&format!("  {code}  ")))).collect();
    assert_eq!(codes, [0, 1, 3]);
    for path in ["specs/", "docs/", ".md"] {
        assert!(!run.stdout.contains(path), "cites `{path}`:\n{}", run.transcript());
    }
}

/// A `vmr.agent` log (the agent profile): one session that reaches a
/// registered tool and runs a call after a person approves it, then proposes
/// a tool it never registered, written in clear, which dispatch refuses.
fn agent_log() -> Vec<u8> {
    let session = "urn:uuid:0f3c6a2e-8d4b-4c1e-9a7f-2b5d8e1c4a90";
    let secret = ContentSecret::from_bytes([7; 32]);
    let digest = |what: &str| secret.session_key(session).item_key("call.proposed", "arguments_digest", 0).digest(what.as_bytes());
    let entries = [
        ("session.started", json!({ "session_id": session, "runtime": "example-runtime 1.0", "model": "example-model", "configuration_hash": format_hash(&sha256(b"settings")) })),
        ("tool.registered", json!({ "session_id": session, "tool": "search_web" })),
        ("call.proposed", json!({ "session_id": session, "call": 0, "turn": 0, "tool": "search_web", "arguments_digest": digest("a") })),
        ("approval.requested", json!({ "session_id": session, "call": 0 })),
        ("approval.granted", json!({ "session_id": session, "call": 0, "approver": "staff:4411", "latency_ms": 900 })),
        ("gate.decided", json!({ "session_id": session, "call": 0, "gate": "approval", "decision": "permitted" })),
        ("call.executed", json!({ "session_id": session, "call": 0, "outcome": "ok" })),
        ("call.proposed", json!({ "session_id": session, "call": 1, "turn": 1, "tool": "transfer_funds", "arguments_digest": digest("b") })),
        ("gate.decided", json!({ "session_id": session, "call": 1, "gate": "dispatch", "decision": "refused", "refusal": "dispatch.unknown_tool" })),
        ("call.refused", json!({ "session_id": session, "call": 1, "gate": "dispatch", "refusal": "dispatch.unknown_tool" })),
        ("session.ended", json!({ "session_id": session, "outcome": "completed" })),
    ];
    let mut log = LogBuilder::new(key_id(key(AUDIT).verifying_key()));
    let mut file = Vec::new();
    for (kind, detail) in entries {
        let entry = log.append(at("2026-09-30T09:00:00Z"), kind, detail, &vmr_agent::PROFILE).unwrap();
        file.extend_from_slice(entry.canonical.as_bytes());
        file.push(b'\n');
    }
    file
}

#[test]
fn the_agent_profile_reports_what_the_entries_say_as_the_writers_statements() {
    let s = Scratch::new("log-verify-agent");
    let path = s.write("agent.jsonl", agent_log());
    let run = vmr(&["log", "verify", "--log", &path, "--profile", "vmr.agent"]);
    // A note never changes the result.
    run.expect_code(0);
    let out = &run.stdout;
    assert!(out.starts_with("Audit log verified: 11 entries"), "{}", run.transcript());
    assert!(out.contains("Profile:      vmr.agent: each entry's kind and detail"), "{}", run.transcript());
    // After the integrity result, labelled as what the entries say.
    let said = out.split("What the entries say").nth(1).unwrap_or_else(|| panic!("no summary: {}", run.transcript()));
    assert!(said.starts_with(" (the writer's statements, not verified facts):"), "{}", run.transcript());
    assert!(said.contains("Sessions:     1\n"), "{}", run.transcript());
    assert!(said.contains("Calls:        2 proposed; 1 refused: 1 by dispatch\n"), "{}", run.transcript());
    assert!(said.contains("Approvals:    1 granted, 0 denied, 0 timed out\n"), "{}", run.transcript());
    assert!(said.contains("Notes:        1:"), "{}", run.transcript());
    // The note names the entry and the call, never the tool's name: it may
    // be model output written in clear.
    assert!(said.contains("entry 7: session urn:uuid:0f3c6a2e-8d4b-4c1e-9a7f-2b5d8e1c4a90: call 1 proposes, as tool, a name the session could not reach"), "{}", run.transcript());
    assert!(!said.contains("transfer_funds"), "{}", run.transcript());
    assert!(!said.contains("Lost events"), "none were lost: {}", run.transcript());

    // The core profile reads the same log and says nothing of what it means.
    let run = vmr(&["log", "verify", "--log", &path]);
    run.expect_code(0);
    assert!(!run.stdout.contains("What the entries say"), "{}", run.transcript());
}

#[test]
fn the_agent_summary_is_bounded_and_claims_only_the_checks_it_made() {
    // Twelve calls, each refused by a gate of the writer's own: the Calls line
    // names at most GATES_SHOWN gates and sums the others. No entry breaks a
    // rule between entries, and the Notes line names what was checked.
    let s = Scratch::new("log-verify-agent-gates");
    let session = "urn:uuid:0f3c6a2e-8d4b-4c1e-9a7f-2b5d8e1c4a90";
    let secret = ContentSecret::from_bytes([7; 32]);
    let digest = |what: &str| secret.session_key(session).item_key("call.proposed", "arguments_digest", 0).digest(what.as_bytes());
    let mut log = LogBuilder::new(key_id(key(AUDIT).verifying_key()));
    let mut file = Vec::new();
    let mut add = |kind: &str, detail: Value| {
        let entry = log.append(at("2026-09-30T09:00:00Z"), kind, detail, &vmr_agent::PROFILE).unwrap();
        file.extend_from_slice(entry.canonical.as_bytes());
        file.push(b'\n');
    };
    for n in 0..12u64 {
        let gate = format!("own_gate_{}", char::from(b'a' + n as u8));
        add("call.proposed", json!({ "session_id": session, "call": n, "turn": 0, "tool_digest": digest("t"), "arguments_digest": digest("a") }));
        add("gate.decided", json!({ "session_id": session, "call": n, "gate": gate, "decision": "refused", "refusal": "policy.forbidden" }));
        add("call.refused", json!({ "session_id": session, "call": n, "gate": gate, "refusal": "policy.forbidden" }));
    }
    let path = s.write("agent.jsonl", file);
    let run = vmr(&["log", "verify", "--log", &path, "--profile", "vmr.agent"]);
    run.expect_code(0);
    let calls = run.stdout.lines().map(str::trim_start).find(|l| l.starts_with("Calls:")).unwrap_or_else(|| panic!("{}", run.transcript()));
    assert_eq!(
        calls,
        "Calls:        12 proposed; 12 refused: 1 by own_gate_a, 1 by own_gate_b, 1 by own_gate_c, 1 by own_gate_d, 1 by own_gate_e, 1 by own_gate_f, 1 by own_gate_g, 1 by own_gate_h, and 4 by other gates",
        "{}",
        run.transcript()
    );
    let notes = run.stdout.lines().map(str::trim_start).find(|l| l.starts_with("Notes:")).unwrap_or_else(|| panic!("{}", run.transcript()));
    assert!(notes.starts_with("Notes:        none, of the checks made:"), "{}", run.transcript());
    assert!(!notes.contains("keep the profile's rules"), "{}", run.transcript());
}

#[test]
fn the_agent_profile_refuses_an_entry_its_checks_refuse() {
    let s = Scratch::new("log-verify-agent-refused");
    let mut lines = lines(&agent_log());
    // Entry 7 names its tool both in clear and as a digest (section 4.6
    // rule 4), rewritten canonical and chained, so only the profile refuses.
    let mut log = LogBuilder::new(key_id(key(AUDIT).verifying_key()));
    for (i, line) in lines.iter_mut().enumerate() {
        let mut value: Value = serde_json::from_str(line).unwrap();
        if i == 7 {
            value["detail"]["tool_digest"] = value["detail"]["arguments_digest"].clone();
        }
        let detail = value["detail"].clone();
        *line = log.append(at("2026-09-30T09:00:00Z"), value["kind"].as_str().unwrap(), detail, &CORE).unwrap().canonical;
    }
    let path = s.write("agent.jsonl", file_of(&lines));
    vmr(&["log", "verify", "--log", &path]).expect_code(0);
    let run = vmr(&["log", "verify", "--log", &path, "--profile", "vmr.agent"]);
    run.expect_code(3);
    assert!(run.stdout.starts_with("Audit log NOT verified: audit_entry.structure: call.proposed:"), "{}", run.transcript());
    assert!(run.stdout.contains("7 entries accepted before the refusal"), "{}", run.transcript());
    assert!(!run.stdout.contains("What the entries say"), "{}", run.transcript());
}
