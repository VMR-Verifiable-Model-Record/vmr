// tests/cli_log_seal.rs — `vmr log init`, `log seal`, `log disclose` and
// `log check-item`: the Community tool writes a vmr.agent log from events a
// runtime sends on a pipe (specs/audit-profile-agent-v0.1.md §3, §5), and
// both sides of a disclosure.
//
// What these tests hold to:
//
//  (1) what the sealer writes, `log verify` accepts under vmr.agent, with its
//      checkpoints signed by the directory's audit key;
//  (2) each content form gives the digest the profile's vectors give, and the
//      content is written nowhere;
//  (3) a refused event is answered as refused and recorded as events.dropped;
//  (4) a torn tail is recovered on the next start; one sealer per directory;
//  (5) disclose and check-item agree, and a changed byte of content does not;
//  (6) the audit key and the content secret never leave their own files.

mod common;
use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SESSION: &str = "urn:uuid:0f3c6a2e-8d4b-4c1e-9a7f-2b5d8e1c4a90";
const HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// `vmr log seal --dir DIR extra...`, with `input` on its standard input.
fn seal(dir: &Path, extra: &[&str], input: &str) -> Run {
    let mut child = Command::new(vmr_path())
        .args(["log", "seal", "--dir", dir.to_str().unwrap()])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vmr log seal");
    let mut stdin = child.stdin.take().unwrap();
    let text = input.to_string();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(text.as_bytes());
    });
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"),
        stderr: String::from_utf8_lossy(&out.stderr).replace("\r\n", "\n"),
    }
}

/// The events as input lines.
fn lines(events: &[Value]) -> String {
    events.iter().map(|e| format!("{e}\n")).collect()
}

/// The answers a seal printed, one JSON value a line.
fn answers(run: &Run) -> Vec<Value> {
    run.stdout.lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}"))).collect()
}

/// A fresh log directory `vmr log init` made.
fn init(s: &Scratch, name: &str) -> PathBuf {
    let dir = s.path(name);
    vmr(&["log", "init", "--dir", dir.to_str().unwrap()]).expect_code(0);
    dir
}

/// `log verify` of `dir`'s files under vmr.agent, with its latest checkpoint
/// and its checkpoint history.
fn verify(dir: &Path) -> Run {
    let arg = |name: &str| dir.join(name).to_string_lossy().into_owned();
    vmr(&[
        "log", "verify", "--profile", "vmr.agent", "--log", &arg("log.jsonl"), "--audit-key", &arg("audit-key.pub.json"),
        "--checkpoint", &arg("checkpoint.json"), "--checkpoints", &arg("checkpoints.jsonl"),
    ])
}

/// A small session: a tool registered, a turn, one call permitted and run,
/// the session's end.
fn session() -> Vec<Value> {
    vec![
        json!({ "kind": "session.started", "detail": { "session_id": SESSION, "runtime": "test-runtime 1.0", "model": "test-model", "configuration_hash": HASH } }),
        json!({ "kind": "tool.registered", "detail": { "session_id": SESSION, "tool": "get_weather" } }),
        json!({ "kind": "turn.started", "detail": { "session_id": SESSION, "turn": 0 }, "content": { "input_digest": { "text": "What is the weather in Oslo?" } } }),
        json!({ "kind": "call.proposed", "detail": { "session_id": SESSION, "call": 0, "turn": 0, "tool": "get_weather" }, "content": { "arguments_digest": { "text": "{\"city\": \"Oslo\"}" } } }),
        json!({ "kind": "gate.decided", "detail": { "session_id": SESSION, "call": 0, "gate": "dispatch", "decision": "permitted" } }),
        json!({ "kind": "call.executed", "detail": { "session_id": SESSION, "call": 0, "outcome": "ok" }, "content": { "result_digest": { "json": { "temp_c": 7 } } } }),
        json!({ "kind": "session.ended", "detail": { "session_id": SESSION, "outcome": "completed" } }),
    ]
}

#[test]
fn a_sealed_session_verifies_with_its_checkpoints() {
    let s = Scratch::new("seal-session");
    let dir = init(&s, "log");
    let run = seal(&dir, &[], &lines(&session()));
    run.expect_code(0);
    let got = answers(&run);
    assert_eq!(got, (0..7).map(|i| json!({ "index": i })).collect::<Vec<_>>(), "{}", run.transcript());
    let v = verify(&dir);
    v.expect_code(0);
    assert!(v.stdout.starts_with("Audit log verified: 7 entries; 2 checkpoints signed by the pinned audit key cover entries 0 to 6"), "{}", v.transcript());
    // No content reached the log.
    let log = std::fs::read_to_string(dir.join("log.jsonl")).unwrap();
    for content in ["Oslo", "weather in", "temp_c"] {
        assert!(!log.contains(content), "{content} is in the log");
    }
    assert!(log.contains("\"arguments_digest\":\"hmac-sha256:"));
}

#[test]
fn each_content_form_gives_the_profiles_vector_digest() {
    // The vectors' own secret and session, and the vectors' indices: the
    // digests the sealer writes must be the vectors' (§3), each form given as
    // the sealer's input takes it.
    let cases: Value = serde_json::from_slice(
        &std::fs::read(repo().join("specs/test-vectors/audit-profile-agent/cases.json")).unwrap(),
    )
    .unwrap();
    let case = |id: &str| cases["digests"].as_array().unwrap().iter().find(|c| c["id"] == id).unwrap().clone();
    let (tool, empty, bytes, parsed) =
        (case("agent-digest-tool-name"), case("agent-digest-empty"), case("agent-digest-bytes"), case("agent-digest-json"));
    let s = Scratch::new("seal-vectors");
    let dir = init(&s, "log");
    std::fs::write(dir.join("content-secret"), format!("{}\n", tool["content_secret"].as_str().unwrap())).unwrap();
    let session = tool["session_id"].as_str().unwrap();

    let raw = hex_decode(bytes["content_hex"].as_str().unwrap());
    let base64 = {
        // Standard padded base64, written here without a library.
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in raw.chunks(3) {
            let n = (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    };
    let mut events = Vec::new();
    for index in 0..=1047u64 {
        events.push(match index {
            0 => json!({ "kind": "tool.registered", "detail": { "session_id": session }, "content": { "tool_digest": { "text": tool["content_text"] } } }),
            7 => json!({ "kind": "turn.started", "detail": { "session_id": session, "turn": 0 }, "content": { "input_digest": { "text": "" } } }),
            1043 => json!({ "kind": "call.proposed", "detail": { "session_id": session, "call": 0, "turn": 0, "tool": "pay" }, "content": { "arguments_digest": { "base64": base64 } } }),
            1047 => json!({ "kind": "call.executed", "detail": { "session_id": session, "call": 0, "outcome": "ok" }, "content": { "result_digest": { "json": parsed["content_json"] } } }),
            _ => json!({ "kind": "policy.loaded", "detail": { "policy_hash": HASH } }),
        });
    }
    let run = seal(&dir, &[], &lines(&events));
    run.expect_code(0);
    assert_eq!(answers(&run).len(), 1048);
    let log = std::fs::read_to_string(dir.join("log.jsonl")).unwrap();
    let entries: Vec<Value> = log.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    for (case, index) in [(&tool, 0usize), (&empty, 7), (&bytes, 1043), (&parsed, 1047)] {
        let member = case["member"].as_str().unwrap();
        assert_eq!(entries[index]["detail"][member], case["digest"], "{}", case["id"]);
    }
    verify(&dir).expect_code(0);
    // Every 1000 entries, and the input's end.
    assert_eq!(std::fs::read_to_string(dir.join("checkpoints.jsonl")).unwrap().lines().count(), 2);
}

/// Doubles of 16 and 17 significant digits that a parser that is not
/// correctly rounded reads one unit in the last place off (QA B1), and an
/// integer past 2^53 that rounds to even.
const LONG_DOUBLES: &str = r#"{"a": 502.20470411297845, "b": 0.009913979737008163, "c": [-6.360375184993316e+38, 9007199254740993.0]}"#;

#[test]
fn json_content_with_17_digit_doubles_gets_the_digest_of_its_rfc_8785_form() {
    // The expected digest was computed outside vmr, from profile §3 and RFC
    // 8785 alone: Python's correctly rounded json.loads, numbers written as
    // ECMAScript's Number::toString writes them, and the hmac module:
    //   JCS: {"a":502.20470411297845,"b":0.009913979737008163,
    //         "c":[-6.360375184993316e+38,9007199254740992]}
    //   HMAC(HMAC(HMAC(secret, session), "call.executed/result_digest/0"), JCS)
    let s = Scratch::new("seal-doubles");
    let dir = init(&s, "log");
    std::fs::write(dir.join("content-secret"), format!("{}\n", "11".repeat(32))).unwrap();
    let event = format!(
        r#"{{"kind": "call.executed", "detail": {{"session_id": "{SESSION}", "call": 0, "outcome": "ok"}}, "content": {{"result_digest": {{"json": {LONG_DOUBLES}}}}}}}"#
    );
    let run = seal(&dir, &[], &format!("{event}\n"));
    run.expect_code(0);
    assert_eq!(answers(&run), [json!({ "index": 0 })], "{}", run.transcript());
    let log = std::fs::read_to_string(dir.join("log.jsonl")).unwrap();
    let entry: Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
    assert_eq!(
        entry["detail"]["result_digest"],
        "hmac-sha256:6e616535bf0520f5062f1a8d07ab3a77b63687d0cfd059f2e66d26b5d27c717a"
    );
}

#[test]
fn a_core_log_of_17_digit_doubles_seals_and_verifies() {
    let s = Scratch::new("seal-core-doubles");
    let dir = init(&s, "log");
    let input: String = (0..4).map(|n| format!("{{\"kind\": \"test.tick\", \"detail\": {{\"n\": {n}, \"x\": {LONG_DOUBLES}}}}}\n")).collect();
    let run = seal(&dir, &["--profile", "core"], &input);
    run.expect_code(0);
    assert_eq!(answers(&run), (0..4).map(|i| json!({ "index": i })).collect::<Vec<_>>(), "{}", run.transcript());
    let log = std::fs::read_to_string(dir.join("log.jsonl")).unwrap();
    assert!(log.lines().all(|l| l.contains("502.20470411297845") && l.contains("0.009913979737008163")), "{log}");
    let arg = |name: &str| dir.join(name).to_string_lossy().into_owned();
    let v = vmr(&[
        "log", "verify", "--log", &arg("log.jsonl"), "--audit-key", &arg("audit-key.pub.json"),
        "--checkpoints", &arg("checkpoints.jsonl"),
    ]);
    v.expect_code(0);
}

#[test]
fn a_refused_event_is_answered_and_recorded_as_dropped() {
    let s = Scratch::new("seal-refused");
    let dir = init(&s, "log");
    let input = [
        "not json".to_string(),
        json!({ "kind": "session.ended", "detail": { "session_id": SESSION, "outcome": "maybe" } }).to_string(),
        json!({ "kind": "call.proposed", "detail": { "session_id": SESSION, "call": 0, "turn": 0, "tool": "t", "arguments_digest": format!("hmac-sha256:{}", "0".repeat(64)) } }).to_string(),
        json!({ "kind": "call.proposed", "detail": { "session_id": SESSION, "call": 0, "turn": 0, "tool": "t" }, "content": { "arguments_digest": { "hex": "00" } } }).to_string(),
        json!({ "kind": "policy.loaded", "detail": { "policy_hash": HASH }, "extra": 1 }).to_string(),
        "x".repeat(1024 * 1024 + 1),
    ]
    .join("\n");
    let run = seal(&dir, &[], &format!("{input}\n"));
    run.expect_code(0);
    let got = answers(&run);
    let ids: Vec<&str> = got.iter().map(|a| a["refused"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        ["seal.syntax", "audit_entry.structure", "seal.digest_in_detail", "seal.content", "seal.structure", "seal.size"],
        "{}",
        run.transcript()
    );
    for (i, a) in got.iter().enumerate() {
        assert_eq!(a["recorded"], json!({ "kind": "events.dropped", "index": i }), "{a}");
        assert!(a["message"].as_str().is_some_and(|m| !m.is_empty()));
    }
    let log = std::fs::read_to_string(dir.join("log.jsonl")).unwrap();
    assert_eq!(log.lines().count(), 6);
    assert!(log.lines().all(|l| l.contains("\"kind\":\"events.dropped\"") && l.contains("\"count\":1")));
    let v = verify(&dir);
    v.expect_code(0);
    assert!(v.stdout.contains("Lost events:  6 the writer says it could not record"), "{}", v.transcript());
}

#[test]
fn content_under_the_core_profile_is_refused_and_nothing_is_recorded() {
    let s = Scratch::new("seal-core");
    let dir = init(&s, "log");
    let events = [
        json!({ "kind": "test.tick", "detail": { "n": 1 } }),
        json!({ "kind": "test.tick", "detail": { "n": 2 }, "content": { "x_digest": { "text": "a" } } }),
    ];
    let run = seal(&dir, &["--profile", "core"], &lines(&events));
    run.expect_code(0);
    let got = answers(&run);
    assert_eq!(got[0], json!({ "index": 0 }));
    assert_eq!(got[1]["refused"], "seal.content");
    assert!(got[1].get("recorded").is_none(), "the core profile has no events.dropped: {}", got[1]);
    assert_eq!(std::fs::read_to_string(dir.join("log.jsonl")).unwrap().lines().count(), 1);
}

#[test]
fn a_torn_tail_is_recovered_on_the_next_start() {
    let s = Scratch::new("seal-torn");
    let dir = init(&s, "log");
    seal(&dir, &[], &lines(&session())).expect_code(0);
    let log_path = dir.join("log.jsonl");
    let complete = std::fs::read(&log_path).unwrap().len();
    let mut file = std::fs::OpenOptions::new().append(true).open(&log_path).unwrap();
    file.write_all(b"{\"log_version\":\"0.1\",\"ind").unwrap();
    drop(file);
    // The torn log does not verify.
    assert!(verify(&dir).expect_code(3).stdout.contains("audit_log.torn_tail"));

    let run = seal(&dir, &[], "");
    run.expect_code(0);
    let log = std::fs::read_to_string(&log_path).unwrap();
    let last: Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    assert_eq!(last["kind"], "log.recovered");
    assert_eq!(last["detail"]["offset"], complete);
    assert_eq!(std::fs::read(dir.join(format!("log.jsonl.torn-{complete}"))).unwrap(), b"{\"log_version\":\"0.1\",\"ind");
    let v = verify(&dir);
    v.expect_code(0);
    assert!(v.stdout.contains("Recovered:    1 torn tail the writer moved aside"), "{}", v.transcript());
}

#[test]
fn a_log_recovered_event_from_the_input_is_refused() {
    // QA S4: only the writer writes log.recovered, when it moves a torn
    // tail aside; an event that names no moved bytes must not pass for one.
    let s = Scratch::new("seal-reserved");
    let dir = init(&s, "log");
    let event = json!({ "kind": "log.recovered", "detail": { "offset": 0, "length": 1, "sha256": HASH } });
    let run = seal(&dir, &[], &lines(&[event]));
    run.expect_code(0);
    let got = answers(&run);
    assert_eq!(got[0]["refused"], "seal.reserved_kind", "{}", run.transcript());
    assert_eq!(got[0]["recorded"], json!({ "kind": "events.dropped", "index": 0 }));
    assert!(!std::fs::read_to_string(dir.join("log.jsonl")).unwrap().contains("log.recovered"));
}

#[test]
fn a_restart_repeats_no_checkpoint() {
    // QA N4: the sealer takes the last checkpoint's size and time from the
    // history, so a start with nothing to add signs nothing.
    let s = Scratch::new("seal-restart");
    let dir = init(&s, "log");
    seal(&dir, &[], &lines(&session())).expect_code(0);
    let history = std::fs::read_to_string(dir.join("checkpoints.jsonl")).unwrap();
    seal(&dir, &[], "").expect_code(0);
    seal(&dir, &["--checkpoint-every", "5"], "").expect_code(0);
    assert_eq!(std::fs::read_to_string(dir.join("checkpoints.jsonl")).unwrap(), history);
}

#[test]
fn a_torn_checkpoint_history_is_moved_aside_and_continued() {
    // The history's torn last line is moved aside, as the log's is (QA S3,
    // N3: found from the file's end, never read whole), and the next
    // checkpoint follows the last complete one.
    let s = Scratch::new("seal-history-torn");
    let dir = init(&s, "log");
    seal(&dir, &[], &lines(&session())).expect_code(0);
    let history_path = dir.join("checkpoints.jsonl");
    let complete = std::fs::read(&history_path).unwrap().len();
    let mut file = std::fs::OpenOptions::new().append(true).open(&history_path).unwrap();
    file.write_all(b"{\"log_id\":\"urn:").unwrap();
    drop(file);
    seal(&dir, &[], &lines(&session()[..1])).expect_code(0);
    assert_eq!(std::fs::read(dir.join(format!("checkpoints.jsonl.torn-{complete}"))).unwrap(), b"{\"log_id\":\"urn:");
    let sizes: Vec<u64> = std::fs::read_to_string(&history_path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["tree_size"].as_u64().unwrap())
        .collect();
    assert_eq!(*sizes.last().unwrap(), 8);
    verify(&dir).expect_code(0);
}

#[test]
fn checkpoints_come_every_n_entries_and_after_each_session_end() {
    let s = Scratch::new("seal-cadence");
    let dir = init(&s, "log");
    let mut events = session(); // 7 entries, the last session.ended
    events.push(json!({ "kind": "policy.loaded", "detail": { "policy_hash": HASH } }));
    seal(&dir, &["--checkpoint-every", "3"], &lines(&events)).expect_code(0);
    let sizes: Vec<u64> = std::fs::read_to_string(dir.join("checkpoints.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["tree_size"].as_u64().unwrap())
        .collect();
    // 3 and 6 by count, 7 after session.ended, 8 at the input's end.
    assert_eq!(sizes, [3, 6, 7, 8]);
    let latest: Value = serde_json::from_slice(&std::fs::read(dir.join("checkpoint.json")).unwrap()).unwrap();
    assert_eq!(latest["tree_size"], 8);
    verify(&dir).expect_code(0);
}

#[test]
fn a_checkpoint_history_out_of_order_is_refused() {
    let s = Scratch::new("seal-history");
    let dir = init(&s, "log");
    seal(&dir, &["--checkpoint-every", "3"], &lines(&session())).expect_code(0);
    let history = std::fs::read_to_string(dir.join("checkpoints.jsonl")).unwrap();
    let mut reversed: Vec<&str> = history.lines().collect();
    reversed.reverse();
    std::fs::write(dir.join("checkpoints.jsonl"), reversed.join("\n") + "\n").unwrap();
    let v = verify(&dir);
    v.expect_code(3);
    assert!(v.stdout.starts_with("Audit log NOT verified: log_verify.checkpoints_out_of_order: "), "{}", v.transcript());
}

#[test]
fn a_second_seal_on_a_held_directory_is_refused() {
    let s = Scratch::new("seal-lock");
    let dir = init(&s, "log");
    let mut first = Command::new(vmr_path())
        .args(["log", "seal", "--dir", dir.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = first.stdin.take().unwrap();
    let mut stdout = BufReader::new(first.stdout.take().unwrap());
    writeln!(stdin, "{}", session()[0]).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "{\"index\":0}", "the first sealer holds the log once it answers");

    let second = seal(&dir, &[], "");
    second.expect_code(1);
    assert!(second.stderr.contains("is locked by another process"), "{}", second.transcript());

    // QA S2: while it holds the directory, the log is readable, on every
    // system: log verify reads it.
    let v = vmr(&["log", "verify", "--profile", "vmr.agent", "--log", dir.join("log.jsonl").to_str().unwrap()]);
    v.expect_code(0);

    drop(stdin);
    assert!(first.wait().unwrap().success());
    seal(&dir, &[], "").expect_code(0);
}

/// QA B2: a reader that holds checkpoint.json open without delete sharing
/// (as .NET, Python and many editors open a file on Windows) must not stop
/// the sealer. checkpoints.jsonl is the durable record; the latest file may
/// lag, and the sealer says so on standard error.
#[cfg(windows)]
#[test]
fn a_held_open_checkpoint_json_does_not_stop_the_sealer() {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 1;
    let s = Scratch::new("seal-held-checkpoint");
    let dir = init(&s, "log");
    seal(&dir, &[], &lines(&session())).expect_code(0);
    let before = std::fs::read(dir.join("checkpoint.json")).unwrap();
    let held = std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(dir.join("checkpoint.json")).unwrap();

    let run = seal(&dir, &[], &lines(&session()));
    run.expect_code(0);
    assert_eq!(answers(&run), (7..14).map(|i| json!({ "index": i })).collect::<Vec<_>>(), "{}", run.transcript());
    assert!(run.stderr.contains("checkpoints.jsonl holds it"), "{}", run.transcript());
    drop(held);
    assert_eq!(std::fs::read(dir.join("checkpoint.json")).unwrap(), before, "the latest file lags");
    let history = std::fs::read_to_string(dir.join("checkpoints.jsonl")).unwrap();
    let last: Value = serde_json::from_str(history.lines().last().unwrap()).unwrap();
    assert_eq!(last["tree_size"], 14);
    verify(&dir).expect_code(0);
    // The next run replaces it.
    seal(&dir, &[], &lines(&session()[..1])).expect_code(0);
    let latest: Value = serde_json::from_slice(&std::fs::read(dir.join("checkpoint.json")).unwrap()).unwrap();
    assert_eq!(latest["tree_size"], 15);
}

#[test]
fn init_refuses_a_directory_that_is_not_empty() {
    let s = Scratch::new("seal-init");
    let dir = s.subdir("taken");
    std::fs::write(dir.join("notes.txt"), "mine").unwrap();
    let run = vmr(&["log", "init", "--dir", dir.to_str().unwrap()]);
    run.expect_code(1);
    assert!(run.stderr.contains("is not empty; nothing was written"), "{}", run.transcript());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    // A second init of a directory init made is refused too: one log, one key.
    let dir = init(&s, "log");
    vmr(&["log", "init", "--dir", dir.to_str().unwrap()]).expect_code(1);
}

#[test]
fn disclose_and_check_item_agree_and_a_changed_byte_does_not() {
    let s = Scratch::new("seal-disclose");
    let dir = init(&s, "log");
    seal(&dir, &[], &lines(&session())).expect_code(0);
    let log = dir.join("log.jsonl").to_string_lossy().into_owned();
    let dir_arg = dir.to_string_lossy().into_owned();

    let d = vmr(&["log", "disclose", "--dir", &dir_arg, "--index", "3", "--member", "arguments_digest"]);
    d.expect_code(0);
    let item_key = d.stdout.trim().to_string();
    assert_eq!(item_key.len(), 64, "{}", d.transcript());

    let check = |content: &str| {
        vmr(&["log", "check-item", "--log", &log, "--index", "3", "--member", "arguments_digest", "--item-key", &item_key, "--content-text", content])
    };
    let ok = check("{\"city\": \"Oslo\"}");
    ok.expect_code(0);
    assert!(ok.stdout.starts_with("Item matches: entry 3's arguments_digest"), "{}", ok.transcript());
    assert!(ok.stdout.contains("Not checked:  whether a signed checkpoint covers entry 3"), "{}", ok.transcript());
    let changed = check("{\"city\": \"Oslp\"}");
    changed.expect_code(3);
    assert!(changed.stdout.starts_with("Item does NOT match"), "{}", changed.transcript());

    // The JSON form: the canonical form of the value, whatever its spacing.
    let json_file = s.write("result.json", "{ \"temp_c\" : 7 }");
    let d = vmr(&["log", "disclose", "--dir", &dir_arg, "--index", "5", "--member", "result_digest"]);
    let key5 = d.stdout.trim().to_string();
    vmr(&["log", "check-item", "--log", &log, "--index", "5", "--member", "result_digest", "--item-key", &key5, "--content-json", &json_file])
        .expect_code(0);
    // An item key opens its one digest only.
    vmr(&["log", "check-item", "--log", &log, "--index", "5", "--member", "result_digest", "--item-key", &item_key, "--content-json", &json_file])
        .expect_code(3);

    // A member the entry does not carry, or not in a session, is refused.
    vmr(&["log", "disclose", "--dir", &dir_arg, "--index", "4", "--member", "arguments_digest"]).expect_code(1);
    vmr(&["log", "disclose", "--dir", &dir_arg, "--index", "3", "--member", "tool"]).expect_code(1);
}

#[test]
fn the_audit_key_and_the_content_secret_stay_in_their_own_files() {
    let s = Scratch::new("seal-secrets");
    let dir = s.path("log");
    let dir_arg = dir.to_string_lossy().into_owned();
    let mut printed = String::new();
    let init = vmr(&["log", "init", "--dir", &dir_arg]);
    init.expect_code(0);
    printed.push_str(&init.stdout);
    printed.push_str(&init.stderr);
    for name in ["audit-key.pem", "audit-key.pub.json", "content-secret", "log.jsonl"] {
        assert!(init.stdout.contains(name), "init names {name}:\n{}", init.transcript());
    }
    let run = seal(&dir, &["--checkpoint-every", "2"], &lines(&session()));
    run.expect_code(0);
    printed.push_str(&run.stdout);
    printed.push_str(&run.stderr);
    let d = vmr(&["log", "disclose", "--dir", &dir_arg, "--index", "3", "--member", "arguments_digest"]);
    printed.push_str(&d.stdout);
    printed.push_str(&d.stderr);

    let secret = std::fs::read_to_string(dir.join("content-secret")).unwrap();
    let secret = secret.trim_end();
    assert_eq!(secret.len(), 64);
    let pem = std::fs::read_to_string(dir.join("audit-key.pem")).unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let scalar = {
        use p256::pkcs8::DecodePrivateKey;
        let key = p256::ecdsa::SigningKey::from_pkcs8_pem(&pem).unwrap();
        key.to_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let needles = [secret.to_string(), body, scalar];
    for needle in &needles {
        assert!(!printed.contains(needle.as_str()), "a secret was printed");
    }
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
        for (i, needle) in needles.iter().enumerate() {
            let own = (i == 0 && name == "content-secret") || (i > 0 && name == "audit-key.pem");
            assert!(own || !text.contains(needle.as_str()), "{name} holds a secret");
        }
    }
}

#[test]
#[allow(clippy::disallowed_methods)] // times the run: a measurement, not a result
#[ignore = "release-mode timing: cargo test --release -p vmr-cli --test cli_log_seal -- --ignored --nocapture"]
fn seal_100_000_events() {
    let s = Scratch::new("seal-scale");
    let dir = init(&s, "log");
    let event = json!({ "kind": "call.proposed", "detail": { "session_id": SESSION, "call": 0, "turn": 0, "tool": "t" }, "content": { "arguments_digest": { "text": "{\"a\": 1}" } } });
    let input = format!("{event}\n").repeat(100_000);
    let start = std::time::Instant::now();
    let run = seal(&dir, &[], &input);
    let took = start.elapsed();
    run.expect_code(0);
    assert_eq!(run.stdout.lines().count(), 100_000);
    println!("sealed 100000 events in {:.1} s ({:.0} events/s)", took.as_secs_f64(), 100_000.0 / took.as_secs_f64());
    verify(&dir).expect_code(0);
}

#[test]
fn the_committed_agent_log_example_verifies_and_its_disclosure_checks() {
    // docs/examples/agent-log/: written by seal_session.py, another runtime
    // driving `vmr log seal` through a pipe. Its README shows these two
    // commands; the item key and the content are the README's.
    let dir = repo().join("docs/examples/agent-log");
    let arg = |name: &str| dir.join(name).to_string_lossy().into_owned();
    let v = vmr(&[
        "log", "verify", "--profile", "vmr.agent", "--log", &arg("log.jsonl"), "--audit-key", &arg("audit-key.pub.json"),
        "--checkpoint", &arg("checkpoint.json"),
    ]);
    v.expect_code(0);
    assert!(
        v.stdout.starts_with("Audit log verified: 14 entries; 1 checkpoint signed by the pinned audit key covers entries 0 to 13"),
        "{}",
        v.transcript()
    );
    assert!(v.stdout.contains("Calls:        2 proposed; 1 refused: 1 by guard"), "{}", v.transcript());
    assert!(v.stdout.contains("Approvals:    1 granted, 0 denied, 0 timed out"), "{}", v.transcript());
    let check = |content: &str| {
        vmr(&[
            "log", "check-item", "--log", &arg("log.jsonl"), "--index", "4", "--member", "arguments_digest", "--item-key",
            "11200c6264981efb8fbbdcd4e3ce185d1db9dcda617e774843dff5c578b0cd3d", "--content-text", content,
        ])
    };
    check("{\"city\": \"Oslo\", \"day\": \"tomorrow\"}").expect_code(0);
    check("{\"city\": \"Oslo\", \"day\": \"tomorrov\"}").expect_code(3);
    // QA N2: the README's command that works in every shell, Windows
    // PowerShell 5.1 included (it passes embedded quotes to a program
    // differently), reads the content from arguments.txt, which holds exactly
    // the disclosed bytes.
    let readme = std::fs::read_to_string(dir.join("README.md")).unwrap();
    assert!(readme.contains("--content-file arguments.txt"), "the README gives the --content-file command");
    assert_eq!(std::fs::read(dir.join("arguments.txt")).unwrap(), b"{\"city\": \"Oslo\", \"day\": \"tomorrow\"}");
    vmr(&[
        "log", "check-item", "--log", &arg("log.jsonl"), "--index", "4", "--member", "arguments_digest", "--item-key",
        "11200c6264981efb8fbbdcd4e3ce185d1db9dcda617e774843dff5c578b0cd3d", "--content-file", &arg("arguments.txt"),
    ])
    .expect_code(0);
    // The directory holds no private key and no content secret.
    for entry in std::fs::read_dir(&dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(
            ["README.md", "seal_session.py", "log.jsonl", "checkpoint.json", "audit-key.pub.json", "arguments.txt"].contains(&name.as_str()),
            "{name}"
        );
    }
}
