// tests/agent_profile.rs — the vmr.agent profile's keyed digests and its notes
// (specs/audit-profile-agent-v0.1.md §3, §4.6). The checks themselves are
// held by the vectors (agent_vectors.rs).

use serde_json::{json, Value};
use vmr_audit_log::log::LogBuilder;
use vmr_audit_log::profile::EntryProfile;
use vmr_audit_log::profiles::vmr_agent::digest::{is_digest, label, ContentSecret, ItemKey, SessionKey};
use vmr_audit_log::profiles::vmr_agent::notes::{NoteKind, Notes};
use vmr_audit_log::profiles::vmr_agent::{NAME, PROFILE};
use vmr_audit_log::vmr_record::hash::{format_hash, sha256};
use vmr_audit_log::vmr_record::timestamp::Timestamp;

const S: &str = "urn:uuid:0f3c6a2e-8d4b-4c1e-9a7f-2b5d8e1c4a90";
const T: &str = "urn:uuid:7b1e2d3c-4a5f-4e6d-8c7b-9a0f1e2d3c4b";

#[test]
fn the_profile_is_named_as_the_spec_names_it() {
    assert_eq!(NAME, "vmr.agent");
    assert_eq!(PROFILE.name(), "vmr.agent");
}

#[test]
fn no_key_shows_its_bytes_in_debug_output() {
    let secret = ContentSecret::from_bytes([0xab; 32]);
    let session = secret.session_key(S);
    let item = session.item_key("call.proposed", "arguments_digest", 1043);
    for shown in [format!("{secret:?}"), format!("{session:?}"), format!("{item:?}")] {
        assert!(!shown.contains("ab") && !shown.contains("171"), "{shown}");
        assert!(shown.ends_with("(..)"), "{shown}");
    }
    // A key given out is the same key taken back.
    let again = ItemKey::from_bytes(*item.as_bytes());
    assert_eq!(again.digest(b"x"), item.digest(b"x"));
    let again = SessionKey::from_bytes(*session.as_bytes());
    assert_eq!(again.item_key("a.b", "c", 0).as_bytes(), session.item_key("a.b", "c", 0).as_bytes());
}

#[test]
fn a_person_is_an_identifier_a_host_supplies_never_an_address_or_a_name() {
    // §2's person: ^[A-Za-z0-9_.:|+=/-]{1,128}$. The identifiers identity
    // providers issue are admitted (a `|`-separated subject, a base64 id);
    // an address (`@`) and a name (a space) are not.
    use vmr_audit_log::profiles::vmr_agent::MemberType;
    let longest = "a".repeat(128);
    let over = "a".repeat(129);
    for ok in ["staff:4411", "acct.7f3e", "google-oauth2|103547991597142817347", "auth0|5f7c8ec7c33c6c004bbafe82", "dGVzdA+/aWQ=", &longest] {
        assert!(MemberType::Person.accepts(&json!(ok)), "{ok}");
    }
    for bad in ["", "ana@example.com", "auth0|ana@example.com", "Ana Lopez", "staff\u{1}", "staff\u{e9}", &over] {
        assert!(!MemberType::Person.accepts(&json!(bad)), "{bad:?}");
    }
}

#[test]
fn labels_and_digests_have_the_spec_s_form() {
    assert_eq!(label("call.proposed", "arguments_digest", 1043), "call.proposed/arguments_digest/1043");
    assert_eq!(label("tool.registered", "tool_digest", 0), "tool.registered/tool_digest/0");
    let digest = ContentSecret::from_bytes(sha256(b"k")).session_key(S).item_key("a.b", "c", 1).digest(b"yes");
    assert!(is_digest(&digest), "{digest}");
    // Every part of the derivation changes the digest.
    let secret = ContentSecret::from_bytes(sha256(b"k"));
    let others = [
        ContentSecret::from_bytes(sha256(b"other")).session_key(S).item_key("a.b", "c", 1).digest(b"yes"),
        secret.session_key(T).item_key("a.b", "c", 1).digest(b"yes"),
        secret.session_key(S).item_key("a.x", "c", 1).digest(b"yes"),
        secret.session_key(S).item_key("a.b", "x", 1).digest(b"yes"),
        secret.session_key(S).item_key("a.b", "c", 10).digest(b"yes"),
        secret.session_key(S).item_key("a.b", "c", 1).digest(b"no"),
    ];
    for other in others {
        assert_ne!(other, digest);
    }
    for bad in ["hmac-sha256:", "sha256:".to_string().as_str(), &digest.to_uppercase(), &digest[..digest.len() - 1]] {
        assert!(!is_digest(bad), "{bad}");
    }
}

/// A log of the profile, built entry by entry (each checked by the profile).
struct Log {
    builder: LogBuilder,
    notes: Notes,
}

impl Log {
    fn new(notes: Notes) -> Log {
        Log { builder: LogBuilder::new(format_hash(&sha256(b"not a key id: unused"))), notes }
    }

    fn add(&mut self, kind: &str, detail: Value) {
        let entry = self
            .builder
            .append(Timestamp::parse("2026-09-30T09:00:00Z").unwrap(), kind, detail, &PROFILE)
            .unwrap_or_else(|e| panic!("{kind}: {e}"));
        self.notes.observe(&entry);
    }
}

fn digest(what: &str) -> String {
    ContentSecret::from_bytes(sha256(b"notes")).session_key(S).item_key("a.b", "c", 0).digest(what.as_bytes())
}

fn proposed(call: u64, tool: &str) -> Value {
    json!({ "session_id": S, "call": call, "turn": 0, "tool": tool, "arguments_digest": digest("args") })
}

#[test]
fn the_notes_report_where_the_entries_break_the_rules_between_entries() {
    let mut log = Log::new(Notes::new());
    log.add("session.started", json!({ "session_id": S, "runtime": "r 1", "model": "m", "configuration_hash": format_hash(&sha256(b"c")) }));
    log.add("tool.registered", json!({ "session_id": S, "tool": "search_web", "provider": "p1" }));
    // entries 2-4: a call that reaches a registered tool and runs: no note.
    log.add("call.proposed", proposed(0, "search_web"));
    log.add("gate.decided", json!({ "session_id": S, "call": 0, "gate": "dispatch", "decision": "permitted" }));
    log.add("call.executed", json!({ "session_id": S, "call": 0, "outcome": "ok" }));
    // 5: a tool the session never registered, in clear.
    log.add("call.proposed", proposed(1, "delete_files"));
    // 6-8: refused by policy; then something of the call after its refusal.
    log.add("gate.decided", json!({ "session_id": S, "call": 1, "gate": "policy", "decision": "refused", "refusal": "policy.forbidden" }));
    log.add("call.refused", json!({ "session_id": S, "call": 1, "gate": "policy", "refusal": "policy.forbidden" }));
    log.add("call.executed", json!({ "session_id": S, "call": 1, "outcome": "ok" }));
    // 9: a call never proposed.
    log.add("gate.decided", json!({ "session_id": S, "call": 2, "gate": "dispatch", "decision": "permitted" }));
    // 10-11: unregistering under another provider leaves the tool reachable;
    // 12-13: under its own, it does not.
    log.add("tool.unregistered", json!({ "session_id": S, "tool": "search_web", "provider": "p2" }));
    log.add("call.proposed", proposed(3, "search_web"));
    log.add("tool.unregistered", json!({ "session_id": S, "tool": "search_web", "provider": "p1" }));
    log.add("call.proposed", proposed(4, "search_web"));
    // 14-16: registered again; the approval gate without an answer.
    log.add("tool.registered", json!({ "session_id": S, "tool": "search_web", "provider": "p1" }));
    log.add("call.proposed", proposed(5, "search_web"));
    log.add("gate.decided", json!({ "session_id": S, "call": 5, "gate": "approval", "decision": "permitted" }));
    // 17-19: requested, granted for the tool, then the gate: no note.
    log.add("approval.requested", json!({ "session_id": S, "call": 5 }));
    log.add("approval.granted", json!({ "session_id": S, "call": 5, "approver": "staff:1", "latency_ms": 900, "scope": "tool" }));
    log.add("gate.decided", json!({ "session_id": S, "call": 5, "gate": "approval", "decision": "permitted" }));
    // 20-21: a later call of that tool, covered by the standing approval.
    log.add("call.proposed", proposed(6, "search_web"));
    log.add("gate.decided", json!({ "session_id": S, "call": 6, "gate": "approval", "decision": "permitted" }));
    // 22-23: a call of another tool is not covered.
    log.add("call.proposed", json!({ "session_id": S, "call": 7, "turn": 1, "tool_digest": digest("other"), "arguments_digest": digest("args") }));
    log.add("gate.decided", json!({ "session_id": S, "call": 7, "gate": "approval", "decision": "refused", "refusal": "approval.denied" }));
    // 24-26: the other answers, counted; the last of a call never proposed.
    log.add("approval.denied", json!({ "session_id": S, "call": 7, "approver": "staff:1", "latency_ms": 10 }));
    log.add("call.refused", json!({ "session_id": S, "call": 7, "gate": "approval", "refusal": "approval.denied" }));
    log.add("approval.timed_out", json!({ "session_id": S, "call": 8, "waited_ms": 60000 }));
    // 27-29: another session, whose standing approval covers all its calls;
    // loss recorded.
    log.add("approval.granted", json!({ "session_id": T, "call": 0, "approver": "staff:2", "latency_ms": 1, "scope": "session" }));
    log.add("gate.decided", json!({ "session_id": T, "call": 1, "gate": "approval", "decision": "permitted" }));
    log.add("events.dropped", json!({ "count": 3 }));

    let found: Vec<(u64, NoteKind)> = log.notes.notes().iter().map(|n| (n.index, n.kind)).collect();
    assert_eq!(
        found,
        vec![
            (5, NoteKind::UnreachableTool),
            (8, NoteKind::AfterRefusal),
            (9, NoteKind::NotProposed),
            (13, NoteKind::UnreachableTool),
            (16, NoteKind::UnansweredApproval),
            (23, NoteKind::UnansweredApproval),
            (26, NoteKind::NotProposed),
            (27, NoteKind::NotProposed),
            (28, NoteKind::NotProposed),
        ],
        "{:#?}",
        log.notes.notes()
    );
    assert_eq!(log.notes.total(), 9);
    let unreachable = &log.notes.notes()[0];
    assert_eq!((unreachable.session_id.as_str(), unreachable.call), (S, Some(1)));
    // The note names the entry and the call, never the name: it may be
    // model output written in clear.
    assert!(unreachable.message.starts_with(&format!("entry 5: session {S}: call 1 proposes, as tool, a name the session could not reach")), "{}", unreachable.message);
    assert!(!unreachable.message.contains("delete_files"), "{}", unreachable.message);
    assert!(unreachable.message.contains("model output written in clear"), "{}", unreachable.message);

    let summary = log.notes.summary();
    assert_eq!(summary.sessions, 2);
    assert_eq!(summary.calls, 7);
    assert_eq!(summary.calls_refused(), 2);
    assert_eq!(summary.refused_by_gate.get("policy"), Some(&1));
    assert_eq!(summary.refused_by_gate.get("approval"), Some(&1));
    assert_eq!((summary.approvals_granted, summary.approvals_denied, summary.approvals_timed_out), (2, 1, 1));
    assert_eq!((summary.events_dropped, summary.recoveries), (3, 0));
}

#[test]
fn the_notes_kept_are_bounded_and_all_are_counted() {
    let mut log = Log::new(Notes::with_limit(2));
    for call in 0..5 {
        log.add("call.executed", json!({ "session_id": S, "call": call, "outcome": "ok" }));
    }
    assert_eq!(log.notes.notes().len(), 2);
    assert_eq!(log.notes.total(), 5);
}

#[test]
fn the_notes_report_a_call_proposed_twice_an_answer_the_gate_contradicts_and_an_entry_after_the_end() {
    let mut log = Log::new(Notes::new());
    log.add("session.started", json!({ "session_id": S, "runtime": "r 1", "model": "m", "configuration_hash": format_hash(&sha256(b"c")) }));
    log.add("tool.registered", json!({ "session_id": S, "tool": "search_web" }));
    // 2-3: call 0 proposed twice: noted, counted once.
    log.add("call.proposed", proposed(0, "search_web"));
    log.add("call.proposed", proposed(0, "search_web"));
    // 4-6: denied, then the approval gate permits.
    log.add("approval.requested", json!({ "session_id": S, "call": 0 }));
    log.add("approval.denied", json!({ "session_id": S, "call": 0, "approver": "staff:1", "latency_ms": 10 }));
    log.add("gate.decided", json!({ "session_id": S, "call": 0, "gate": "approval", "decision": "permitted" }));
    // 7-9: timed out, then the gate refuses with another refusal.
    log.add("call.proposed", proposed(1, "search_web"));
    log.add("approval.timed_out", json!({ "session_id": S, "call": 1, "waited_ms": 60000 }));
    log.add("gate.decided", json!({ "session_id": S, "call": 1, "gate": "approval", "decision": "refused", "refusal": "approval.denied" }));
    // 10-12: granted, then the gate refuses.
    log.add("call.proposed", proposed(2, "search_web"));
    log.add("approval.granted", json!({ "session_id": S, "call": 2, "approver": "staff:1", "latency_ms": 10 }));
    log.add("gate.decided", json!({ "session_id": S, "call": 2, "gate": "approval", "decision": "refused", "refusal": "approval.denied" }));
    // 13-16: denied and refused as §4.4 says, then timed out and refused
    // with its own refusal: no note.
    log.add("call.proposed", proposed(3, "search_web"));
    log.add("approval.denied", json!({ "session_id": S, "call": 3, "approver": "staff:1", "latency_ms": 10 }));
    log.add("gate.decided", json!({ "session_id": S, "call": 3, "gate": "approval", "decision": "refused", "refusal": "approval.denied" }));
    log.add("call.refused", json!({ "session_id": S, "call": 3, "gate": "approval", "refusal": "approval.denied" }));
    log.add("call.proposed", proposed(4, "search_web"));
    log.add("approval.timed_out", json!({ "session_id": S, "call": 4, "waited_ms": 60000 }));
    log.add("gate.decided", json!({ "session_id": S, "call": 4, "gate": "approval", "decision": "refused", "refusal": "approval.timed_out" }));
    // 20-22: the session ends; a later entry of it is noted, and not counted.
    log.add("session.ended", json!({ "session_id": S, "outcome": "completed" }));
    log.add("call.proposed", proposed(5, "search_web"));
    log.add("session.ended", json!({ "session_id": S, "outcome": "completed" }));

    let found: Vec<(u64, NoteKind)> = log.notes.notes().iter().map(|n| (n.index, n.kind)).collect();
    assert_eq!(
        found,
        vec![
            (3, NoteKind::ProposedTwice),
            (6, NoteKind::ApprovalAgainstAnswer),
            (9, NoteKind::ApprovalAgainstAnswer),
            (12, NoteKind::ApprovalAgainstAnswer),
            (21, NoteKind::AfterSessionEnded),
            (22, NoteKind::AfterSessionEnded),
        ],
        "{:#?}",
        log.notes.notes()
    );
    let summary = log.notes.summary();
    assert_eq!((summary.sessions, summary.calls, summary.calls_refused()), (1, 5, 1));
    assert_eq!((summary.approvals_granted, summary.approvals_denied, summary.approvals_timed_out), (1, 2, 2));
    assert_eq!(log.notes.untracked_from(), None);
}

#[test]
fn the_notes_pass_forgets_an_ended_session_and_stops_past_its_caps() {
    let started = |id: &str| json!({ "session_id": id, "runtime": "r 1", "model": "m", "configuration_hash": format_hash(&sha256(b"c")) });
    let ended = |id: &str| json!({ "session_id": id, "outcome": "completed" });
    let call = |id: &str, n: u64| json!({ "session_id": id, "call": n, "turn": 0, "tool_digest": digest("t"), "arguments_digest": digest("args") });

    // At most 2 sessions tracked, 3 calls and tools held.
    let mut log = Log::new(Notes::with_bounds(100, 2, 3));
    // 0-4: session S holds a tool and two calls, then ends: its state is
    // dropped, so session T can hold three.
    log.add("session.started", started(S));
    log.add("tool.registered", json!({ "session_id": S, "tool": "search_web" }));
    log.add("call.proposed", call(S, 0));
    log.add("call.proposed", call(S, 1));
    log.add("session.ended", ended(S));
    // 5-8: session T holds three calls: at the cap, not past it.
    log.add("session.started", started(T));
    for n in 0..3 {
        log.add("call.proposed", call(T, n));
    }
    assert_eq!(log.notes.untracked_from(), None);
    // 9: a fourth call passes the cap: the entry is read, the next is not.
    log.add("call.proposed", call(T, 3));
    assert_eq!(log.notes.untracked_from(), Some(10));
    // 10-11: not tracked: no note (a call never proposed), no count; lost
    // events are still counted.
    log.add("call.executed", json!({ "session_id": T, "call": 99, "outcome": "ok" }));
    log.add("events.dropped", json!({ "count": 2 }));
    assert_eq!(log.notes.total(), 0, "{:#?}", log.notes.notes());
    let summary = log.notes.summary();
    assert_eq!((summary.sessions, summary.calls, summary.events_dropped), (2, 6, 2));

    // The session cap: a third session passes it.
    let mut log = Log::new(Notes::with_bounds(100, 2, 100));
    let third = "urn:uuid:3c2b1a09-8f7e-4d6c-9b5a-493827160504";
    log.add("session.started", started(S));
    log.add("session.started", started(T));
    assert_eq!(log.notes.untracked_from(), None);
    log.add("session.started", started(third));
    assert_eq!(log.notes.untracked_from(), Some(3));
}

#[test]
fn refusals_are_counted_under_a_bounded_number_of_gate_names() {
    use vmr_audit_log::profiles::vmr_agent::notes::MAX_GATES_COUNTED;
    let mut log = Log::new(Notes::new());
    let gates = MAX_GATES_COUNTED as u64 + 3;
    for n in 0..gates {
        let gate = format!("gate_{}{}", char::from(b'a' + (n % 26) as u8), "x".repeat((n / 26) as usize + 1));
        log.add("call.proposed", json!({ "session_id": S, "call": n, "turn": 0, "tool_digest": digest("t"), "arguments_digest": digest("args") }));
        log.add("call.refused", json!({ "session_id": S, "call": n, "gate": gate, "refusal": "policy.forbidden" }));
    }
    let summary = log.notes.summary();
    assert_eq!(summary.refused_by_gate.len(), MAX_GATES_COUNTED);
    assert_eq!(summary.refused_by_other_gates, 3);
    assert_eq!(summary.calls_refused(), gates);
}
