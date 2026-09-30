// tests/agent_generate/mod.rs — the vmr.agent profile's vector generator
// (specs/audit-profile-agent-v0.1.md §6).
//
// It writes specs/test-vectors/audit-profile-agent/cases.json: entry cases,
// each read on its own under the profile, whose expected result is declared
// BY HAND here, and digest cases whose expected keys and digests are
// declared by hand too: they were computed once with Python's own hmac and
// hashlib (an implementation that shares nothing with this crate), and the
// generator refuses to write a digest this build computes differently.
//
//   VMR_WRITE_VECTORS=1 cargo test -p vmr-audit-log --test agent_vectors -- --ignored

use serde_json::{json, Value};
use vmr_audit_log::profiles::vmr_agent::digest::{json_content, label, ContentSecret};
use vmr_audit_log::vmr_record::canonical::jcs;
use vmr_audit_log::vmr_record::hash::{format_hash, sha256};
use vmr_audit_log::vmr_record::merkle::empty_root;

/// The label the vectors' content secret is derived from: the secret is
/// `sha256(label)`, as the audit-log vectors derive their keys (tests only).
pub const SECRET_LABEL: &str = "vmr.agent vectors: content secret (test-only)";

/// The session every entry case and most digest cases name.
pub const SESSION: &str = "urn:uuid:0f3c6a2e-8d4b-4c1e-9a7f-2b5d8e1c4a90";
/// Another session: the parent of a sub-agent, and a second digest session.
pub const OTHER_SESSION: &str = "urn:uuid:7b1e2d3c-4a5f-4e6d-8c7b-9a0f1e2d3c4b";

/// The vectors' content secret.
pub fn secret() -> ContentSecret {
    ContentSecret::from_bytes(sha256(SECRET_LABEL.as_bytes()))
}

/// The relative path (under specs/test-vectors/) and the bytes of every file
/// this generator owns.
pub fn generate() -> Vec<(String, String)> {
    let mut text = serde_json::to_string_pretty(&build()).unwrap();
    text.push('\n');
    vec![("audit-profile-agent/cases.json".to_string(), text)]
}

/// One entry line: index 0 of a log of one entry, so a reader reads it as a
/// whole log (core §4.4) and the profile's checks are what decide it.
pub fn line(kind: &str, detail: Value) -> String {
    jcs(&json!({
        "log_version": "0.1",
        "index": 0,
        "previous_root": format_hash(&empty_root()),
        "recorded_at": "2026-09-30T09:00:00Z",
        "kind": kind,
        "detail": detail,
    }))
}

/// A digest of `content` for `kind`/`member` at index 0 of SESSION: a real
/// keyed digest (§3), so each case holds what a writer would write.
fn d(kind: &str, member: &str, content: &[u8]) -> String {
    secret().session_key(SESSION).item_key(kind, member, 0).digest(content)
}

/// A hash of `what`.
fn h(what: &str) -> String {
    format_hash(&sha256(what.as_bytes()))
}

fn accept(id: &str, description: &str, kind: &str, detail: Value) -> Value {
    json!({ "id": id, "description": description, "raw": line(kind, detail), "expect": "accept" })
}

/// A refused case: `rule` is the §4.6 rule it breaks.
fn refuse(id: &str, rule: u64, description: &str, kind: &str, detail: Value) -> Value {
    json!({ "id": id, "description": description, "rule": rule, "raw": line(kind, detail), "expect": "audit_entry.structure" })
}

fn build() -> Value {
    json!({
        "vector_version": "0.1",
        "profile": "vmr.agent",
        "note": "VMR audit log profile vmr.agent v0.1 vectors (specs/audit-profile-agent-v0.1.md). Each entry case is one line, read as a log of one entry under the vmr.agent profile: accepted, or refused with audit_entry.structure (rule names the section 4.6 check it breaks). Each digest case gives a content secret derived from a fixed label (sha256 of it, tests only), a session, a kind, a member, an index and the content, with the session key, item key and digest section 3 gives. Every expected result was declared by hand; the digests were computed once with an independent implementation. Regenerate with VMR_WRITE_VECTORS=1 cargo test -p vmr-audit-log --test agent_vectors -- --ignored.",
        "entries": entry_cases(),
        "digests": digest_cases(),
    })
}

fn entry_cases() -> Value {
    let s = SESSION;
    let args = d("call.proposed", "arguments_digest", br#"{"query":"weather in Lisbon"}"#);
    let started = json!({
        "session_id": s,
        "runtime": "example-runtime 2.3.1",
        "model": "example-model-7b-instruct",
        "configuration_hash": h("generation settings"),
    });
    let proposed = json!({ "session_id": s, "call": 0, "turn": 0, "tool": "search_web", "arguments_digest": args });
    let with = |base: &Value, member: &str, value: Value| {
        let mut v = base.clone();
        v[member] = value;
        v
    };
    let without = |base: &Value, member: &str| {
        let mut v = base.clone();
        v.as_object_mut().unwrap().remove(member);
        v
    };
    let accented_256 = "é".repeat(128); // 128 characters, 256 bytes
    let accented_258 = "é".repeat(129); // 129 characters, 258 bytes

    let cases = vec![
        // ---- one accepting case for every kind (§4), and the optional members ----
        accept("agent-session-started", "session.started with its required members", "session.started", started.clone()),
        accept("agent-session-started-full", "session.started with every optional member: a sub-agent session with the largest u64 seed", "session.started", json!({
            "session_id": s,
            "runtime": "example-runtime 2.3.1",
            "model": "example-model-7b-instruct",
            "model_hash": h("model state"),
            "record_id": "urn:uuid:22222222-2222-4222-8222-222222222222",
            "configuration_hash": h("generation settings"),
            "seed": "18446744073709551615",
            "parent_session_id": OTHER_SESSION,
            "parent_call": 4,
        })),
        accept("agent-session-started-text-at-limit", "runtime of 128 two-byte characters: 256 bytes, the limit", "session.started", with(&started, "runtime", json!(accented_256))),
        accept("agent-session-ended", "session.ended, completed", "session.ended", json!({ "session_id": s, "outcome": "completed" })),
        accept("agent-session-ended-stopped", "session.ended, stopped by a person named by a pseudonymous id", "session.ended", json!({ "session_id": s, "outcome": "stopped", "stopped_by": "staff:4411" })),
        accept("agent-session-ended-stopped-anonymous", "session.ended, stopped, with no stopped_by: only its presence without \"stopped\" is refused", "session.ended", json!({ "session_id": s, "outcome": "stopped" })),
        accept("agent-policy-loaded", "policy.loaded for every session: no session_id", "policy.loaded", json!({ "policy_hash": h("policy document") })),
        accept("agent-policy-loaded-session", "policy.loaded for one session", "policy.loaded", json!({ "session_id": s, "policy_hash": h("policy document") })),
        accept("agent-policy-refused", "policy.refused with a writer's own refusal id", "policy.refused", json!({ "policy_hash": h("policy document"), "refusal": "policy.bad_signature", "detail": "the policy's signature does not verify" })),
        accept("agent-policy-refused-session", "policy.refused inside one session", "policy.refused", json!({ "session_id": s, "refusal": "policy.forbidden", "detail": "the policy forbids the tool" })),
        accept("agent-tool-registered", "tool.registered by name, with its provider and its schema's digest", "tool.registered", json!({ "session_id": s, "tool": "search_web", "provider": "mcp:web-tools", "schema_digest": d("tool.registered", "schema_digest", b"{}") })),
        accept("agent-tool-registered-digest", "tool.registered as a digest: its name is not a name", "tool.registered", json!({ "session_id": s, "tool_digest": d("tool.registered", "tool_digest", b"send payment") })),
        accept("agent-tool-unregistered", "tool.unregistered by name and provider", "tool.unregistered", json!({ "session_id": s, "tool": "search_web", "provider": "mcp:web-tools" })),
        accept("agent-turn-started", "turn.started with every optional member: a turn routed to another model", "turn.started", json!({
            "session_id": s,
            "turn": 0,
            "input_digest": d("turn.started", "input_digest", b"what is the weather in Lisbon?"),
            "grammar_digest": d("turn.started", "grammar_digest", b"root ::= call"),
            "model": "example-model-70b",
            "model_hash": h("another model state"),
        })),
        accept("agent-call-proposed", "call.proposed naming a tool the session could reach", "call.proposed", proposed.clone()),
        accept("agent-call-proposed-digest", "call.proposed naming another tool: model output, written as a digest", "call.proposed", json!({ "session_id": s, "call": 1, "turn": 0, "tool_digest": d("call.proposed", "tool_digest", b"delete_all_files"), "arguments_digest": args })),
        accept("agent-gate-decided-permitted", "gate.decided, permitted by the dispatch gate", "gate.decided", json!({ "session_id": s, "call": 0, "gate": "dispatch", "decision": "permitted" })),
        accept("agent-gate-decided-refused", "gate.decided, refused by the policy gate with a registered refusal", "gate.decided", json!({ "session_id": s, "call": 0, "gate": "policy", "decision": "refused", "refusal": "policy.forbidden" })),
        accept("agent-gate-decided-writer-gate", "gate.decided of a gate the profile does not register: the writer's own", "gate.decided", json!({ "session_id": s, "call": 0, "gate": "rate_limit", "decision": "refused", "refusal": "rate_limit.exceeded" })),
        accept("agent-call-executed", "call.executed, ok, with its result's digest", "call.executed", json!({ "session_id": s, "call": 0, "outcome": "ok", "result_digest": d("call.executed", "result_digest", b"18 C, clear") })),
        accept("agent-call-executed-error", "call.executed, error, with no result", "call.executed", json!({ "session_id": s, "call": 0, "outcome": "error" })),
        accept("agent-call-refused", "call.refused by the approval gate", "call.refused", json!({ "session_id": s, "call": 0, "gate": "approval", "refusal": "approval.denied" })),
        accept("agent-approval-requested", "approval.requested with what the person was shown", "approval.requested", json!({ "session_id": s, "call": 0, "presented_digest": d("approval.requested", "presented_digest", b"Search the web for: weather in Lisbon") })),
        accept("agent-approval-granted", "approval.granted of tool scope, with edited arguments", "approval.granted", json!({ "session_id": s, "call": 0, "approver": "staff:4411", "latency_ms": 5210, "scope": "tool", "arguments_digest": d("approval.granted", "arguments_digest", br#"{"query":"weather in Porto"}"#) })),
        accept("agent-approval-denied", "approval.denied", "approval.denied", json!({ "session_id": s, "call": 0, "approver": "acct.7f3e", "latency_ms": 0 })),
        accept("agent-approval-granted-provider-subject", "approval.granted by a person named by an identity provider's subject, with a |", "approval.granted", json!({ "session_id": s, "call": 0, "approver": "google-oauth2|103547991597142817347", "latency_ms": 5210 })),
        accept("agent-approval-denied-base64-id", "approval.denied by a person named by a base64 id, with +, / and =", "approval.denied", json!({ "session_id": s, "call": 0, "approver": "q+Zk/3xY7w==", "latency_ms": 40 })),
        accept("agent-approval-timed-out", "approval.timed_out", "approval.timed_out", json!({ "session_id": s, "call": 0, "waited_ms": 300000 })),
        accept("agent-events-dropped", "events.dropped, the least count", "events.dropped", json!({ "count": 1 })),
        accept("agent-log-recovered", "log.recovered: the core's recovery of a torn tail", "log.recovered", json!({ "offset": 0, "length": 37, "sha256": h("torn tail") })),

        // ---- rule 1: the kind ----
        refuse("agent-kind-unknown", 1, "a kind section 4 does not name", "tool.called", json!({ "session_id": s })),
        refuse("agent-kind-other-profile", 1, "another profile's kind (khalm-vmr.enforcer's), which the core profile would accept", "enforcer.stopped", json!({})),

        // ---- rule 2: members named and required ----
        refuse("agent-member-unknown-content", 2, "call.proposed carrying the arguments themselves: a member the kind does not name", "call.proposed", with(&proposed, "arguments", json!({ "query": "weather in Lisbon" }))),
        refuse("agent-member-unknown", 2, "session.ended with a member the kind does not name", "session.ended", json!({ "session_id": s, "outcome": "completed", "reason": "done" })),
        refuse("agent-member-missing", 2, "session.started without configuration_hash", "session.started", without(&started, "configuration_hash")),
        refuse("agent-member-missing-session", 2, "call.executed without session_id", "call.executed", json!({ "call": 0, "outcome": "ok" })),

        // ---- rule 3: null, types, lists, limits, least values ----
        refuse("agent-member-null", 3, "an optional member written as null", "turn.started", json!({ "session_id": s, "turn": 0, "model_hash": null })),
        refuse("agent-integer-as-string", 3, "call as a string", "call.proposed", with(&proposed, "call", json!("0"))),
        refuse("agent-integer-negative", 3, "latency_ms below 0", "approval.denied", json!({ "session_id": s, "call": 0, "approver": "staff:4411", "latency_ms": -1 })),
        refuse("agent-integer-fraction", 3, "turn with a fraction", "turn.started", json!({ "session_id": s, "turn": 1.5 })),
        refuse("agent-integer-over-safe", 3, "call over 2^53 - 1", "call.proposed", with(&proposed, "call", json!(9_007_199_254_740_992u64))),
        refuse("agent-uuid-upper-case", 3, "session_id in upper case", "session.ended", json!({ "session_id": s.to_uppercase().replace("URN:UUID:", "urn:uuid:"), "outcome": "completed" })),
        refuse("agent-hash-upper-case", 3, "configuration_hash in upper case", "session.started", with(&started, "configuration_hash", json!(h("generation settings").to_uppercase().replace("SHA256:", "sha256:")))),
        refuse("agent-u64-number", 3, "seed as a JSON number: a u64 is a string", "session.started", with(&started, "seed", json!(7))),
        refuse("agent-u64-leading-zero", 3, "seed with a leading zero", "session.started", with(&started, "seed", json!("07"))),
        refuse("agent-u64-over", 3, "seed of 2^64", "session.started", with(&started, "seed", json!("18446744073709551616"))),
        refuse("agent-refusal-bad", 3, "a refusal id in upper case", "call.refused", json!({ "session_id": s, "call": 0, "gate": "approval", "refusal": "Approval.Denied" })),
        refuse("agent-name-space", 3, "a tool name with a space: it is written as tool_digest", "tool.registered", json!({ "session_id": s, "tool": "send payment" })),
        refuse("agent-name-too-long", 3, "a tool name of 129 characters", "tool.registered", json!({ "session_id": s, "tool": "t".repeat(129) })),
        refuse("agent-provider-empty", 3, "an empty provider", "tool.unregistered", json!({ "session_id": s, "tool": "search_web", "provider": "" })),
        refuse("agent-gate-bad", 3, "a gate starting with a digit", "gate.decided", json!({ "session_id": s, "call": 0, "gate": "2fa", "decision": "permitted" })),
        refuse("agent-gate-too-long", 3, "a gate of 65 characters", "call.refused", json!({ "session_id": s, "call": 0, "gate": "g".repeat(65), "refusal": "policy.forbidden" })),
        refuse("agent-digest-plain-hash", 3, "a plain SHA-256 where a keyed digest is required", "call.proposed", with(&proposed, "arguments_digest", json!(h(r#"{"query":"weather in Lisbon"}"#)))),
        refuse("agent-digest-upper-case", 3, "a digest in upper case", "call.proposed", with(&proposed, "arguments_digest", json!(args.to_uppercase().replace("HMAC-SHA256:", "hmac-sha256:")))),
        refuse("agent-digest-short", 3, "a digest of 63 digits", "call.executed", json!({ "session_id": s, "call": 0, "outcome": "ok", "result_digest": &args[..args.len() - 1] })),
        refuse("agent-person-address", 3, "an approver written as an e-mail address", "approval.granted", json!({ "session_id": s, "call": 0, "approver": "ana@example.com", "latency_ms": 5210 })),
        refuse("agent-person-provider-address", 3, "an approver written as an identity provider's id that holds an e-mail address", "approval.denied", json!({ "session_id": s, "call": 0, "approver": "auth0|ana@example.com", "latency_ms": 40 })),
        refuse("agent-person-name", 3, "stopped_by written as a name with a space", "session.ended", json!({ "session_id": s, "outcome": "stopped", "stopped_by": "Ana Lopez" })),
        refuse("agent-text-over-limit-bytes", 3, "runtime of 129 two-byte characters: 258 bytes, over the 256-byte limit although under 256 characters", "session.started", with(&started, "runtime", json!(accented_258))),
        refuse("agent-text-model-over-limit", 3, "a turn's model of 257 bytes", "turn.started", json!({ "session_id": s, "turn": 0, "model": "m".repeat(257) })),
        refuse("agent-text-detail-over-limit", 3, "policy.refused's detail of 4097 bytes", "policy.refused", json!({ "refusal": "policy.bad_signature", "detail": "x".repeat(4097) })),
        refuse("agent-session-outcome-unlisted", 3, "session.ended's outcome outside its list", "session.ended", json!({ "session_id": s, "outcome": "cancelled" })),
        refuse("agent-decision-unlisted", 3, "gate.decided's decision outside its list", "gate.decided", json!({ "session_id": s, "call": 0, "gate": "policy", "decision": "deferred" })),
        refuse("agent-call-outcome-unlisted", 3, "call.executed's outcome outside its list", "call.executed", json!({ "session_id": s, "call": 0, "outcome": "timeout" })),
        refuse("agent-scope-unlisted", 3, "approval.granted's scope outside its list", "approval.granted", json!({ "session_id": s, "call": 0, "approver": "staff:4411", "latency_ms": 5210, "scope": "forever" })),
        refuse("agent-count-zero", 3, "events.dropped's count below its least value, 1", "events.dropped", json!({ "count": 0 })),
        refuse("agent-length-zero", 3, "log.recovered's length below its least value, 1", "log.recovered", json!({ "offset": 0, "length": 0, "sha256": h("torn tail") })),

        // ---- rule 4: exactly one of tool and tool_digest ----
        refuse("agent-tool-both", 4, "call.proposed with both tool and tool_digest", "call.proposed", with(&proposed, "tool_digest", json!(d("call.proposed", "tool_digest", b"search_web")))),
        refuse("agent-tool-neither", 4, "tool.registered with neither tool nor tool_digest", "tool.registered", json!({ "session_id": s, "provider": "mcp:web-tools" })),
        refuse("agent-tool-both-unregistered", 4, "tool.unregistered with both tool and tool_digest", "tool.unregistered", json!({ "session_id": s, "tool": "search_web", "tool_digest": d("tool.unregistered", "tool_digest", b"search_web") })),

        // ---- rule 5: gate.decided's refusal exactly when refused ----
        refuse("agent-refused-without-refusal", 5, "gate.decided refused, without refusal", "gate.decided", json!({ "session_id": s, "call": 0, "gate": "policy", "decision": "refused" })),
        refuse("agent-permitted-with-refusal", 5, "gate.decided permitted, with a refusal", "gate.decided", json!({ "session_id": s, "call": 0, "gate": "policy", "decision": "permitted", "refusal": "policy.forbidden" })),

        // ---- rule 6: parent_call and stopped_by ----
        refuse("agent-parent-call-alone", 6, "parent_call without parent_session_id", "session.started", with(&started, "parent_call", json!(4))),
        refuse("agent-stopped-by-not-stopped", 6, "stopped_by with outcome completed", "session.ended", json!({ "session_id": s, "outcome": "completed", "stopped_by": "staff:4411" })),
    ];
    Value::Array(cases)
}

/// The digest cases (§3). The expected hex was computed with Python's hmac
/// and hashlib and is written here by hand; the generator asserts this build
/// computes the same before it writes anything.
fn digest_cases() -> Value {
    let jcs_text = r#"{"amount":250.5,"memo":"café","to":"ACME-7"}"#;
    let as_parsed = json!({ "to": "ACME-7", "amount": 250.5, "memo": "café" });
    assert_eq!(String::from_utf8(json_content(&as_parsed)).unwrap(), jcs_text, "the JCS form of the parsed value");
    let raw_arguments = r#"{"amount": 250, "to": "ACME-7"}"#;
    let s1_key = "54ce6562a2e66f207275d740b228c4ad0a105391700f74c1d8e6481ef69cdcfc";
    let cases = vec![
        digest_case(
            "agent-digest-bytes",
            "arguments the model generated, as received: their bytes before any parsing (not their JCS form)",
            SESSION,
            ("call.proposed", "arguments_digest", 1043),
            Content::Text(raw_arguments),
            (s1_key, "58334c870aee26aed0a98fb7eea7aa9d41d7e8582e565791519bf7880582ff3a", "hmac-sha256:c35d4645210f09f047375c6df7fa900069ef7ac08bdb0acd606cc99c9cd7b0a7"),
        ),
        digest_case(
            "agent-digest-json",
            "a result received only as a parsed JSON value: the UTF-8 bytes of its JCS form",
            SESSION,
            ("call.executed", "result_digest", 1047),
            Content::Json(as_parsed),
            (s1_key, "106eb6b407cfc1c294824b09a2fdfb7cc15577abd9838c92ef9707a6fc8bacf4", "hmac-sha256:add770ee396c8a29509b18679e6b2faca0839ae9f034d21ccb12abd37444888a"),
        ),
        digest_case(
            "agent-digest-tool-name",
            "a short, guessable tool name that is not a name, at index 0",
            SESSION,
            ("tool.registered", "tool_digest", 0),
            Content::Text("send payment"),
            (s1_key, "41e4a7485d70ec5bdbf7874429467bea104d20fc0665171f11890dfa1e2f7e07", "hmac-sha256:422740ffdfc9efdb951a682cf46045ee4716720511708ca6c782ed0a9c0cdce9"),
        ),
        digest_case(
            "agent-digest-empty",
            "empty content",
            SESSION,
            ("turn.started", "input_digest", 7),
            Content::Text(""),
            (s1_key, "e2a980920a54e2449321882e844e13f3309b2308cce01d33362fa9d3ba343e0e", "hmac-sha256:5df8eb28306fab9e23cd9b4ac7db9806c87c1829b90748a83566dadcc149eb26"),
        ),
        digest_case(
            "agent-digest-other-session",
            "the content, kind, member and index of agent-digest-bytes in another session: another session key, another digest",
            OTHER_SESSION,
            ("call.proposed", "arguments_digest", 1043),
            Content::Text(raw_arguments),
            ("71fd2cced3f272b45d4074035c9527689a9fb6d550f96c469f8c22a878d0990f", "1a241ef035d4badac0d4b345013a35d918375cc9bcc6e68d699234c0e501f9df", "hmac-sha256:9403d10d99feb9065eda80dc8c290f98452d3094c575a888e2e830112431af2e"),
        ),
    ];
    Value::Array(cases)
}

/// A digest case's content: bytes as received (here UTF-8 text), or a value
/// received only parsed.
enum Content<'a> {
    Text(&'a str),
    Json(Value),
}

fn digest_case(
    id: &str,
    description: &str,
    session_id: &str,
    (kind, member, index): (&str, &str, u64),
    content: Content<'_>,
    (session_key, item_key, digest): (&str, &str, &str),
) -> Value {
    let secret = secret();
    let bytes = match &content {
        Content::Text(text) => text.as_bytes().to_vec(),
        Content::Json(value) => json_content(value),
    };
    let sk = secret.session_key(session_id);
    let ik = sk.item_key(kind, member, index);
    assert_eq!(hex::encode(sk.as_bytes()), session_key, "{id}: the session key");
    assert_eq!(hex::encode(ik.as_bytes()), item_key, "{id}: the item key");
    assert_eq!(ik.digest(&bytes), digest, "{id}: the digest");
    let mut case = json!({
        "id": id,
        "description": description,
        "content_secret_label": SECRET_LABEL,
        "content_secret": hex::encode(secret.as_bytes()),
        "session_id": session_id,
        "kind": kind,
        "member": member,
        "index": index,
        "label": label(kind, member, index),
    });
    match content {
        Content::Text(text) => case["content_text"] = json!(text),
        Content::Json(value) => case["content_json"] = value,
    }
    case["content_hex"] = json!(hex::encode(&bytes));
    case["session_key"] = json!(session_key);
    case["item_key"] = json!(item_key);
    case["digest"] = json!(digest);
    case
}
