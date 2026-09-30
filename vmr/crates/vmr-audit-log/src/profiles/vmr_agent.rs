// ============================================================================
//  vmr_agent.rs — the `vmr.agent` profile
//  (`specs/audit-profile-agent-v0.1.md`).
//
//  What an agent runtime decided about the tool calls a model proposed: the
//  tools a session could reach, the proposals, the gates, the people and the
//  runs. Any runtime may write it, whoever made the runtime and whichever
//  model it runs: nothing here knows one runtime, one model or one vendor.
//
//  Three parts:
//    * this module: the kinds of §4 and the checks of §4.6, refusing with the
//      core's `audit_entry.structure` and a message that names the kind and
//      the member, never a member's value (a value may be content a writer
//      put there by mistake, and a refusal is shown to whoever reads the log);
//    * `digest`: the keyed digest of §3, from the `hmac` and `sha2` crates;
//    * `notes`: a reader's pass over accepted entries that reports where they
//      break the rules between entries (§4.6, its last paragraph) and never
//      refuses.
// ============================================================================

//! The `vmr.agent` profile (`specs/audit-profile-agent-v0.1.md`): its kinds,
//! the detail each carries, and the checks of its §4.6. [`digest`] computes
//! the keyed digests of its §3, and [`notes`] reports what a log's accepted
//! entries say across one another.

pub mod digest;
pub mod notes;

use crate::entry::structure;
use crate::error::Error;
use crate::profile::EntryProfile;
use crate::types::{is_lower_hex_64, is_pos_int, is_refusal, is_safe_int, is_u64_string, is_uuid};
use serde_json::Value;

/// The profile's name (core §5.1: `<owner>.<name>`).
pub const NAME: &str = "vmr.agent";

/// The `vmr.agent` profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentProfile;

impl EntryProfile for AgentProfile {
    fn name(&self) -> &str {
        NAME
    }

    fn check(&self, kind: &str, detail: &Value) -> Result<(), Error> {
        check_detail(kind, detail)
    }
}

/// The `vmr.agent` profile ([`AgentProfile`]).
pub const PROFILE: AgentProfile = AgentProfile;

/// The type of a detail member (§2, with the core's §2 types).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberType {
    /// A UUID URN (core §2 rule 8).
    Uuid,
    /// A hash: `sha256:` and 64 lower-case hexadecimal digits (core §2 rule 7).
    Hash,
    /// An integer (core §2 rule 5) of at least `min`.
    Integer {
        /// The least value.
        min: u64,
    },
    /// A u64: a string of decimal digits without leading zeros (§2).
    U64,
    /// A refusal id (§2).
    Refusal,
    /// A text of at most `max_bytes` bytes of UTF-8 (§2's text is
    /// 4096; `runtime` and `model` are 256).
    Text {
        /// The most bytes.
        max_bytes: usize,
    },
    /// A name (§2).
    Name,
    /// A gate (§2, §4.3).
    Gate,
    /// A digest (§2, §3).
    Digest,
    /// A person (§2, §4.4).
    Person,
    /// One of a list of strings.
    OneOf(&'static [&'static str]),
}

impl MemberType {
    /// Whether `value` is of this type. `null` is of none.
    pub fn accepts(&self, value: &Value) -> bool {
        let text = value.as_str();
        match *self {
            MemberType::Uuid => is_uuid(value),
            MemberType::Hash => text.is_some_and(|s| s.strip_prefix("sha256:").is_some_and(is_lower_hex_64)),
            MemberType::Integer { min: 0 } => is_safe_int(value),
            MemberType::Integer { min: 1 } => is_pos_int(value),
            MemberType::Integer { min } => is_safe_int(value) && value.as_u64().is_some_and(|n| n >= min),
            MemberType::U64 => is_u64_string(value),
            MemberType::Refusal => is_refusal(value),
            MemberType::Text { max_bytes } => text.is_some_and(|s| s.len() <= max_bytes),
            MemberType::Name => text.is_some_and(|s| is_token(s, 128, |b| b"_./:-".contains(&b))),
            MemberType::Gate => text.is_some_and(is_gate),
            MemberType::Digest => text.is_some_and(digest::is_digest),
            MemberType::Person => text.is_some_and(|s| is_token(s, 128, |b| b"_.:|+=/-".contains(&b))),
            MemberType::OneOf(values) => text.is_some_and(|s| values.contains(&s)),
        }
    }

    /// The type in words, for a refusal's message.
    pub fn describe(&self) -> String {
        match *self {
            MemberType::Uuid => "a UUID URN".to_string(),
            MemberType::Hash => "a hash".to_string(),
            MemberType::Integer { min: 0 } => "an integer".to_string(),
            MemberType::Integer { min } => format!("an integer of at least {min}"),
            MemberType::U64 => "a u64 (a string of decimal digits)".to_string(),
            MemberType::Refusal => "a refusal id".to_string(),
            MemberType::Text { max_bytes } => format!("a text of at most {max_bytes} bytes"),
            MemberType::Name => "a name".to_string(),
            MemberType::Gate => "a gate".to_string(),
            MemberType::Digest => "a digest".to_string(),
            MemberType::Person => "a person".to_string(),
            MemberType::OneOf(values) => {
                let quoted: Vec<String> = values.iter().map(|v| format!("{v:?}")).collect();
                format!("one of {}", quoted.join(", "))
            }
        }
    }
}

/// `^[A-Za-z0-9<extra>]{1,max}$`: the name and person types (§2).
fn is_token(s: &str, max: usize, extra: impl Fn(u8) -> bool) -> bool {
    (1..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || extra(b))
}

/// `^[a-z][a-z_]{0,63}$`: the gate type (§2).
fn is_gate(s: &str) -> bool {
    s.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// A member of a kind's detail: its name, whether the kind requires it, and
/// its type (§4's tables).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// The member's name.
    pub name: &'static str,
    /// Whether the kind requires it. `tool` and `tool_digest` are each
    /// optional, and exactly one of them is present (§4.6 rule 4).
    pub required: bool,
    /// Its type.
    pub ty: MemberType,
}

const fn req(name: &'static str, ty: MemberType) -> Member {
    Member { name, required: true, ty }
}
const fn opt(name: &'static str, ty: MemberType) -> Member {
    Member { name, required: false, ty }
}

const INTEGER: MemberType = MemberType::Integer { min: 0 };
const AT_LEAST_ONE: MemberType = MemberType::Integer { min: 1 };
const TEXT: MemberType = MemberType::Text { max_bytes: 4096 };
const SHORT_TEXT: MemberType = MemberType::Text { max_bytes: 256 };
const SESSION_ID: Member = req("session_id", MemberType::Uuid);
const SESSION_ID_OPTIONAL: Member = opt("session_id", MemberType::Uuid);
const CALL: Member = req("call", INTEGER);
const TOOL: Member = opt("tool", MemberType::Name);
const TOOL_DIGEST: Member = opt("tool_digest", MemberType::Digest);
const PROVIDER: Member = opt("provider", MemberType::Name);

/// §4.1
const SESSION_STARTED: &[Member] = &[
    SESSION_ID,
    req("runtime", SHORT_TEXT),
    req("model", SHORT_TEXT),
    opt("model_hash", MemberType::Hash),
    opt("record_id", MemberType::Uuid),
    req("configuration_hash", MemberType::Hash),
    opt("seed", MemberType::U64),
    opt("parent_session_id", MemberType::Uuid),
    opt("parent_call", INTEGER),
];
const SESSION_ENDED: &[Member] = &[
    SESSION_ID,
    req("outcome", MemberType::OneOf(&["completed", "stopped", "terminated", "failed"])),
    opt("stopped_by", MemberType::Person),
];
const POLICY_LOADED: &[Member] = &[SESSION_ID_OPTIONAL, req("policy_hash", MemberType::Hash)];
const POLICY_REFUSED: &[Member] = &[
    SESSION_ID_OPTIONAL,
    opt("policy_hash", MemberType::Hash),
    req("refusal", MemberType::Refusal),
    req("detail", TEXT),
];
const TOOL_REGISTERED: &[Member] = &[SESSION_ID, TOOL, TOOL_DIGEST, PROVIDER, opt("schema_digest", MemberType::Digest)];
const TOOL_UNREGISTERED: &[Member] = &[SESSION_ID, TOOL, TOOL_DIGEST, PROVIDER];
/// §4.2
const TURN_STARTED: &[Member] = &[
    SESSION_ID,
    req("turn", INTEGER),
    opt("input_digest", MemberType::Digest),
    opt("grammar_digest", MemberType::Digest),
    opt("model", SHORT_TEXT),
    opt("model_hash", MemberType::Hash),
];
const CALL_PROPOSED: &[Member] =
    &[SESSION_ID, CALL, req("turn", INTEGER), TOOL, TOOL_DIGEST, req("arguments_digest", MemberType::Digest)];
const GATE_DECIDED: &[Member] = &[
    SESSION_ID,
    CALL,
    req("gate", MemberType::Gate),
    req("decision", MemberType::OneOf(&["permitted", "refused"])),
    opt("refusal", MemberType::Refusal),
];
const CALL_EXECUTED: &[Member] = &[
    SESSION_ID,
    CALL,
    req("outcome", MemberType::OneOf(&["ok", "error"])),
    opt("result_digest", MemberType::Digest),
];
const CALL_REFUSED: &[Member] = &[SESSION_ID, CALL, req("gate", MemberType::Gate), req("refusal", MemberType::Refusal)];
/// §4.4
const APPROVAL_REQUESTED: &[Member] = &[SESSION_ID, CALL, opt("presented_digest", MemberType::Digest)];
const APPROVAL_GRANTED: &[Member] = &[
    SESSION_ID,
    CALL,
    req("approver", MemberType::Person),
    req("latency_ms", INTEGER),
    opt("scope", MemberType::OneOf(&["call", "tool", "session"])),
    opt("arguments_digest", MemberType::Digest),
];
const APPROVAL_DENIED: &[Member] =
    &[SESSION_ID, CALL, req("approver", MemberType::Person), req("latency_ms", INTEGER)];
const APPROVAL_TIMED_OUT: &[Member] = &[SESSION_ID, CALL, req("waited_ms", INTEGER)];
/// §4.5
const EVENTS_DROPPED: &[Member] = &[req("count", AT_LEAST_ONE)];
const LOG_RECOVERED: &[Member] =
    &[req("offset", INTEGER), req("length", AT_LEAST_ONE), req("sha256", MemberType::Hash)];

/// The kinds an entry of this profile may carry (§4), in the order §4 names
/// them.
pub const KINDS: [&str; 17] = [
    "session.started",
    "session.ended",
    "policy.loaded",
    "policy.refused",
    "tool.registered",
    "tool.unregistered",
    "turn.started",
    "call.proposed",
    "gate.decided",
    "call.executed",
    "call.refused",
    "approval.requested",
    "approval.granted",
    "approval.denied",
    "approval.timed_out",
    "events.dropped",
    "log.recovered",
];

/// The kinds whose detail names a tool as exactly one of `tool` and
/// `tool_digest` (§4.6 rule 4).
pub const TOOL_KINDS: [&str; 3] = ["tool.registered", "tool.unregistered", "call.proposed"];

/// The members a kind's detail may carry (§4), or `None` for a kind this
/// profile does not have.
pub fn members(kind: &str) -> Option<&'static [Member]> {
    Some(match kind {
        "session.started" => SESSION_STARTED,
        "session.ended" => SESSION_ENDED,
        "policy.loaded" => POLICY_LOADED,
        "policy.refused" => POLICY_REFUSED,
        "tool.registered" => TOOL_REGISTERED,
        "tool.unregistered" => TOOL_UNREGISTERED,
        "turn.started" => TURN_STARTED,
        "call.proposed" => CALL_PROPOSED,
        "gate.decided" => GATE_DECIDED,
        "call.executed" => CALL_EXECUTED,
        "call.refused" => CALL_REFUSED,
        "approval.requested" => APPROVAL_REQUESTED,
        "approval.granted" => APPROVAL_GRANTED,
        "approval.denied" => APPROVAL_DENIED,
        "approval.timed_out" => APPROVAL_TIMED_OUT,
        "events.dropped" => EVENTS_DROPPED,
        "log.recovered" => LOG_RECOVERED,
        _ => return None,
    })
}

/// The longest stranger's member name a refusal quotes, in characters.
const SHOWN_NAME_CHARS: usize = 64;

/// A member name from the detail, quoted and bounded (the refusal escapes it).
fn shown_name(name: &str) -> String {
    if name.chars().count() <= SHOWN_NAME_CHARS {
        format!("{name:?}")
    } else {
        let cut: String = name.chars().take(SHOWN_NAME_CHARS).collect();
        format!("{cut:?}…")
    }
}

/// The checks of §4.6, in its order. Every refusal is `audit_entry.structure`
/// and names the kind and the member; no message quotes a member's value.
fn check_detail(kind: &str, detail: &Value) -> Result<(), Error> {
    // Rule 1: the kind is one of §4's.
    let Some(specs) = members(kind) else {
        return Err(structure(format!("{kind}: not a kind of the {NAME} profile")));
    };
    let obj = detail.as_object().ok_or_else(|| structure(format!("{kind}: the detail is not an object")))?;

    // Rule 2: no member the kind does not name, and none it requires missing.
    if let Some(unknown) = obj.keys().find(|key| !specs.iter().any(|m| m.name == key.as_str())) {
        return Err(structure(format!("{kind}: the detail has the member {}, which the kind does not name", shown_name(unknown))));
    }
    if let Some(missing) = specs.iter().find(|m| m.required && !obj.contains_key(m.name)) {
        return Err(structure(format!("{kind}: the detail lacks {:?}, which the kind requires", missing.name)));
    }

    // Rule 3: every member present is of its type.
    for member in specs {
        match obj.get(member.name) {
            Some(Value::Null) => return Err(structure(format!("{kind}: detail member {:?} is null", member.name))),
            Some(value) if !member.ty.accepts(value) => {
                return Err(structure(format!("{kind}: detail member {:?} is not {}", member.name, member.ty.describe())))
            }
            _ => {}
        }
    }

    // Rule 4: exactly one of tool and tool_digest.
    if TOOL_KINDS.contains(&kind) {
        match (obj.contains_key("tool"), obj.contains_key("tool_digest")) {
            (true, true) => {
                return Err(structure(format!("{kind}: detail members \"tool\" and \"tool_digest\" are both present")))
            }
            (false, false) => {
                return Err(structure(format!("{kind}: the detail has neither \"tool\" nor \"tool_digest\"")))
            }
            _ => {}
        }
    }

    // Rule 5: gate.decided's refusal is present exactly when it refused.
    if kind == "gate.decided" {
        let refused = obj.get("decision").and_then(Value::as_str) == Some("refused");
        match (obj.contains_key("refusal"), refused) {
            (true, false) => {
                return Err(structure(format!("{kind}: detail member \"refusal\" is present, and \"decision\" is not \"refused\"")))
            }
            (false, true) => {
                return Err(structure(format!("{kind}: \"decision\" is \"refused\", and the detail lacks \"refusal\"")))
            }
            _ => {}
        }
    }

    // Rule 6: parent_call only with parent_session_id; stopped_by only when
    // a person stopped the session.
    if kind == "session.started" && obj.contains_key("parent_call") && !obj.contains_key("parent_session_id") {
        return Err(structure(format!("{kind}: detail member \"parent_call\" is present without \"parent_session_id\"")));
    }
    if kind == "session.ended"
        && obj.contains_key("stopped_by")
        && obj.get("outcome").and_then(Value::as_str) != Some("stopped")
    {
        return Err(structure(format!("{kind}: detail member \"stopped_by\" is present, and \"outcome\" is not \"stopped\"")));
    }
    Ok(())
}
