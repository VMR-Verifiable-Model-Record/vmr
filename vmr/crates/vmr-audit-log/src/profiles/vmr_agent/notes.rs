// ============================================================================
//  notes.rs — what a `vmr.agent` log's entries say across one another
//  (`specs/audit-profile-agent-v0.1.md` §4.6, its last paragraph).
//
//  The rules that relate entries to each other (§4.1's reachable tools, §4.2's
//  order of a call's entries, §4.4's approval gate) are the writer's: a reader
//  does not refuse a log for breaking them, and SHOULD report where it does.
//  This is that report: fed the entries a reader accepted, in log order, it
//  counts what they record and notes each place they break those rules. It
//  never refuses and never changes a verdict, and what it counts is what the
//  writer states, not what happened.
//
//  Its memory is bounded, whatever the log. It holds, per open session, the
//  tools it could reach and a few bits per call; a session's state is dropped
//  at its `session.ended` (only its id is kept, to note a later entry of it).
//  Past a cap on the sessions it tracks, or on the calls and tools it holds,
//  it drops everything, stops counting and noting, and says from which entry
//  (`Notes::untracked_from`). It keeps at most a limit of notes (the count of
//  all of them is kept) and counts refusals under at most `MAX_GATES_COUNTED`
//  gate names.
// ============================================================================

//! A reader's pass over the accepted entries of a `vmr.agent` log: a
//! [`Summary`] of what they record and a [`Note`] where they break the rules
//! between entries (§4.6), in bounded memory.

use crate::entry::AuditEntry;
use crate::error::display_safe;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// What a note is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NoteKind {
    /// A `call.proposed` names as `tool` a tool the session could not reach
    /// (§4.1, §4.2): a writer names any other proposed tool as
    /// `tool_digest`, so this may be model output written in clear. The note
    /// names the entry and the call, never the name.
    UnreachableTool,
    /// A second `call.proposed` of a call (§4.2: one per call). The call is
    /// counted once.
    ProposedTwice,
    /// An entry of a call with no earlier `call.proposed` of that call
    /// (§4.2).
    NotProposed,
    /// An entry of a call after the call's `call.refused` (§4.2).
    AfterRefusal,
    /// A `gate.decided` of the `approval` gate with no answer of a person
    /// (`approval.granted`, `approval.denied` or `approval.timed_out`) for
    /// the call before it, and no standing approval covering it (§4.4).
    UnansweredApproval,
    /// A `gate.decided` of the `approval` gate that does not follow the
    /// person's last answer for the call (§4.4): permitted after
    /// `approval.denied` or `approval.timed_out`, refused after
    /// `approval.granted`, or refused with another refusal than the answer's.
    ApprovalAgainstAnswer,
    /// An entry of a session after the session's `session.ended` (§2: a
    /// session runs from its start to its end).
    AfterSessionEnded,
}

/// One place the entries break a rule between entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// The `index` of the entry the note is about.
    pub index: u64,
    /// What it is about.
    pub kind: NoteKind,
    /// The entry's session.
    pub session_id: String,
    /// The entry's call, for the kinds that carry one.
    pub call: Option<u64>,
    /// The note in words, terminal-safe. It names kinds, members, the entry
    /// and the call, never a member's value.
    pub message: String,
}

/// What the accepted entries record, counted: the writer's statements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// The sessions the entries name (distinct `session_id`s).
    pub sessions: u64,
    /// Calls proposed: the first `call.proposed` of each call.
    pub calls: u64,
    /// `call.refused` entries, by the gate each names: the first
    /// [`MAX_GATES_COUNTED`] gate names.
    pub refused_by_gate: BTreeMap<String, u64>,
    /// `call.refused` entries naming a gate past the first
    /// [`MAX_GATES_COUNTED`].
    pub refused_by_other_gates: u64,
    /// `approval.granted` entries.
    pub approvals_granted: u64,
    /// `approval.denied` entries.
    pub approvals_denied: u64,
    /// `approval.timed_out` entries.
    pub approvals_timed_out: u64,
    /// The events the writer says it could not record: the sum of the
    /// `events.dropped` counts (§5: the log is incomplete when it is not 0).
    /// Counted over the whole log, tracked or not.
    pub events_dropped: u64,
    /// `log.recovered` entries: torn tails the writer moved aside. Counted
    /// over the whole log, tracked or not.
    pub recoveries: u64,
}

impl Summary {
    /// Every `call.refused` entry, whatever its gate.
    pub fn calls_refused(&self) -> u64 {
        self.refused_by_gate.values().fold(self.refused_by_other_gates, |sum, n| sum.saturating_add(*n))
    }
}

/// How many notes [`Notes::new`] keeps.
pub const DEFAULT_NOTE_LIMIT: usize = 1000;
/// How many sessions (open, or ended and remembered by id) [`Notes::new`]
/// tracks.
pub const DEFAULT_MAX_SESSIONS: usize = 100_000;
/// How many calls and tools of open sessions [`Notes::new`] holds.
pub const DEFAULT_MAX_ITEMS: usize = 200_000;
/// How many gate names [`Summary::refused_by_gate`] counts under.
pub const MAX_GATES_COUNTED: usize = 64;

/// A person's answer for a call (§4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Granted,
    Denied,
    TimedOut,
}

impl Answer {
    /// The answer's kind, which is also the refusal id the approval gate
    /// refuses with after a denial or a timeout.
    fn kind(self) -> &'static str {
        match self {
            Answer::Granted => "approval.granted",
            Answer::Denied => "approval.denied",
            Answer::TimedOut => "approval.timed_out",
        }
    }
}

/// A call's state: whether it was proposed, the tool it proposed by name,
/// whether it was refused, and the person's last answer for it.
#[derive(Debug, Default)]
struct Call {
    proposed: bool,
    tool: Option<String>,
    refused: bool,
    answer: Option<Answer>,
}

/// A session's state. An ended session holds none: only `ended`.
#[derive(Debug, Default)]
struct Session {
    ended: bool,
    /// The tools it could reach: `(tool, provider)` (§4.1).
    reachable: BTreeSet<(String, Option<String>)>,
    calls: BTreeMap<u64, Call>,
    /// An `approval.granted` of scope `"session"` was seen (§4.4).
    standing_session: bool,
    /// The tools an `approval.granted` of scope `"tool"` covers (§4.4).
    standing_tools: BTreeSet<String>,
}

impl Session {
    /// The calls and tools it holds.
    fn items(&self) -> usize {
        self.calls.len().saturating_add(self.reachable.len()).saturating_add(self.standing_tools.len())
    }
}

/// The pass: feed it every accepted entry in log order with
/// [`Notes::observe`], then read [`Notes::summary`], [`Notes::notes`] and
/// [`Notes::untracked_from`].
#[derive(Debug)]
pub struct Notes {
    sessions: BTreeMap<String, Session>,
    /// The calls and tools the open sessions hold.
    items: usize,
    summary: Summary,
    notes: Vec<Note>,
    total: u64,
    limit: usize,
    max_sessions: usize,
    max_items: usize,
    untracked_from: Option<u64>,
}

impl Default for Notes {
    fn default() -> Self {
        Notes::new()
    }
}

fn text<'a>(detail: &'a Value, member: &str) -> Option<&'a str> {
    detail.get(member).and_then(Value::as_str)
}

impl Notes {
    /// A pass that keeps the first [`DEFAULT_NOTE_LIMIT`] notes, within the
    /// default caps.
    pub fn new() -> Notes {
        Notes::with_limit(DEFAULT_NOTE_LIMIT)
    }

    /// A pass that keeps the first `limit` notes, and counts all of them,
    /// within [`DEFAULT_MAX_SESSIONS`] and [`DEFAULT_MAX_ITEMS`].
    pub fn with_limit(limit: usize) -> Notes {
        Notes::with_bounds(limit, DEFAULT_MAX_SESSIONS, DEFAULT_MAX_ITEMS)
    }

    /// A pass that keeps the first `limit` notes, tracks at most
    /// `max_sessions` sessions (open, or ended and remembered by id) and
    /// holds at most `max_items` calls and tools of open sessions. The entry
    /// that passes a cap is still read; from the next one on, nothing but
    /// lost events and recoveries is counted, and nothing is noted.
    pub fn with_bounds(limit: usize, max_sessions: usize, max_items: usize) -> Notes {
        Notes {
            sessions: BTreeMap::new(),
            items: 0,
            summary: Summary::default(),
            notes: Vec::new(),
            total: 0,
            limit,
            max_sessions,
            max_items,
            untracked_from: None,
        }
    }

    /// What the entries so far record.
    pub fn summary(&self) -> &Summary {
        &self.summary
    }

    /// The notes kept, in log order: the first of [`Notes::total`].
    pub fn notes(&self) -> &[Note] {
        &self.notes
    }

    /// How many notes the entries so far gave, kept or not.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// The index of the first entry the pass did not track, once a cap was
    /// passed: from it on, the summary counts only lost events and
    /// recoveries, and nothing is noted.
    pub fn untracked_from(&self) -> Option<u64> {
        self.untracked_from
    }

    /// The most sessions tracked and the most calls and tools held.
    pub fn bounds(&self) -> (usize, usize) {
        (self.max_sessions, self.max_items)
    }

    /// Take in the next accepted entry of the log. An entry the profile did
    /// not accept is read as far as its members allow; nothing here panics
    /// or refuses.
    pub fn observe(&mut self, entry: &AuditEntry) {
        for Found { kind, session_id, call, message } in self.observe_parts(&entry.kind, &entry.detail) {
            self.total = self.total.saturating_add(1);
            if self.notes.len() < self.limit {
                let message = display_safe(&format!("entry {}: session {session_id}: {message}", entry.index));
                self.notes.push(Note { index: entry.index, kind, session_id, call, message });
            }
        }
        if self.untracked_from.is_none() && (self.sessions.len() > self.max_sessions || self.items > self.max_items) {
            // Past a cap: drop everything, and say from which entry.
            self.sessions = BTreeMap::new();
            self.items = 0;
            self.untracked_from = Some(entry.index.saturating_add(1));
        }
    }

    /// The counting and the rules; the notes this entry gives.
    fn observe_parts(&mut self, kind: &str, detail: &Value) -> Vec<Found> {
        let summary = &mut self.summary;
        match kind {
            "events.dropped" => {
                let count = detail.get("count").and_then(Value::as_u64).unwrap_or(0);
                summary.events_dropped = summary.events_dropped.saturating_add(count);
            }
            "log.recovered" => summary.recoveries = summary.recoveries.saturating_add(1),
            _ => {}
        }
        if self.untracked_from.is_some() {
            return Vec::new();
        }
        let Some(session_id) = text(detail, "session_id") else { return Vec::new() };
        let number = detail.get("call").and_then(Value::as_u64);

        if !self.sessions.contains_key(session_id) {
            summary.sessions = summary.sessions.saturating_add(1);
        }
        let session = self.sessions.entry(session_id.to_string()).or_default();
        if session.ended {
            // §2: a session runs from its start to its end. Nothing else of
            // the entry is read: its session's state is gone.
            return vec![Found {
                kind: NoteKind::AfterSessionEnded,
                session_id: session_id.to_string(),
                call: number,
                message: format!("{kind} of the session after its session.ended (a session ends there, §2)"),
            }];
        }
        let items = &mut self.items;
        let tool = text(detail, "tool").map(str::to_string);
        let provider = text(detail, "provider").map(str::to_string);
        let mut found: Vec<Found> = Vec::new();
        let mut note = |kind: NoteKind, call: u64, message: String| {
            found.push(Found { kind, session_id: session_id.to_string(), call: Some(call), message });
        };

        match kind {
            "session.ended" => {
                *items = items.saturating_sub(session.items());
                *session = Session { ended: true, ..Session::default() };
            }
            "tool.registered" => {
                if let Some(tool) = tool {
                    if session.reachable.insert((tool, provider)) {
                        *items = items.saturating_add(1);
                    }
                }
            }
            "tool.unregistered" => {
                if let Some(tool) = tool {
                    if session.reachable.remove(&(tool, provider)) {
                        *items = items.saturating_sub(1);
                    }
                }
            }
            "call.proposed" | "gate.decided" | "call.executed" | "call.refused" | "approval.requested"
            | "approval.granted" | "approval.denied" | "approval.timed_out" => {
                let Some(number) = number else { return Vec::new() };
                if !session.calls.contains_key(&number) {
                    *items = items.saturating_add(1);
                }
                let call = session.calls.entry(number).or_default();

                // §4.2: nothing of a call follows its call.refused, a call is
                // proposed once, and every other entry of it follows its
                // call.proposed.
                if call.refused {
                    note(
                        NoteKind::AfterRefusal,
                        number,
                        format!("{kind} of call {number} after the call's call.refused (nothing of a call follows it, §4.2)"),
                    );
                } else if kind == "call.proposed" && call.proposed {
                    note(
                        NoteKind::ProposedTwice,
                        number,
                        format!(
                            "a second call.proposed of call {number} (each call is proposed once, §4.2); the call is \
                             counted once"
                        ),
                    );
                } else if kind != "call.proposed" && !call.proposed {
                    note(
                        NoteKind::NotProposed,
                        number,
                        format!("{kind} of call {number}, which no earlier call.proposed of the session proposed (§4.2)"),
                    );
                }

                match kind {
                    "call.proposed" => {
                        if let Some(tool) = &tool {
                            // §4.1: reachable is registered before this entry
                            // and not unregistered since, whatever the
                            // provider. The name is never shown: it may be
                            // model output.
                            if !session.reachable.iter().any(|(name, _)| name == tool) {
                                note(
                                    NoteKind::UnreachableTool,
                                    number,
                                    format!(
                                        "call {number} proposes, as tool, a name the session could not reach \
                                         (§4.1); a writer names any other proposed tool as tool_digest, so the \
                                         entry may hold model output written in clear"
                                    ),
                                );
                            }
                        }
                        if !call.proposed {
                            summary.calls = summary.calls.saturating_add(1);
                            call.proposed = true;
                            call.tool = tool;
                        }
                    }
                    "call.refused" => {
                        call.refused = true;
                        let gate = text(detail, "gate").unwrap_or("");
                        let counted = summary.refused_by_gate.len() < MAX_GATES_COUNTED
                            || summary.refused_by_gate.contains_key(gate);
                        if counted {
                            let n = summary.refused_by_gate.entry(gate.to_string()).or_insert(0);
                            *n = n.saturating_add(1);
                        } else {
                            summary.refused_by_other_gates = summary.refused_by_other_gates.saturating_add(1);
                        }
                    }
                    "approval.granted" => {
                        summary.approvals_granted = summary.approvals_granted.saturating_add(1);
                        call.answer = Some(Answer::Granted);
                        match text(detail, "scope") {
                            Some("session") => session.standing_session = true,
                            Some("tool") => {
                                if let Some(tool) = &call.tool {
                                    if session.standing_tools.insert(tool.clone()) {
                                        *items = items.saturating_add(1);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    "approval.denied" => {
                        summary.approvals_denied = summary.approvals_denied.saturating_add(1);
                        call.answer = Some(Answer::Denied);
                    }
                    "approval.timed_out" => {
                        summary.approvals_timed_out = summary.approvals_timed_out.saturating_add(1);
                        call.answer = Some(Answer::TimedOut);
                    }
                    "gate.decided" if text(detail, "gate") == Some("approval") => {
                        // §4.4: a person's answer comes first, unless a
                        // standing approval of the session, or of the call's
                        // tool, covers the call; and the gate follows the
                        // answer.
                        let standing = session.standing_session
                            || call.tool.as_ref().is_some_and(|t| session.standing_tools.contains(t));
                        match call.answer {
                            None if !standing => note(
                                NoteKind::UnansweredApproval,
                                number,
                                format!(
                                    "gate.decided of the approval gate for call {number}, with no approval.granted, \
                                     approval.denied or approval.timed_out of the call before it and no standing \
                                     approval covering it (§4.4)"
                                ),
                            ),
                            None => {}
                            Some(answer) => {
                                let decision = text(detail, "decision");
                                let follows = match answer {
                                    Answer::Granted => decision == Some("permitted"),
                                    Answer::Denied | Answer::TimedOut => {
                                        decision == Some("refused") && text(detail, "refusal") == Some(answer.kind())
                                    }
                                };
                                if !follows {
                                    note(
                                        NoteKind::ApprovalAgainstAnswer,
                                        number,
                                        format!(
                                            "gate.decided of the approval gate for call {number} does not follow the \
                                             call's last answer, {} (§4.4: permitted after approval.granted, refused \
                                             with the answer's refusal after approval.denied or approval.timed_out)",
                                            answer.kind()
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        found
    }
}

/// A note as the rules find it, before [`Notes::observe`] numbers it.
struct Found {
    kind: NoteKind,
    session_id: String,
    call: Option<u64>,
    message: String,
}
