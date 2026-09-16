//! The screens a person sees at a terminal (docs/dev/cli-polish.md CP-3):
//! the tool's help and version, `record verify`, `record inspect`,
//! `key generate`, `key export`, `trust-store add`, and errors.
// ============================================================================
//  screens.rs — what render.rs says, drawn with rich.rs
//
//  The same report, the same record and the same escaping as the plain text
//  (render.rs): every value from a record, a trust store, a pack or a file
//  passes through shown_value, shown or escape_controls before it becomes a
//  span, so a span's text is always terminal-safe. The meaning is render.rs's
//  where it matters. The issuer's declaration and this verifier's evaluation
//  are two rows, never merged; a disagreement about the same pack is called
//  out; "compliant" never stands without its pack and the mandatory-rules
//  qualifier; green is only for what this verifier checked and passed; every
//  badge and mark carries its word; a verified record the evaluation did not
//  accept says NOT ACCEPTED beside VALID. Values are never shortened but a
//  checked key id's fixed prefix (record inspect shows every value as the
//  record states it), and lists are bounded as the plain text's are (QA
//  P5-05), except that a rule that did not pass is never left off (QA QP-01).
// ============================================================================

use crate::clock::TimeSource;
use crate::inspect_cmd::Form;
use crate::render::{
    accepted_line, learned_state_label, lineage_line, or_none, plural, policy_status, shown_value, COMPONENTS_SHOWN,
    PACK_READING_NOTE,
};
use crate::names::{RECORD_EXTENSION, TOOL};
use crate::rich::{
    banner, grid, header, human_size, paragraph, plain, row, sections, styled, table, width, Block, Grid, Line, Row,
    Span, Style,
};
use vmr_record::jwk::KEY_ID_PREFIX;
use vmr_verify::policy::{PackSignatureState, PolicyRuleStatus, PolicyStatus};
use vmr_verify::report::{EvaluationState, PolicyReport, Verdict};
use vmr_verify::VerificationReport;

/// The most rules a policy screen lists (a pack may hold many; a screen is
/// bounded as every list is).
const RULES_SHOWN: usize = 32;

fn p(text: impl Into<String>) -> Span {
    plain(text)
}

fn st(text: impl Into<String>, style: Style) -> Span {
    styled(text, style)
}

/// A value of one plain line.
fn one(text: impl Into<String>) -> Vec<Line> {
    vec![vec![p(text)]]
}

/// A key id as a screen of a checked or a made key shows it: escaped, without
/// the prefix every key id carries (the plain text and --json keep the whole
/// id, CP-5). `record inspect` checks nothing, so it shows a record's key ids
/// whole, as the record states them (QA QP-04).
fn key(id: &str) -> String {
    let shown = shown_value(id);
    match shown.strip_prefix(KEY_ID_PREFIX) {
        Some(thumbprint) => thumbprint.to_string(),
        None => shown,
    }
}

/// A key id as a record states it, for `record inspect`: whole and escaped
/// (QA QP-04). A thumbprint URN is drawn as its fixed prefix on one line and
/// its thumbprint on the next, so that no line breaks inside the thumbprint
/// and it can be read and copied whole; any other id as it is.
fn stated_key(id: &str) -> Vec<Line> {
    let shown = shown_value(id);
    match shown.strip_prefix(KEY_ID_PREFIX) {
        Some(thumbprint) => vec![vec![p(KEY_ID_PREFIX)], vec![p(thumbprint)]],
        None => one(shown),
    }
}

/// A pass: its mark in a span of its own, the one --ascii redraws, then its
/// word (QA QP-11).
fn passed(word: &str) -> Line {
    vec![st("√", Style::OkMark), st(format!(" {word}"), Style::Ok)]
}

/// A failure: its mark in a span of its own, then its word.
fn failed(word: &str) -> Line {
    vec![st("×", Style::FailMark), st(format!(" {word}"), Style::Fail)]
}

/// An undecided result: an ASCII mark and its word.
fn undecided(word: &str) -> Line {
    vec![st(format!("? {word}"), Style::Caution)]
}

/// Badges in a banner, one a row, the words after them starting in one
/// column.
fn badge_rows(badges: Vec<(Span, String)>) -> Vec<Line> {
    let column = badges.iter().map(|(badge, _)| width(&badge.text)).max().unwrap_or(0);
    badges
        .into_iter()
        .map(|(badge, words)| {
            let gap = " ".repeat(3 + column.saturating_sub(width(&badge.text)));
            vec![p(" "), badge, p(format!("{gap}{words}"))]
        })
        .collect()
}

/// What a declaration adds to its status: a declared "compliant" is always
/// read as the pack's mandatory rules passing, in the issuer's words.
fn declaration_qualifier(status: &str) -> &'static str {
    if status == "compliant" {
        "its mandatory rules pass, as the issuer declares"
    } else {
        "as the issuer declares"
    }
}

// ---------------------------------------------------------------------------
//  record verify
// ---------------------------------------------------------------------------

/// A verification report, drawn.
pub fn verification(report: &VerificationReport, time: TimeSource) -> Vec<Line> {
    let s = shown_value;
    let mut out = header("record verify");
    if let Verdict::Fail = report.verdict {
        out.extend(failure(report, time));
        return out;
    }
    let mut badges = vec![(st(" √ VALID ", Style::BadgeOk), "Signed by a key your trust store trusts for this issuer".to_string())];
    if !report.accepted {
        // QA QP-03, approved by the owner on 2026-09-15: a genuine record
        // the evaluation did not accept (exit 4) says so beside VALID.
        let indeterminate =
            matches!(report.policy.evaluation, EvaluationState::Evaluated { status: PolicyStatus::Indeterminate, .. });
        let badge =
            if indeterminate { st(" ? NOT ACCEPTED ", Style::BadgeCaution) } else { st(" × NOT ACCEPTED ", Style::BadgeFail) };
        let line = accepted_line(&report.policy.evaluation);
        badges.push((badge, line.strip_prefix("no: ").unwrap_or(&line).to_string()));
    }
    let mut rows = vec![Vec::new()];
    rows.extend(badge_rows(badges));
    rows.push(Vec::new());
    out.extend(banner(&rows));
    let mut blocks = Vec::new();
    if let Some(issuer) = &report.issuer {
        let level = report.record.as_ref().map_or(issuer.attestation_level.as_str(), |r| r.attestation_level.as_str());
        blocks.push(Block::Rows(vec![
            row(
                "Issuer",
                vec![
                    vec![p(s(&issuer.issuer_id))],
                    vec![p(s(&issuer.issuer_name)), st(" · your trust store's name for it", Style::Dim)],
                ],
            ),
            row("Signing key", vec![vec![p(key(&issuer.key_id)), st(format!(" · {} attestation", s(level)), Style::Dim)]]),
        ]));
    }
    if let Some(r) = &report.record {
        let mut rows = vec![
            row("Record", one(s(&r.record_id))),
            row("Issued", one(s(&r.issued_at))),
            row("Model", vec![vec![p(s(&r.model_hash))], vec![st(format!("model format {}", s(&r.model_format)), Style::Dim)]]),
            row(learned_state_label(&r.model_format), one(s(&r.learned_state_hash))),
            row(
                "Training data",
                if r.training_input_digest.is_empty() {
                    one("none committed: not disclosed, or not held by the issuer")
                } else {
                    one(s(&r.training_input_digest))
                },
            ),
        ];
        if let Some(lineage) = &report.lineage {
            rows.push(row("Lineage", one(lineage_line(lineage))));
        }
        blocks.push(Block::Rows(rows));
    }
    let evaluated = matches!(report.policy.evaluation, EvaluationState::Evaluated { .. });
    if !evaluated {
        blocks.push(Block::Rows(vec![declared_row(&report.policy)]));
    }
    out.extend(table(&blocks));

    let mut closing = Vec::new();
    if let EvaluationState::Evaluated { policy_pack_payload_hash, pack_signature, authority_store, status, .. } =
        &report.policy.evaluation
    {
        out.extend(evaluation(&report.policy));
        let store = if authority_store.is_some() { "authority store" } else { "trust store" };
        closing.push(Block::Rows(vec![
            row("Pack signature", signature(pack_signature, store)),
            row(
                "Pack payload",
                vec![
                    vec![p(s(policy_pack_payload_hash))],
                    vec![st("the payload hash names the exact text of the pack that was applied", Style::Dim)],
                ],
            ),
            // The owner, 2026-09-16: the same one line the plain report
            // carries, once, beside the pack result.
            row("Pack reading", vec![vec![st(PACK_READING_NOTE, Style::Dim)]]),
        ]));
        if !report.accepted {
            let style = if *status == PolicyStatus::Indeterminate { Style::Caution } else { Style::Fail };
            closing.push(Block::Rows(vec![row("Accepted", vec![vec![st(accepted_line(&report.policy.evaluation), style)]])]));
        }
    } else if !report.accepted {
        closing.push(Block::Rows(vec![row("Accepted", vec![vec![st(accepted_line(&report.policy.evaluation), Style::Fail)]])]));
    }
    closing.push(Block::Rows(checked(report, time)));
    out.push(Vec::new());
    out.extend(table(&closing));
    out
}

/// A failed verification: the check, the verifier's reason, and what the
/// record claims, labelled as not verified.
fn failure(report: &VerificationReport, time: TimeSource) -> Vec<Line> {
    let s = shown_value;
    let (check, reason) = match &report.failure {
        Some(f) => (f.check.to_string(), f.detail.to_string()),
        None => ("none".to_string(), "the verifier gave no reason".to_string()),
    };
    let mut out = banner(&[
        Vec::new(),
        vec![p(" "), st(" × NOT VALID ", Style::BadgeFail), p(format!("   Check {check} failed"))],
        Vec::new(),
    ]);
    let mut blocks = vec![Block::Rows(vec![row("Failed check", vec![vec![st(check, Style::Fail)]]), row("Reason", one(reason))])];
    if let Some(r) = &report.record {
        blocks.push(Block::Heading(vec![st(" NOT VERIFIED ", Style::BadgeCaution), st("  What the record claims", Style::Bold)]));
        blocks.push(Block::Rows(vec![
            row("Record", one(s(&r.record_id))),
            row("Issued", one(s(&r.issued_at))),
            row("Issuer", vec![vec![p(s(&r.issuer_id))], vec![p(format!("\"{}\"", s(&r.issuer_name)))]]),
            row("Model", vec![vec![p(s(&r.model_hash))], vec![st(format!("model format {}", s(&r.model_format)), Style::Dim)]]),
            row(learned_state_label(&r.model_format), one(s(&r.learned_state_hash))),
        ]));
    }
    blocks.push(Block::Rows(checked(report, time)));
    out.extend(table(&blocks));
    out
}

/// The issuer's declaration when nothing was evaluated here.
fn declared_row(policy: &PolicyReport) -> Row {
    let s = shown_value;
    let Some(d) = &policy.declared else {
        return row("Policy", one("nothing declared"));
    };
    let mut lines = vec![vec![
        st(" DECLARED ", Style::BadgeCaution),
        p(format!("  \"{}\" for {}", s(&d.overall_status), s(&d.policy_pack_id))),
    ]];
    let qualifier = declaration_qualifier(&d.overall_status);
    match &policy.evaluation {
        EvaluationState::Skipped { reason } => {
            lines.push(vec![st(qualifier, Style::Note)]);
            lines.push(vec![st(format!("not evaluated: {reason}"), Style::Note)]);
        }
        EvaluationState::EvaluatorPanicked { policy_pack_id } => {
            lines.push(vec![st(qualifier, Style::Note)]);
            lines.push(vec![st(format!("the evaluation against {} failed", s(policy_pack_id)), Style::Fail)]);
        }
        _ => lines.push(vec![st(format!("{qualifier}; not evaluated here"), Style::Note)]),
    }
    row("Policy", lines)
}

/// The issuer's declaration and this verifier's evaluation, side by side and
/// never merged, then every rule the evaluation applied.
fn evaluation(policy: &PolicyReport) -> Vec<Line> {
    let s = shown_value;
    let EvaluationState::Evaluated { policy_pack_id, policy_pack_version, status, rules, detail, .. } = &policy.evaluation
    else {
        return Vec::new();
    };
    let mut out = vec![Vec::new(), vec![p("  "), st("Policy", Style::Bold)]];
    let declared = match &policy.declared {
        Some(d) => vec![
            vec![vec![st("Declared", Style::Dim)]],
            vec![vec![st(format!("\"{}\"", s(&d.overall_status)), Style::Note)]],
            // The pack, then what the status means, then when: the
            // qualifier stays on the line under the status, whatever the
            // pack id's length (a pack id and an evaluation time on one
            // line no longer fit the column since the reference packs were
            // renamed, 2026-09-16).
            vec![
                vec![p(s(&d.policy_pack_id))],
                vec![st(declaration_qualifier(&d.overall_status), Style::Dim)],
                vec![st(format!("as of {}", s(&d.evaluated_at)), Style::Dim)],
            ],
        ],
        None => vec![vec![vec![st("Declared", Style::Dim)]], vec![vec![st("nothing", Style::Dim)]], one("the record declares no evaluation")],
    };
    let (result, why) = match status {
        PolicyStatus::Compliant => (passed("compliant"), "its mandatory rules pass"),
        PolicyStatus::NonCompliant => (failed("non-compliant"), "a mandatory rule failed"),
        PolicyStatus::Indeterminate => (undecided("indeterminate"), "a mandatory rule could not be decided"),
    };
    let evaluated = vec![
        vec![vec![st("Evaluated here", Style::Dim)]],
        vec![result],
        vec![vec![p(format!("{} {}", s(policy_pack_id), s(policy_pack_version)))], vec![st(why, Style::Dim)]],
    ];
    out.extend(grid(&Grid {
        headers: vec!["Statement".into(), "Result".into(), "Policy pack".into()],
        widths: vec![16, 15, 53],
        right: vec![false; 3],
        rows: vec![declared, evaluated],
    }));
    let found = policy_status(*status);
    if let Some(d) = &policy.declared {
        if d.overall_status != found && d.policy_pack_id == *policy_pack_id {
            out.extend(paragraph(
                &[
                    p("  "),
                    st(" DISAGREEMENT ", Style::BadgeFail),
                    p(format!(
                        "  the issuer declared \"{}\" ({}); this evaluation found \"{found}\" ({}). Only mandatory rules decide either status",
                        s(&d.overall_status),
                        s(&d.policy_pack_id),
                        s(policy_pack_id)
                    )),
                ],
                17,
            ));
        }
    }
    if let Some(note) = detail {
        out.extend(paragraph(&[p("  "), st("Note", Style::Note), p(format!("  {}", s(note)))], 8));
    }

    let count = |want: PolicyRuleStatus| rules.iter().filter(|r| r.status == want).count();
    let counts: Vec<String> = [
        (count(PolicyRuleStatus::Pass), "pass"),
        (count(PolicyRuleStatus::Fail), "fail"),
        (count(PolicyRuleStatus::Indeterminate), "indeterminate"),
    ]
    .iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, word)| format!("{n} {word}"))
    .collect();
    out.push(Vec::new());
    out.push(vec![
        p("  "),
        st("Rules", Style::Bold),
        st(
            format!(
                "   {} {} · {}: {}",
                s(policy_pack_id),
                s(policy_pack_version),
                plural(rules.len() as u64, "rule", "rules"),
                counts.join(", ")
            ),
            Style::Dim,
        ),
    ]);
    // QA QP-01: the rules that did not pass come first and are never left
    // off, so the rules that decided the result are on the screen with their
    // reasons; passes fill the rest of RULES_SHOWN, in the pack's order.
    let not_passed: Vec<_> = rules.iter().filter(|r| r.status != PolicyRuleStatus::Pass).collect();
    let room = RULES_SHOWN.saturating_sub(not_passed.len());
    let shown = not_passed.into_iter().chain(rules.iter().filter(|r| r.status == PolicyRuleStatus::Pass).take(room));
    let mut rows: Vec<Vec<Vec<Line>>> = shown
        .map(|r| {
            let result = match r.status {
                PolicyRuleStatus::Pass => passed("pass"),
                PolicyRuleStatus::Fail => failed("fail"),
                PolicyRuleStatus::Indeterminate => undecided("indeterminate"),
            };
            let mut rule = vec![vec![p(s(&r.rule_id))], vec![st(s(&r.reference), Style::Dim)]];
            if r.status != PolicyRuleStatus::Pass {
                let detail_style = if r.status == PolicyRuleStatus::Fail { Style::Fail } else { Style::Note };
                rule.push(vec![st(s(&r.detail), detail_style)]);
            }
            vec![vec![result], rule, one(s(&r.severity))]
        })
        .collect();
    let hidden = rules.len().saturating_sub(rows.len());
    if hidden > 0 {
        let (noun, all) = if hidden == 1 { ("rule", "it") } else { ("rules", "all") };
        rows.push(vec![
            Vec::new(),
            vec![vec![st(format!("… {hidden} more {noun}, {all} passed, not shown"), Style::Dim)]],
            Vec::new(),
        ]);
    }
    if !rows.is_empty() {
        out.extend(grid(&Grid {
            headers: vec!["Result".into(), "Rule".into(), "Severity".into()],
            widths: vec![15, 58, 11],
            right: vec![false; 3],
            rows,
        }));
    }
    out.push(vec![
        p("  "),
        st("Only mandatory rules decide the result; the others are listed for information.", Style::Dim),
    ]);
    out
}

/// Whether the pack carried its authority's signature, and what checking it
/// found: never one read as the other (P6-16).
fn signature(state: &PackSignatureState, store: &str) -> Vec<Line> {
    let s = shown_value;
    match state {
        PackSignatureState::Unsigned => vec![vec![st("none", Style::Note), p(" · the pack carries no authority signature")]],
        PackSignatureState::NotChecked { signing_key_id } => vec![
            vec![st("NOT checked", Style::Caution), p(format!(" · the pack names {} as its signer", key(signing_key_id)))],
            vec![st(format!("no policy authority in the {store} holds that key"), Style::Dim)],
        ],
        PackSignatureState::Valid { signing_key_id, authority_id, authority_name } => vec![
            [passed("valid"), vec![p(format!(" · signed by {}", key(signing_key_id)))]].concat(),
            vec![p(format!("a key the {store} trusts for policy authority {} ({})", s(authority_id), s(authority_name)))],
        ],
    }
}

/// When the record was checked, and against what.
fn checked(report: &VerificationReport, time: TimeSource) -> Vec<Row> {
    let mut rows = vec![
        row(
            "Checked at",
            vec![vec![p(report.evaluation_time.to_string()), st(format!(" · {}", time.rich_label()), Style::Dim)]],
        ),
        row(
            "Trust store",
            vec![
                vec![p(report.trust_store.sha256.to_string())],
                vec![st(
                    format!(
                        "{} · {}",
                        plural(report.trust_store.issuer_count, "issuer", "issuers"),
                        plural(report.trust_store.key_count, "key", "keys")
                    ),
                    Style::Dim,
                )],
            ],
        ),
    ];
    if let EvaluationState::Evaluated { authority_store: Some(a), .. } = &report.policy.evaluation {
        rows.push(row(
            "Authorities",
            vec![
                vec![p(a.sha256.to_string())],
                vec![st(
                    format!(
                        "{} · {}",
                        plural(a.authority_count, "authority", "authorities"),
                        plural(a.key_count, "key", "keys")
                    ),
                    Style::Dim,
                )],
            ],
        ));
    }
    rows
}

// ---------------------------------------------------------------------------
//  record inspect
// ---------------------------------------------------------------------------

/// A record's claims, drawn under an UNVERIFIED banner. `file` is the path as
/// it is shown; `bytes` the file's content.
pub fn inspection(record: &vmr_record::Record, form: Form, file: &str, bytes: &[u8]) -> Vec<Line> {
    let s = shown_value;
    let hash = vmr_record::hash::format_hash(&vmr_record::hash::sha256(bytes));
    let mut out = header("record inspect");
    out.extend(banner(&[
        Vec::new(),
        vec![
            p(" "),
            st(" UNVERIFIED ", Style::BadgeCaution),
            p("   The record's own claims. Nothing here was checked against a trust store."),
        ],
        vec![p(" ".repeat(16)), st("To check it  ", Style::Dim), p(format!("{TOOL} record verify --record <FILE> --trust-store <FILE>"))],
        Vec::new(),
    ]));

    let issuer = &record.issuer;
    let about = vec![
        row("File", vec![vec![p(format!("{file} · {} form · {} bytes", form.label(), bytes.len()))], vec![st(hash, Style::Dim)]]),
        row("Record", one(format!("{} · format {}", s(&record.record_id), s(&record.record_version)))),
        row("Issued", one(s(&record.issued_at))),
        row(
            "Issuer",
            vec![
                vec![p(format!("{} · attestation {}", s(&issuer.issuer_id), s(&issuer.attestation_level)))],
                vec![p(format!("\"{}\"", s(&issuer.issuer_name)))],
            ],
        ),
        row("Signing key", stated_key(&issuer.key_id)),
    ];

    let m = &record.model_identity;
    let general = record.model_description() == vmr_record::validate::ModelDescription::General;
    let not_stated = || "parameters not stated".to_string();
    let mut model = Vec::new();
    if general {
        let parameters = m.parameter_count.map_or_else(not_stated, |n| format!("{n} parameters, as the issuer states"));
        model.push(row("Model hash", one(s(&m.model_hash))));
        model.push(row("Format", one(format!("\"{}\" · {parameters}", s(&m.model_format)))));
        model.push(row(
            "Model state",
            vec![vec![p(s(&m.learned_state_hash))], vec![st("the components' named-set digest", Style::Dim)]],
        ));
    } else {
        let parameters = m.parameter_count.map_or_else(not_stated, |n| format!("{n} parameters"));
        model.push(row("Model state", one(s(&m.learned_state_hash))));
        model.push(row("Format", one(format!("{} · {parameters}", s(&m.model_format)))));
    }
    let bases = m.derived_from.as_deref().unwrap_or_default();
    for (i, b) in bases.iter().take(COMPONENTS_SHOWN).enumerate() {
        model.push(row(
            if i == 0 { "Derived from" } else { "" },
            vec![vec![p(format!("{} of {}", s(&b.relation), s(&b.model_hash)))], vec![p(format!("\"{}\"", s(&b.name)))]],
        ));
    }
    let hidden = bases.len().saturating_sub(COMPONENTS_SHOWN);
    if hidden > 0 {
        model.push(row("", one(format!("… {hidden} more base models, not shown"))));
    }
    let references = m.statement_references.as_deref().unwrap_or_default();
    for (i, r) in references.iter().take(COMPONENTS_SHOWN).enumerate() {
        model.push(row(
            if i == 0 { "Statement ref" } else { "" },
            vec![
                vec![p(format!("{} {}", s(&r.format), s(&r.digest)))],
                vec![st("a signed statement about the model, by digest: declared, not checked", Style::Note)],
            ],
        ));
    }
    let hidden = references.len().saturating_sub(COMPONENTS_SHOWN);
    if hidden > 0 {
        model.push(row("", one(format!("… {hidden} more statement references, not shown"))));
    }
    out.extend(table(&[Block::Rows(about), Block::Rows(model)]));

    let components = &m.learned_state_components;
    out.push(Vec::new());
    out.push(vec![
        p("  "),
        st("Components", Style::Bold),
        st(format!("   {}", plural(components.len() as u64, "component", "components")), Style::Dim),
    ]);
    let mut rows: Vec<Vec<Vec<Line>>> = components
        .iter()
        .take(COMPONENTS_SHOWN)
        .map(|c| {
            vec![
                vec![vec![p(s(&c.name))], vec![st(s(&c.hash), Style::Dim)]],
                vec![vec![p(human_size(c.size_bytes))], vec![st(format!("{} B", c.size_bytes), Style::Dim)]],
            ]
        })
        .collect();
    let hidden = components.len().saturating_sub(COMPONENTS_SHOWN);
    if hidden > 0 {
        rows.push(vec![vec![vec![st(format!("… {hidden} more components, not shown"), Style::Dim)]], Vec::new()]);
    }
    out.extend(grid(&Grid { headers: vec!["Name and SHA-256".into(), "Size".into()], widths: vec![76, 11], right: vec![false, true], rows }));

    out.push(Vec::new());
    out.extend(table(&[
        Block::Rows(training(record, general)),
        Block::Rows(context(record)),
        Block::Heading(vec![st(" NOT CHECKED ", Style::BadgeCaution), st("  The signature, as the record states it", Style::Bold)]),
        Block::Rows(vec![
            row("Algorithm", one(s(&record.signature.algorithm))),
            row("Signing key", stated_key(&record.signature.signing_key_id)),
            row("Payload hash", one(s(&record.signature.signed_payload_hash))),
        ]),
    ]));
    out
}

/// A record's training, as it states it.
fn training(record: &vmr_record::Record, general: bool) -> Vec<Row> {
    let s = shown_value;
    let l = &record.learning_provenance;
    let committed = match l.training_input_disclosure.as_deref() {
        None => s(&l.training_input_digest),
        Some("not-held") => "none committed: not held by the issuer".to_string(),
        Some("not-disclosed") => "none committed: not disclosed by the issuer".to_string(),
        Some(other) => format!("none committed: {}", s(other)),
    };
    let (one_item, many) = if general { ("record", "records") } else { ("frame", "frames") };
    let times = match (l.training_started_at.as_deref(), l.training_ended_at.as_deref()) {
        (None, None) => "times not stated".to_string(),
        (started, ended) => format!(
            "{} to {}",
            started.map_or_else(|| "not stated".to_string(), s),
            ended.map_or_else(|| "not stated".to_string(), s)
        ),
    };
    let epochs = l.training_epochs.map_or_else(|| "epochs not stated".to_string(), |e| plural(e, "epoch", "epochs"));
    let mut rows = vec![row(
        "Training input",
        vec![vec![p(committed)], vec![st(format!("{} · {epochs} · {times}", plural(l.training_input_count, one_item, many)), Style::Dim)]],
    )];
    if let Some(format) = &l.training_input_format {
        rows.push(row("Record format", one(s(format))));
    }
    rows.push(row(
        "Merkle root",
        one(if l.training_input_merkle_root.is_empty() { "none".to_string() } else { s(&l.training_input_merkle_root) }),
    ));
    let src = &l.training_input_provenance;
    let source = if src.source_type.is_empty() { "source not stated".to_string() } else { s(&src.source_type) };
    let residency = match (&src.data_residency, &src.data_residency_countries) {
        (Some(country), _) => s(country),
        (None, Some(countries)) => s(&countries.join(", ")),
        (None, None) => "not stated".to_string(),
    };
    let collected = src
        .collection_period
        .as_ref()
        .map_or_else(|| "collection period not stated".to_string(), |c| format!("collected {} to {}", s(&c.start), s(&c.end)));
    rows.push(row(
        "Training data",
        vec![vec![p(format!("{source} · residency {residency} · {collected}"))], vec![p(format!("\"{}\"", s(&src.source_description)))]],
    ));
    let env = &l.training_environment;
    let mut environment = format!("training software {}", or_none(&env.training_software));
    if let Some(software) = &env.accelerator_software {
        environment.push_str(&format!(" · accelerator software {}", or_none(software)));
    }
    environment.push_str(&format!(
        " · hardware {} · TEE {} · software {}",
        or_none(&env.hardware_id),
        or_none(&env.tee_measurement),
        or_none(&env.software_hash)
    ));
    if let Some(accelerator) = &env.accelerator {
        environment.push_str(&format!(" · accelerator {}", or_none(accelerator)));
    }
    rows.push(row("Environment", one(environment)));
    rows
}

/// A record's deployment, declared policy, lineage and documents.
fn context(record: &vmr_record::Record) -> Vec<Row> {
    let s = shown_value;
    let mut rows = Vec::new();
    rows.push(match &record.deployment_context {
        Some(d) => {
            let egress = if d.inference_boundary.egress_allowed {
                format!(
                    "egress allowed to {}",
                    plural(d.inference_boundary.allowed_egress_destinations.len() as u64, "destination", "destinations")
                )
            } else {
                "egress not allowed".to_string()
            };
            row(
                "Deployment",
                vec![
                    vec![p(format!("{} by {}", s(&d.deployment_id), s(&d.deployed_by)))],
                    vec![p(format!("at {} · boundary {} · {egress}", s(&d.deployed_at), s(&d.inference_boundary.kind)))],
                ],
            )
        }
        None => row("Deployment", one("none stated")),
    });
    let pc = &record.policy_compliance;
    let passes = pc.results.iter().filter(|r| r.status == "pass").count() as u64;
    rows.push(row(
        "Policy",
        vec![
            vec![st(" DECLARED ", Style::BadgeCaution), p(format!("  \"{}\" for {}", s(&pc.overall_status), s(&pc.policy_pack_id)))],
            vec![st(format!("{}; not evaluated", declaration_qualifier(&pc.overall_status)), Style::Note)],
            vec![st(
                format!(
                    "as of {} · {}, {passes} pass",
                    s(&pc.evaluated_at),
                    plural(pc.results.len() as u64, "rule result", "rule results")
                ),
                Style::Dim,
            )],
        ],
    ));
    let ln = &record.lineage;
    let mut lineage = vec![vec![p(format!("{} · chain length {}", s(&ln.lineage_type), ln.lineage_chain_length))], vec![p(format!("root {}", s(&ln.root_record_id)))]];
    if let (Some(id), Some(hash)) = (&ln.previous_record_id, &ln.previous_record_hash) {
        lineage.push(vec![p(format!("previous {} ({})", s(id), s(hash)))]);
    }
    rows.push(row("Lineage", lineage));
    for (label, subject, member) in [
        ("Governance doc", "data governance", &record.data_governance),
        ("Oversight doc", "human oversight", &record.human_oversight),
    ] {
        if let Some(d) = member {
            rows.push(row(
                label,
                vec![
                    vec![p(s(&d.documentation_hash))],
                    vec![st(format!("{subject} documentation, by hash: declared, not checked"), Style::Note)],
                ],
            ));
        }
    }
    rows
}

// ---------------------------------------------------------------------------
//  key generate, key export, trust-store add
// ---------------------------------------------------------------------------

/// A new signing key. `file` is its path as shown; `permissions` the
/// Windows note, when there is one.
pub fn key_generated(key_id: &str, file: &str, permissions: Option<&str>) -> Vec<Line> {
    let mut out = header("key generate");
    out.extend(banner(&[vec![p(" "), st(" KEY CREATED ", Style::BadgeNeutral), p(format!("   {}", key(key_id)))]]));
    let mut rows = vec![row(
        "Private key",
        vec![
            vec![p(format!("{file} · PKCS#8 PEM · P-256 · not encrypted"))],
            vec![st(format!("keep it secret: {TOOL} never prints it"), Style::Note)],
        ],
    )];
    if let Some(note) = permissions {
        let lines = match note.split_once("run: ") {
            Some((before, command)) => vec![vec![p(format!("{before}run:"))], vec![st(command, Style::Bold)]],
            None => one(note),
        };
        rows.push(row("Permissions", lines));
    }
    out.extend(table(&[Block::Rows(rows)]));
    out.push(Vec::new());
    out.extend(paragraph(
        &[p("  "), st("Next", Style::Hint), p(format!("  {TOOL} key export --key <FILE> --output <FILE>"))],
        8,
    ));
    out
}

/// A public key file written. `file` is its path as shown.
pub fn key_exported(key_id: &str, file: &str) -> Vec<Line> {
    let mut out = header("key export");
    out.extend(banner(&[vec![
        p(" "),
        st(" EXPORTED ", Style::BadgeNeutral),
        p(format!("   {file} · the public key only, no private key material")),
    ]]));
    out.push(vec![p("  "), st("Key id", Style::Dim), p(format!("  {}", key(key_id)))]);
    out.extend(paragraph(
        &[
            p("  "),
            st("Next", Style::Hint),
            p(format!("    send {file} to your verifiers, and confirm this key id with them by a second channel")),
        ],
        10,
    ));
    out
}

/// What `trust-store add` decided and wrote.
pub struct TrustDecision<'a> {
    /// The key trusted (a checked thumbprint URN).
    pub key_id: &'a str,
    /// The DID it may sign for.
    pub issuer_id: &'a str,
    /// The operator's name for the issuer.
    pub issuer_name: &'a str,
    /// The highest attestation level it may declare.
    pub level: &'a str,
    /// When it may sign.
    pub window: &'a str,
    /// The store's path, as shown.
    pub store: &'a str,
    /// Whether the store was created.
    pub created: bool,
    /// Issuers in the store now.
    pub issuers: u64,
    /// Keys in the store now.
    pub keys: u64,
    /// The store's canonical hash.
    pub sha256: String,
}

/// A key trusted for an issuer.
pub fn trusted(t: &TrustDecision<'_>) -> Vec<Line> {
    let s = shown_value;
    let mut out = header("trust-store add");
    out.extend(banner(&[vec![
        p(" "),
        st(" TRUSTED ", Style::BadgeNeutral),
        p(format!("   {} for {}", key(t.key_id), s(t.issuer_id))),
    ]]));
    out.extend(table(&[Block::Rows(vec![
        row("For issuer", vec![vec![p(s(t.issuer_id))], vec![p(s(t.issuer_name)), st(" · the name you gave", Style::Dim)]]),
        row("Attestation", one(format!("up to {}", t.level))),
        row("May sign", one(t.window)),
        row(
            "Trust store",
            vec![
                vec![p(format!(
                    "{} · {} · {} · {}",
                    t.store,
                    if t.created { "created" } else { "updated" },
                    plural(t.issuers, "issuer", "issuers"),
                    plural(t.keys, "key", "keys")
                ))],
                vec![st(t.sha256.clone(), Style::Dim)],
            ],
        ),
    ])]));
    out
}

// ---------------------------------------------------------------------------
//  Errors
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
//  model hash, record emit
// ---------------------------------------------------------------------------

/// Every file of a model: its name, readable size and SHA-256, the hash's
/// first 12 hex digits unless `full` (CP-5). A shortened table ends with a
/// note naming `whole`, the options that show each hash whole.
pub fn file_table(files: &vmr_builder::general::FileSet, full: bool, whole: &str) -> Vec<Line> {
    let hexes: Vec<String> = files
        .entries()
        .iter()
        .map(|e| {
            let hash = vmr_record::hash::format_hash(&e.digest);
            hash.strip_prefix("sha256:").unwrap_or(&hash).to_string()
        })
        .collect();
    // QA QPB-06: two files whose hashes begin alike are never drawn alike.
    // Each hash is shown to one digit past the longest start it shares with
    // any other (found by sorting), and to 12 digits at least.
    let mut sorted: Vec<&str> = hexes.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let shared = |a: &str, b: &str| a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count();
    let shown_digits = |hex: &str| {
        let at = sorted.binary_search(&hex).unwrap_or(0);
        let before = at.checked_sub(1).and_then(|i| sorted.get(i)).map_or(0, |other| shared(hex, other));
        let after = sorted.get(at + 1).map_or(0, |other| shared(hex, other));
        (before.max(after) + 1).clamp(12, hex.len())
    };
    let rows: Vec<Vec<Vec<Line>>> = files
        .entries()
        .iter()
        .zip(&hexes)
        .map(|(e, hex)| {
            let name = vmr_verify::display_safe(&e.name).to_string();
            let size = one(human_size(e.size_bytes));
            if full {
                vec![vec![vec![p(name)], vec![st(format!("sha256:{hex}"), Style::Dim)]], size]
            } else {
                vec![one(name), size, one(format!("{}\u{2026}", hex.get(..shown_digits(hex)).unwrap_or(hex)))]
            }
        })
        .collect();
    if full {
        return grid(&Grid {
            headers: vec!["File and SHA-256".into(), "Size".into()],
            widths: vec![76, 11],
            right: vec![false, true],
            rows,
        });
    }
    let mut out = grid(&Grid {
        headers: vec!["File".into(), "Size".into(), "SHA-256".into()],
        widths: vec![58, 10, 16],
        right: vec![false, true, false],
        rows,
    });
    out.extend(paragraph(
        &[p("  "), st(format!("Hashes shortened, longer where two begin alike; {whole} shows them whole."), Style::Dim)],
        2,
    ));
    out
}

/// `model hash`, drawn (CP-3): a MODEL HASH banner with the whole model_hash,
/// the file count and size and where the files were read, then every file.
pub fn model_hash(files: &vmr_builder::general::FileSet, path: &std::path::Path, full: bool) -> Vec<Line> {
    let mut out = header("model hash");
    let badge = st(" MODEL HASH ", Style::BadgeNeutral);
    let under = " ".repeat(1 + width(&badge.text) + 3);
    let detail = format!(
        "{} · {} ({} bytes) · read from {}",
        plural(files.len() as u64, "file", "files"),
        human_size(files.total_bytes()),
        files.total_bytes(),
        crate::files::shown(path)
    );
    let mut rows = vec![Vec::new(), vec![p(" "), badge, p("   "), p(vmr_record::hash::format_hash(&files.named_set_digest()))]];
    // QA QPB-13: a long detail wraps under its own indent, not at the frame.
    for part in crate::rich::fit(&[st(detail, Style::Dim)], crate::rich::INNER.saturating_sub(under.len())) {
        let mut line = vec![p(under.clone())];
        line.extend(part);
        rows.push(line);
    }
    rows.push(Vec::new());
    out.extend(banner(&rows));
    out.push(Vec::new());
    out.extend(file_table(files, full, "--full or --json"));
    out
}

/// How a record just signed was written, for its screen (CP-3).
pub struct Written<'a> {
    /// The record.
    pub record: &'a vmr_record::Record,
    /// Where it was written, as given.
    pub output: &'a std::path::Path,
    /// Its form: `COSE_Sign1` or `JSON`.
    pub form: &'a str,
    /// Its size in bytes.
    pub size: usize,
    /// Whether its id was derived from its content (else --record-id gave it).
    pub derived_id: bool,
    /// Where its issued_at came from.
    pub time: TimeSource,
}

/// An issuer's statement in a table: the DECLARED badge, then `text`.
pub fn declared(text: impl Into<String>) -> Line {
    vec![st(" DECLARED ", Style::BadgeCaution), p(format!("  {}", text.into()))]
}

/// A record just signed, drawn (CP-3, CP-4, CP-11): SIGNED as a neutral badge,
/// never green; the record, its time and its key; the issuer's statements
/// under DECLARED, with `model`, this build's rows about the model, among
/// them; `files`, already drawn; and the next steps, naming `<FILE>`.
pub fn emitted(w: &Written<'_>, model: Vec<Row>, files: Vec<Line>) -> Vec<Line> {
    let s = shown_value;
    let r = w.record;
    let output = crate::files::shown(w.output);
    let mut out = header("record emit");
    out.extend(banner(&[
        Vec::new(),
        vec![p(" "), st(" SIGNED ", Style::BadgeNeutral), p(format!("   Record written to {output} · {} · {} bytes", w.form, w.size))],
        Vec::new(),
    ]));
    let id = if w.derived_id { "id derived from its content" } else { "from --record-id" };
    let about = vec![
        row("Record", vec![vec![p(s(&r.record_id)), st(format!(" · {id}"), Style::Dim)]]),
        row("Issued at", vec![vec![p(s(&r.issued_at)), st(format!(" · {}", w.time.rich_label()), Style::Dim)]]),
        row("Signing key", one(key(&r.issuer.key_id))),
        row(
            "Issuer",
            vec![
                declared(format!("{} · attestation {}", s(&r.issuer.issuer_id), s(&r.issuer.attestation_level))),
                vec![p(format!("\"{}\"", s(&r.issuer.issuer_name)))],
            ],
        ),
    ];
    let pc = &r.policy_compliance;
    let mut statements = model;
    statements.push(row(
        "Policy",
        vec![declared(format!("\"{}\" for {} · not evaluated", s(&pc.overall_status), s(&pc.policy_pack_id)))],
    ));
    statements.push(row(
        "Lineage",
        one(format!("{} · chain length {}", s(&r.lineage.lineage_type), r.lineage.lineage_chain_length)),
    ));
    out.extend(table(&[Block::Rows(about), Block::Rows(statements)]));
    out.extend(files);
    out.push(Vec::new());
    out.push(vec![p("  "), st("Next", Style::Hint)]);
    out.extend(hanging(vec![p("    "), st("1", Style::Hint), p("  ")], &format!("Send {output} to your verifiers")));
    out.extend(hanging(
        vec![p("    "), st("2", Style::Hint), p("  ")],
        &format!("They check it:  {TOOL} record verify --record <FILE> --trust-store <FILE>"),
    ));
    out
}

// ---------------------------------------------------------------------------
//  The tool's help and version
// ---------------------------------------------------------------------------

/// The standard's logo as its artwork draws it (`vmr.svg`): nine squares on an
/// 8x3 grid, each `(column, row)` (CP-3).
const LOGO_SQUARES: [(usize, usize); 9] = [(0, 0), (4, 0), (6, 0), (1, 1), (3, 1), (0, 2), (2, 2), (4, 2), (7, 2)];

/// The widest line the logo and its words take: an 80-column terminal never
/// wraps them, and the screens read no terminal size (CP-8).
const LOGO_COLUMNS: usize = 79;

/// The logo's rows, unchanged: each square four characters wide and two rows
/// tall, which a terminal's cells draw as a square; 32 columns by 6 rows, in
/// the terminal's own text colour.
fn logo() -> Vec<Line> {
    (0..3)
        .flat_map(|r| {
            let row: String =
                (0..8).map(|c| if LOGO_SQUARES.contains(&(c, r)) { "\u{2588}\u{2588}\u{2588}\u{2588}" } else { "    " }).collect();
            let line = vec![p("  "), st(row.trim_end().to_string(), Style::Logo)];
            [line.clone(), line]
        })
        .collect()
}

/// The standard's logo, and below it the standard's name, the tool's name and
/// version as a reference implementation of the standard, the build's words
/// after its version number, and `lines`: every line within [`LOGO_COLUMNS`].
fn wordmark(tree: &clap::Command, lines: &[&str]) -> Vec<Line> {
    let version = tree.get_version().unwrap_or_default();
    let (number, words) = version.split_once(' ').unwrap_or((version, ""));
    // QA QPB-11, D11f-5: both builds' versions carry words now, so a build
    // that extends this tool (the private engine build's) is told apart by
    // comparing its words against the Community build's own, not by whether
    // it has any.
    let caption = if words == crate::cli::REFERENCE_WORDS {
        format!("{TOOL} {number} · a reference implementation of the standard")
    } else {
        format!("{TOOL} {number} · implements the Verifiable Model Record standard")
    };
    let indented = |part: Line| -> Line {
        let mut line = vec![p("  ")];
        line.extend(part);
        line
    };
    let mut out = vec![Vec::new()];
    out.extend(logo());
    out.push(Vec::new());
    out.push(indented(vec![st("Verifiable Model Record", Style::Bold)]));
    out.push(indented(vec![st(caption, Style::Dim)]));
    if !words.is_empty() {
        out.extend(crate::rich::fit(&[st(words, Style::Dim)], LOGO_COLUMNS - 2).into_iter().map(&indented));
    }
    if !lines.is_empty() {
        out.push(Vec::new());
        out.extend(lines.iter().map(|text| indented(vec![p(*text)])));
    }
    out
}

/// The tool's help screen, from `tree`, the command tree this build parses
/// (CP-3, CP-11): the wordmark, the commands grouped in a bordered table,
/// examples, the options and the exit codes.
pub fn help(tree: &clap::Command) -> Vec<Line> {
    let mut out = wordmark(
        tree,
        &[
            "Make, verify and inspect signed records of AI models.",
            "Verifying shows who signed a record and that nothing changed;",
            "it does not show that its claims are true.",
        ],
    );
    out.push(Vec::new());
    let mut groups = Vec::new();
    for (heading, parents) in [("Records", &["record"][..]), ("Models", &["model"][..]), ("Keys and trust", &["key", "trust-store"][..])] {
        let mut rows = Vec::new();
        for parent in parents {
            if let Some(command) = tree.find_subcommand(parent) {
                for sub in command.get_subcommands().filter(|sub| sub.get_name() != "help") {
                    let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
                    rows.push((format!("{parent} {}", sub.get_name()), about));
                }
            }
        }
        if !rows.is_empty() {
            groups.push((heading.to_string(), rows));
        }
    }
    // QA QPB-10: every other command of the tree, as a build adds it, in a
    // section of its own: its subcommands, or itself when it has none.
    let known = ["record", "model", "key", "trust-store", "help"];
    for command in tree.get_subcommands().filter(|c| !known.contains(&c.get_name())) {
        let about = |c: &clap::Command| c.get_about().map(ToString::to_string).unwrap_or_default();
        let subs: Vec<&clap::Command> = command.get_subcommands().filter(|s| s.get_name() != "help").collect();
        let rows = if subs.is_empty() {
            vec![(command.get_name().to_string(), about(command))]
        } else {
            subs.iter().map(|s| (format!("{} {}", command.get_name(), s.get_name()), about(s))).collect()
        };
        groups.push((command.get_name().to_string(), rows));
    }
    out.extend(sections(&groups));
    out.push(Vec::new());
    out.push(vec![p("  "), st("Get started", Style::Bold)]);
    for example in [
        format!("{TOOL} model hash --model my-model"),
        format!("{TOOL} record emit --model my-model --manifest manifest.json --key signer.key --output model.{RECORD_EXTENSION}"),
        format!("{TOOL} record verify --record model.{RECORD_EXTENSION} --trust-store trust-store.json"),
    ] {
        out.extend(hanging(vec![p("    "), st("$ ", Style::Dim)], &example));
    }
    out.push(Vec::new());
    for (label, text) in [
        ("Options", "--color <auto|always|never>    --ascii    -h, --help    -V, --version".to_string()),
        ("Exit", exit_summary(tree)),
        ("More", format!("{TOOL} <command> --help")),
    ] {
        out.extend(hanging(vec![p("  "), st(format!("{label:<10}"), Style::Dim)], &text));
    }
    out
}

/// `text` after `lead` (an indent and a label or a prompt), wrapped to the
/// screen's width, every further line starting under the text's first.
fn hanging(lead: Line, text: &str) -> Vec<Line> {
    let hang = crate::rich::line_width(&lead);
    let parts = crate::rich::fit(&[p(text)], (crate::rich::OUTER + 2).saturating_sub(hang));
    parts
        .into_iter()
        .enumerate()
        .map(|(i, part)| {
            let mut line = if i == 0 { lead.clone() } else { vec![p(" ".repeat(hang))] };
            line.extend(part);
            line
        })
        .collect()
}

/// The tool's version screen (CP-3).
pub fn version(tree: &clap::Command) -> Vec<Line> {
    wordmark(tree, &[])
}

/// The exit codes the table of `tree`'s help lists, each in a few words: the
/// Community build's codes in words of their own, any other code in its
/// table's words.
fn exit_summary(tree: &clap::Command) -> String {
    let table = tree.get_after_help().map(ToString::to_string).unwrap_or_default();
    table
        .lines()
        .filter_map(|line| {
            let (code, words) = line.strip_prefix("  ")?.split_once("  ")?;
            if code.len() != 1 || !code.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let short = match code {
                "0" => "done",
                "1" => "could not run",
                "3" => "not valid",
                "4" => "valid, not accepted by a policy pack",
                _ => words.split(['(', ':', ';']).next().unwrap_or(words).trim(),
            };
            Some(format!("{code} {short}"))
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// A command's error; `message` and `hint` already escaped.
pub fn error(message: &str, hint: Option<&str>) -> Vec<Line> {
    let mut out = paragraph(&[st(" ERROR ", Style::BadgeFail), p(format!("  {message}"))], 9);
    if let Some(hint) = hint {
        out.extend(paragraph(&[st("  hint", Style::Hint), p(format!("   {hint}"))], 9));
    }
    out
}

/// clap's usage error, already escaped, drawn as an error: its first line
/// under the badge, its tip as a hint, the rest under them.
pub fn usage_error(text: &str) -> Vec<Line> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = line.strip_prefix("error: ") {
            out.extend(paragraph(&[st(" ERROR ", Style::BadgeFail), p(format!("  {rest}"))], 9));
        } else if let Some(rest) = trimmed.strip_prefix("tip: ") {
            out.extend(paragraph(&[st("  hint", Style::Hint), p(format!("   {rest}"))], 9));
        } else if !trimmed.is_empty() {
            let style = if trimmed.starts_with("Usage:") || trimmed.starts_with("For more information") {
                Style::Dim
            } else {
                Style::Plain
            };
            out.extend(paragraph(&[p(" ".repeat(9)), st(trimmed, style)], 9));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutate::{mutate, repo_file, terminal_safe, Lcg};
    use crate::rich::{render, strip, width, OUTER};
    use vmr_record::timestamp::Timestamp;
    use vmr_verify::{TrustStore, Verifier, VerifyOptions};

    /// Every frame line of a drawn screen takes the screen's full width.
    fn frames_are_even(text: &str) -> bool {
        text.lines()
            .filter(|l| l.starts_with("  ") && l.chars().nth(2).is_some_and(|c| "│┌├└╭╰".contains(c)))
            .all(|l| width(l) == OUTER + 2)
    }

    #[test]
    fn screens_of_mutated_records_never_panic_and_stay_safe_and_even() {
        // Law 9 and R6, as render.rs's test is for the plain text: stacked
        // mutations of the vector's two forms, verified and inspected, drawn.
        // Without the screens' own sequences the text is terminal-safe, and
        // every frame keeps its width whatever the record says.
        let store = TrustStore::from_json(&repo_file("specs/test-vectors/verify/trust-stores/ts-basic.json")).unwrap();
        let verifier = Verifier::new(store);
        let opts = VerifyOptions::new(Timestamp::parse("2026-09-11T00:00:00Z").unwrap());
        let json = crate::render::tests::vector_json();
        let cose = vmr_record::Record::from_json(std::str::from_utf8(&json).unwrap()).unwrap().to_cose().unwrap();
        let mut rng = Lcg::new(0x5EED_5006);
        let (mut claims, mut inspected) = (0, 0);
        for seed in [&json, &cose] {
            let mut current = seed.clone();
            for i in 0..1000 {
                if i % 8 == 0 {
                    current = seed.clone();
                }
                current = mutate(&mut rng, &current);
                let report = verifier.verify(&current, &opts);
                let text = strip(&render(&verification(&report, TimeSource::Argument("--at")), false));
                assert!(terminal_safe(&text), "{text}");
                assert!(frames_are_even(&text), "{text}");
                if text.contains("NOT VERIFIED") {
                    claims += 1;
                }
                let (record, form) = match vmr_record::Record::from_json(std::str::from_utf8(&current).unwrap_or("")) {
                    Ok(record) => (record, Form::Json),
                    Err(_) => match vmr_record::Record::from_cose(&current) {
                        Ok(record) => (record, Form::Cose),
                        Err(_) => continue,
                    },
                };
                let text = strip(&render(&inspection(&record, form, "'x'", &current), true));
                assert!(terminal_safe(&text), "{text}");
                inspected += 1;
            }
        }
        assert!(claims > 50 && inspected > 50, "the harness reaches the claims ({claims}) and inspections ({inspected})");
    }

    #[test]
    fn compliant_never_stands_without_its_qualifier() {
        for status in ["compliant", "non-compliant", "indeterminate"] {
            let q = declaration_qualifier(status);
            assert!(q.contains("declares"), "{q}");
            assert_eq!(q.contains("mandatory rules"), status == "compliant", "{q}");
        }
    }

    #[test]
    fn a_suggested_command_names_no_path_and_key_ids_are_drawn_as_designed() {
        // QA QP-09: a quoted path pastes back into PowerShell and a POSIX
        // shell but not into cmd.exe, so a suggested command says <FILE>, as
        // the plain text does.
        let text = strip(&render(&key_generated("urn:ietf:params:oauth:jwk-thumbprint:sha-256:abc", "'my.key'", None), false));
        assert!(text.contains(&format!("{TOOL} key export --key <FILE> --output <FILE>")) && !text.contains("--key '"), "{text}");
        // A checked or made key id loses only its prefix.
        assert_eq!(key("urn:ietf:params:oauth:jwk-thumbprint:sha-256:abc"), "abc");
        assert_eq!(key("not-a-urn"), "not-a-urn");
        // QA QP-04: inspect states a key id whole, a thumbprint URN as its
        // prefix and its thumbprint on two lines, any other id as it is.
        assert_eq!(
            stated_key("urn:ietf:params:oauth:jwk-thumbprint:sha-256:abc"),
            vec![vec![p("urn:ietf:params:oauth:jwk-thumbprint:sha-256:")], vec![p("abc")]]
        );
        assert_eq!(stated_key("abc"), one("abc"));
    }

    /// A file set of `entries`: (name, digest, size).
    fn file_set(entries: &[(&str, [u8; 32], u64)]) -> vmr_builder::general::FileSet {
        vmr_builder::general::FileSet::from_entries(
            entries
                .iter()
                .map(|(name, digest, size)| vmr_builder::general::FileEntry {
                    name: name.to_string(),
                    digest: *digest,
                    size_bytes: *size,
                    source: vmr_builder::general::DigestSource::Read { through_link: false },
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn two_files_whose_short_hashes_collide_are_drawn_apart() {
        // QA QPB-06: café.bin in NFC and in NFD render alike; hashes that share
        // their first 12 hex digits must not make their rows alike too.
        let mut first = [0xab_u8; 32];
        let mut second = [0xab_u8; 32];
        first[6] = 0x10;
        second[6] = 0x20;
        let files = file_set(&[("caf\u{e9}.bin", first, 35), ("cafe\u{301}.bin", second, 35)]);
        let text = strip(&render(&file_table(&files, false, "--full"), false));
        assert!(text.contains("abababababab1") && text.contains("abababababab2"), "{text}");
    }

    #[test]
    fn no_screen_string_spells_the_tools_name() {
        // QA QPB-09 (CP-10): a screen's suggested command or sentence takes the
        // tool's name from names.rs.
        let source = include_str!("screens.rs");
        for spelled in [format!("\"{} ", "vmr"), format!("\"  {} ", "vmr"), format!("{} never", "vmr")] {
            assert!(!source.contains(&spelled), "screens.rs spells `{spelled}`");
        }
    }

    #[test]
    fn every_command_of_the_tree_is_on_the_help_screen() {
        // QA QPB-10: a command a build adds to a known group, or a group of its
        // own, is listed as the plain help lists it.
        use clap::CommandFactory;
        let tree = crate::cli::Cli::command()
            .subcommand(
                clap::Command::new("export")
                    .about("Export a verified record")
                    .subcommand(clap::Command::new("cyclonedx").about("As a CycloneDX ML-BOM")),
            )
            .mut_subcommand("record", |r| r.subcommand(clap::Command::new("attest").about("A command a build adds")));
        let text = strip(&render(&help(&tree), false));
        assert!(text.contains("record attest") && text.contains("export cyclonedx"), "{text}");
    }

    /// The standard's logo as the owner drew it (vmr.svg): nine squares on an
    /// 8x3 grid, each four characters wide and two rows tall, `mark` for a square.
    fn logo_rows(mark: &str) -> Vec<String> {
        let cells = [(0, 0), (4, 0), (6, 0), (1, 1), (3, 1), (0, 2), (2, 2), (4, 2), (7, 2)];
        (0..3)
            .flat_map(|r| {
                let row: String = (0..8).map(|c| if cells.contains(&(c, r)) { mark.repeat(4) } else { " ".repeat(4) }).collect();
                let row = format!("  {}", row.trim_end());
                [row.clone(), row]
            })
            .collect()
    }

    /// The command tree with the engine build's version words, the longest words
    /// a build has.
    fn engine_like_tree() -> clap::Command {
        use clap::CommandFactory;
        crate::cli::Cli::command().version(
            "0.1.0 (KHALM-VMR, implements the Verifiable Model Record standard; record format v0.1; \
             engine build: record emit also takes a KHALM engine brain)",
        )
    }

    #[test]
    fn the_help_and_version_screens_draw_the_standards_logo_unchanged() {
        // The owner's logo, never recoloured or stretched: the terminal's own
        // text colour (no sequence on its rows), and ## with --ascii, in every
        // build.
        use clap::CommandFactory;
        for tree in [crate::cli::Cli::command(), engine_like_tree()] {
            for (name, screen) in [("version", version(&tree)), ("help", help(&tree))] {
                let rows = |text: &str| -> Vec<String> { text.lines().skip(1).take(6).map(|l| l.trim_end().to_string()).collect() };
                let drawn = render(&screen, false);
                assert_eq!(rows(&strip(&drawn)), logo_rows("\u{2588}"), "{name}:\n{drawn}");
                assert!(drawn.lines().skip(1).take(6).all(|l| !l.contains('\u{1b}')), "{name}:\n{drawn}");
                assert_eq!(rows(&strip(&render(&screen, true))), logo_rows("#"), "{name} --ascii");
            }
        }
    }

    #[test]
    fn the_logo_and_its_words_fit_an_80_column_terminal() {
        // The screens read no terminal size (CP-8), so the logo, the standard's
        // name, the caption, a build's words and the help's own lines take at
        // most 79 columns: an 80-column terminal never wraps them. The tables
        // below keep the screens' 96 columns, as every other screen does.
        use clap::CommandFactory;
        for tree in [crate::cli::Cli::command(), engine_like_tree()] {
            for screen in [version(&tree), help(&tree)] {
                let text = strip(&render(&screen, false));
                for line in text.lines().take_while(|l| !l.contains('\u{250c}')) {
                    assert!(width(line) <= 79, "{} columns: `{line}`\n{text}", width(line));
                }
            }
        }
    }

    #[test]
    fn a_pass_and_a_failure_are_marked_with_characters_every_console_font_has() {
        assert_eq!(passed("pass")[0].text, "\u{221a}");
        assert_eq!(failed("fail")[0].text, "\u{d7}");
    }

    #[test]
    fn a_long_path_wraps_under_its_own_indent_in_the_model_hash_banner() {
        // QA QPB-13.
        let files = file_set(&[("weights.bin", [7; 32], 3)]);
        let path = format!("model-{}", "x".repeat(120));
        let text = strip(&render(&model_hash(&files, std::path::Path::new(&path), false), false));
        let inside: Vec<&str> = text
            .lines()
            .skip_while(|l| !l.contains('\u{256d}'))
            .skip(1)
            .take_while(|l| !l.contains('\u{2570}'))
            .map(|l| l.trim_start().trim_start_matches('\u{2502}').trim_end().trim_end_matches('\u{2502}'))
            .filter(|l| !l.trim().is_empty() && !l.contains("MODEL HASH"))
            .collect();
        assert!(inside.len() >= 2, "{text}");
        for line in inside {
            assert!(line.starts_with(&" ".repeat(16)) && !line[16..].starts_with(' '), "`{line}` in:\n{text}");
        }
    }
}
