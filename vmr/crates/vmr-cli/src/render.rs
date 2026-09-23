//! Human renderings: the verification report (docs/dev/phase4.md §3.5,
//! docs/dev/phase5.md §5).
// ============================================================================
//  render.rs — text for a terminal, built only from what the report holds
//
//  The report is the whole answer (phase4.md §3.4); this module prints
//  nothing it does not contain. Every record- or trust-store-derived
//  string goes through display_safe on its way out: an issuer_name
//  carrying ANSI escapes must not repaint the screen with a fake "valid"
//  line. (The report's own `detail` strings are escaped by the verifier.)
//
//  On a pass the issuer shown is the TRUST STORE's (its id and its name for
//  that issuer). A record's own claims appear only after a failure, under
//  "Claims (not verified)".
//
//  The policy is TWO statements, and they are never merged (P6-13). The
//  "Policy status" line is the ISSUER's declaration: its status, its pack,
//  as of its own evaluation time. With --policy-pack a second line, "Policy
//  check", is what THIS verifier found, naming the pack and its pack
//  version and saying whether the pack's own authority signature was
//  checked. When the two disagree, a line at column 0 says so, off the
//  field grid, because it is the most interesting thing on the screen.
//  Without --policy-pack the "Policy status" line is exactly C6's: the
//  declaration, and "not evaluated".
//
//  Bounded too (QA P5-05): every value shown is at most VALUE_MAX_CHARS
//  characters, cut before it is escaped and marked with its whole length
//  (shown_value), and a list is shown in part: one record of 1 MB can no
//  longer flood a terminal. --json is the report, whole.
// ============================================================================

use crate::clock::TimeSource;
use crate::names::TOOL;
use vmr_verify::display_safe;
use vmr_verify::policy::{PackSignatureState, PolicyRuleResult, PolicyRuleStatus, PolicyStatus};
use vmr_verify::report::{EvaluationState, LineageReport, LineageStatus, PolicyReport, Verdict};
use vmr_verify::VerificationReport;

/// The most characters of one value a human rendering shows (QA P5-05).
/// Every id, hash, key id and timestamp of a valid record is far shorter;
/// a name or a description longer than this is cut.
pub const VALUE_MAX_CHARS: usize = 200;

/// What a pack's disclaimer is cut at ([`shown_disclaimer`]): enough that no
/// disclaimer written to be read ever reaches it, and still a bound on a file
/// this tool did not write.
pub const DISCLAIMER_MAX_CHARS: usize = 2_000;

/// The most state components, or base models, `inspect` lists (a record in
/// the engine profile has three components; a general one lists its files).
pub(crate) const COMPONENTS_SHOWN: usize = 8;

/// The most rules a policy evaluation lists — and it lists only the ones
/// that did NOT pass. A pack may hold many; one screen is the budget here,
/// as it is for every other list (QA P5-05).
const RULES_SHOWN: usize = 8;

/// A record-, trust-store- or manifest-derived value as a human rendering
/// shows it: at most [`VALUE_MAX_CHARS`] characters, cut first and made
/// `display_safe` second (so an escape is never cut in half), and, when it
/// was cut, marked with the value's whole length: `…[250000 characters in
/// all]`.
pub fn shown_value(v: &str) -> String {
    shown_upto(v, VALUE_MAX_CHARS)
}

/// A pack's disclaimer as a human rendering shows it. It is the line that
/// limits what the pack's authority claims - that it is not legal advice,
/// that the body it cites has not endorsed it - so cutting it at
/// [`VALUE_MAX_CHARS`] while printing every claim in full would be the wrong
/// way round (the owner, 2026-09-23). It is still bounded: the pack is
/// another party's file, and its schema sets no length, so a hostile pack
/// could otherwise flood the terminal. Every real disclaimer is far shorter
/// than this; the five reference packs are under 400 characters.
pub fn shown_disclaimer(v: &str) -> String {
    shown_upto(v, DISCLAIMER_MAX_CHARS)
}

fn shown_upto(v: &str, max: usize) -> String {
    match v.char_indices().nth(max) {
        None => display_safe(v),
        Some((at, _)) => format!(
            "{}…[{} characters in all]",
            display_safe(v.get(..at).unwrap_or_default()),
            v.chars().count()
        ),
    }
}

/// The first line of a passing verification.
pub const VALID_HEADLINE: &str = "✓ Record valid — signed by a key the trust store trusts for this issuer";
/// The start of the first line of a failing verification.
pub const NOT_VALID_HEADLINE: &str = "✗ Record NOT valid — ";

/// Width of a field label ("Policy status: ") in a rendering.
const LABEL: usize = 15;

fn field(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!("  {:<LABEL$}{value}\n", format!("{label}:")));
}

/// A further line of the field above it, aligned under that field's value.
fn continuation(out: &mut String, text: &str) {
    out.push_str(&format!("  {:<LABEL$}{text}\n", ""));
}

fn claim(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!("    {:<13}{value}\n", format!("{label}:")));
}

/// `1 key`, `2 keys`.
pub fn plural(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// The label of a record's `learned_state_hash` (QA QC-02): in the engine
/// profile it is the hash of the state, "Model state"; in the general
/// description, the digest of the components the issuer chose (spec §7.1,
/// §7.3, §7.4). The model itself is named by `model_hash`, on its own line.
pub(crate) fn learned_state_label(model_format: &str) -> &'static str {
    if model_format == vmr_record::validate::KHALM_ENGINE_PROFILE {
        "Model state"
    } else {
        "Components"
    }
}

/// A verification report for a human, given where its evaluation time came
/// from.
pub fn verification(report: &VerificationReport, time: TimeSource) -> String {
    let s = shown_value;
    let mut out = String::new();
    match (report.verdict, &report.failure) {
        (Verdict::Pass, _) => {
            out.push_str(VALID_HEADLINE);
            out.push('\n');
            if let Some(issuer) = &report.issuer {
                field(
                    &mut out,
                    "Issuer",
                    &format!("{} ({}, per trust store)", s(&issuer.issuer_id), s(&issuer.issuer_name)),
                );
                let level = report.record.as_ref().map_or(issuer.attestation_level.as_str(), |p| p.attestation_level.as_str());
                field(&mut out, "Key", &format!("{} ({})", s(&issuer.key_id), s(level)));
            }
            if let Some(p) = &report.record {
                field(&mut out, "Record", &format!("{}, issued {}", s(&p.record_id), s(&p.issued_at)));
                field(&mut out, "Model", &format!("{} ({})", s(&p.model_hash), s(&p.model_format)));
                field(&mut out, learned_state_label(&p.model_format), &s(&p.learned_state_hash));
                // Task 10.11b: "" is a record that commits to no training
                // records (spec §8.4), never a digest to show.
                if p.training_input_digest.is_empty() {
                    field(&mut out, "Training data", "none committed (not disclosed, or not held by the issuer)");
                } else {
                    field(&mut out, "Training data", &s(&p.training_input_digest));
                }
            }
            field(&mut out, "Policy status", &policy_line(&report.policy));
            policy_check(&mut out, &report.policy);
            if let Some(lineage) = &report.lineage {
                field(&mut out, "Lineage chain", &lineage_line(lineage));
            }
            if !report.accepted {
                field(&mut out, "Accepted", &accepted_line(&report.policy.evaluation));
            }
        }
        (Verdict::Fail, failure) => {
            out.push_str(NOT_VALID_HEADLINE);
            match failure {
                Some(f) => out.push_str(&format!("{}: {}\n", f.check, f.detail)),
                None => out.push_str("the verifier gave no reason\n"),
            }
            if let Some(p) = &report.record {
                out.push_str("  Claims (not verified):\n");
                claim(&mut out, "Record", &format!("{}, issued {}", s(&p.record_id), s(&p.issued_at)));
                claim(&mut out, "Issuer", &format!("{} (\"{}\")", s(&p.issuer_id), s(&p.issuer_name)));
                claim(&mut out, "Model", &format!("{} ({})", s(&p.model_hash), s(&p.model_format)));
                claim(&mut out, learned_state_label(&p.model_format), &s(&p.learned_state_hash));
            }
        }
    }
    field(&mut out, "Checked at", &format!("{} {}", report.evaluation_time, time.label()));
    field(
        &mut out,
        "Trust store",
        &format!(
            "{} ({}, {})",
            report.trust_store.sha256,
            plural(report.trust_store.issuer_count, "issuer", "issuers"),
            plural(report.trust_store.key_count, "key", "keys")
        ),
    );
    // The authority store a pack's signature was checked against, printed as
    // the trust store is (P6-16). Without --authority-store, the trust store
    // above held the authorities.
    if let EvaluationState::Evaluated { authority_store: Some(a), .. } = &report.policy.evaluation {
        field(
            &mut out,
            "Authorities",
            &format!(
                "{} ({}, {})",
                a.sha256,
                plural(a.authority_count, "authority", "authorities"),
                plural(a.key_count, "key", "keys")
            ),
        );
    }
    out
}

pub(crate) fn policy_status(s: PolicyStatus) -> &'static str {
    match s {
        PolicyStatus::Compliant => "compliant",
        PolicyStatus::NonCompliant => "non-compliant",
        PolicyStatus::Indeterminate => "indeterminate",
    }
}

/// One rule's word: the three a record's own `policy_compliance.results[]`
/// uses, so a declared result and an evaluated one read alike.
fn rule_status(s: PolicyRuleStatus) -> &'static str {
    match s {
        PolicyRuleStatus::Pass => "pass",
        PolicyRuleStatus::Fail => "fail",
        PolicyRuleStatus::Indeterminate => "indeterminate",
    }
}

/// The "Policy status" line: the ISSUER's declaration, and nothing else.
/// Without an evaluation it is C6's line word for word — the declaration and
/// "not evaluated". With one it says what the declaration is ABOUT (its pack
/// and its own evaluation time), because a second line then says what this
/// verifier found and the two must not read as one statement.
fn policy_line(policy: &PolicyReport) -> String {
    let (declared, pack) = match &policy.declared {
        Some(d) => (
            format!("\"{}\", declared by the issuer", shown_value(&d.overall_status)),
            shown_value(&d.policy_pack_id),
        ),
        None => ("nothing declared".to_string(), String::new()),
    };
    match (&policy.evaluation, &policy.declared) {
        (EvaluationState::NotRequested, _) => format!("{declared}, not evaluated ({pack})"),
        (EvaluationState::Skipped { reason }, _) => format!("{declared}; not evaluated: {reason}"),
        (EvaluationState::Evaluated { .. }, Some(d)) => format!(
            "\"{}\" for {pack} as of {}, declared by the issuer",
            shown_value(&d.overall_status),
            shown_value(&d.evaluated_at)
        ),
        (EvaluationState::Evaluated { .. }, None) => declared,
        (EvaluationState::EvaluatorPanicked { policy_pack_id }, _) => {
            format!("{declared}; the evaluation against {} failed", shown_value(policy_pack_id))
        }
    }
}

/// Whether the pack that decided carried its authority's signature, and what
/// checking it found — never one read as the other (P6-13, P6-16). `store`
/// is where the authorities came from: "trust store" or "authority store".
/// A `not_checked` key id is only what the pack names: no policy authority
/// in that store holds the key, so nothing checked that it signed. A `valid`
/// signature names the authority as the store knows it. A signature that
/// fails is no line at all: that pack was refused before anything was
/// verified.
fn pack_signature_line(state: &PackSignatureState, store: &str) -> String {
    match state {
        PackSignatureState::Unsigned => {
            "pack signature: none, the pack carries no authority signature".to_string()
        }
        PackSignatureState::NotChecked { signing_key_id } => format!(
            "pack signature: names {} as its signer — NOT checked: no policy authority in the {store} holds that key",
            shown_value(signing_key_id)
        ),
        PackSignatureState::Valid { signing_key_id, authority_id, authority_name } => format!(
            "pack signature: valid — signed by {}, a key the {store} trusts for policy authority {} ({})",
            shown_value(signing_key_id),
            shown_value(authority_id),
            shown_value(authority_name)
        ),
    }
}

/// The one line that says what a pack result is: its author's reading of the
/// text it cites, applied to this record's declarations. Printed once, in
/// both the plain report and the rich screen, wherever a pack result is
/// (the owner, 2026-09-16). `--json` carries no such line: a machine reader
/// takes the document.
pub(crate) const PACK_READING_NOTE: &str =
    "the pack author's reading of the cited text — docs/POLICY_PACKS.md says what it does not mean";

/// The "Policy check" block: what THIS verifier found, against which pack.
/// Nothing is written when no evaluation was requested, when one was skipped
/// or when a panicking evaluator was contained — those stay on the
/// declaration line above, where they always were.
fn policy_check(out: &mut String, policy: &PolicyReport) {
    let EvaluationState::Evaluated {
        policy_pack_id,
        policy_pack_version,
        policy_pack_payload_hash,
        pack_signature,
        authority_store,
        status,
        rules,
        detail,
    } = &policy.evaluation
    else {
        return;
    };
    let found = policy_status(*status);
    field(
        out,
        "Policy check",
        &format!(
            "{found} — evaluated here against pack {} {}",
            shown_value(policy_pack_id),
            shown_value(policy_pack_version)
        ),
    );
    // The one line a reader must not be able to skip: the issuer said one
    // thing about a pack and this evaluation found another about the same
    // pack. Off the field grid on purpose. Statuses about two different
    // packs answer different questions, so they get the note below and no
    // such line (QA Q6-08, the owner's option (a)).
    if let Some(d) = &policy.declared {
        if d.overall_status != found && d.policy_pack_id == *policy_pack_id {
            out.push_str(&format!(
                "!! DISAGREEMENT — the issuer declared \"{}\" ({}); this evaluation found \"{found}\" ({})\n",
                shown_value(&d.overall_status),
                shown_value(&d.policy_pack_id),
                shown_value(policy_pack_id)
            ));
        }
    }
    // The verifier's own note, e.g. that the declaration is about another
    // pack, so the two statements answer different questions.
    if let Some(note) = detail {
        continuation(out, &format!("note: {}", shown_value(note)));
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
    continuation(
        out,
        &format!("{}: {}", plural(rules.len() as u64, "rule", "rules"), counts.join(", ")),
    );
    let store = if authority_store.is_some() { "authority store" } else { "trust store" };
    continuation(out, &pack_signature_line(pack_signature, store));
    // What a gate pins, signed or not (P6-16).
    continuation(out, &format!("pack payload hash: {}", shown_value(policy_pack_payload_hash)));
    // The owner, 2026-09-16: one line, once, where a pack result is printed.
    // A pack is an authority's reading of a document, and a result is that
    // reading applied — never the document's own verdict.
    continuation(out, PACK_READING_NOTE);
    // Only the rules that did not pass: they are why the overall status is
    // what it is, and a pack whose every rule passed has nothing to add.
    let undecided: Vec<&PolicyRuleResult> =
        rules.iter().filter(|r| r.status != PolicyRuleStatus::Pass).collect();
    for r in undecided.iter().take(RULES_SHOWN) {
        continuation(
            out,
            &format!(
                "{:<14}{} ({}, {}): {}",
                rule_status(r.status),
                shown_value(&r.rule_id),
                shown_value(&r.severity),
                shown_value(&r.reference),
                shown_value(&r.detail)
            ),
        );
    }
    let hidden = undecided.len().saturating_sub(RULES_SHOWN);
    if hidden > 0 {
        continuation(out, &format!("({hidden} more rule(s) that did not pass, not shown)"));
    }
}

/// Why the record was not accepted, in the words of the reason it was not.
/// An indeterminate evaluation gets its own: "could not be decided" is not
/// acceptance, and must not read as a failure of the record either
/// (P6-13).
pub(crate) fn accepted_line(evaluation: &EvaluationState) -> String {
    match evaluation {
        EvaluationState::Evaluated { status: PolicyStatus::NonCompliant, .. } => {
            "no: the evaluation found the record non-compliant".to_string()
        }
        EvaluationState::Evaluated { status: PolicyStatus::Indeterminate, .. } => {
            "no: the evaluation could not be decided — \"indeterminate\" is not acceptance".to_string()
        }
        _ => "no: the policy evaluation did not accept the record".to_string(),
    }
}

// ---------------------------------------------------------------------------
//  Inspect: a record's claims, labelled as claims
// ---------------------------------------------------------------------------

/// The first line of every inspection.
pub const UNVERIFIED_BANNER: &str =
    "UNVERIFIED — the record's own claims; nothing here was checked against a trust store.";

/// Width of a field label ("Training input: ") in an inspection.
const INSPECT_LABEL: usize = 16;

fn inspect_field(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!("  {:<INSPECT_LABEL$}{value}\n", format!("{label}:")));
}

/// Every section of a record, for `record inspect`. `file` is the path
/// as it should be shown; `bytes` the file's content.
pub fn inspection(p: &vmr_record::Record, form: crate::inspect_cmd::Form, file: &str, bytes: &[u8]) -> String {
    let s = shown_value;
    let hash = vmr_record::hash::format_hash(&vmr_record::hash::sha256(bytes));
    let mut out = String::new();
    out.push_str(UNVERIFIED_BANNER);
    out.push('\n');
    out.push_str(&format!("  To verify it: {TOOL} record verify --record <FILE> --trust-store <FILE>\n"));
    inspect_field(&mut out, "File", &format!("{file} ({} form, {} bytes, {hash})", form.label(), bytes.len()));
    inspect_field(&mut out, "Record", &format!("{} (format version {})", s(&p.record_id), s(&p.record_version)));
    inspect_field(&mut out, "Issued at", &s(&p.issued_at));
    inspect_field(
        &mut out,
        "Issuer",
        &format!(
            "{} (\"{}\"), attestation level {}",
            s(&p.issuer.issuer_id),
            s(&p.issuer.issuer_name),
            s(&p.issuer.attestation_level)
        ),
    );
    inspect_field(&mut out, "Signing key", &s(&p.issuer.key_id));

    let m = &p.model_identity;
    // Task 10.11b: a record in the general description (spec §7.3) names its
    // model's files by model_hash and its components by their named-set
    // digest; the engine profile's record reads as it always did.
    let general = p.model_description() == vmr_record::validate::ModelDescription::General;
    // QA QB-09: parameter_count is optional in the general description, and
    // inspect checks nothing, so a profile record can lack it too.
    let not_stated = || "parameters not stated".to_string();
    if general {
        let parameters = m.parameter_count.map_or_else(not_stated, |n| format!("{n} parameters, as the issuer states"));
        inspect_field(&mut out, "Model", &format!("{} ({}, {parameters})", s(&m.model_hash), s(&m.model_format)));
        inspect_field(&mut out, "Model state", &format!("{} (the components' named-set digest)", s(&m.learned_state_hash)));
    } else {
        let parameters = m.parameter_count.map_or_else(not_stated, |n| format!("{n} parameters"));
        inspect_field(&mut out, "Model state", &format!("{} ({}, {parameters})", s(&m.learned_state_hash), s(&m.model_format)));
    }
    for (i, c) in m.learned_state_components.iter().take(COMPONENTS_SHOWN).enumerate() {
        let label = if i == 0 { "Components" } else { "" };
        let value = format!("{} {} bytes {}", s(&c.name), c.size_bytes, s(&c.hash));
        if label.is_empty() {
            out.push_str(&format!("  {:<INSPECT_LABEL$}{value}\n", ""));
        } else {
            inspect_field(&mut out, label, &value);
        }
    }
    let hidden = m.learned_state_components.len().saturating_sub(COMPONENTS_SHOWN);
    if hidden > 0 {
        out.push_str(&format!("  {:<INSPECT_LABEL$}({hidden} more components, not shown)\n", ""));
    }
    if let Some(bases) = &m.derived_from {
        for (i, b) in bases.iter().take(COMPONENTS_SHOWN).enumerate() {
            let value = format!("{} of {} (\"{}\")", s(&b.relation), s(&b.model_hash), s(&b.name));
            if i == 0 {
                inspect_field(&mut out, "Derived from", &value);
            } else {
                out.push_str(&format!("  {:<INSPECT_LABEL$}{value}\n", ""));
            }
        }
        let hidden = bases.len().saturating_sub(COMPONENTS_SHOWN);
        if hidden > 0 {
            out.push_str(&format!("  {:<INSPECT_LABEL$}({hidden} more base models, not shown)\n", ""));
        }
    }
    // Task 10.11e (D11e-6): other signed statements the record names, never
    // as checked. Inspect reads nothing but the record, as verify does.
    if let Some(references) = &m.statement_references {
        for (i, r) in references.iter().take(COMPONENTS_SHOWN).enumerate() {
            let value = format!(
                "{} {} (a signed statement about the model, by digest: declared, not checked)",
                s(&r.format),
                s(&r.digest)
            );
            if i == 0 {
                inspect_field(&mut out, "Statement ref", &value);
            } else {
                out.push_str(&format!("  {:<INSPECT_LABEL$}{value}\n", ""));
            }
        }
        let hidden = references.len().saturating_sub(COMPONENTS_SHOWN);
        if hidden > 0 {
            out.push_str(&format!("  {:<INSPECT_LABEL$}({hidden} more statement references, not shown)\n", ""));
        }
    }

    let l = &p.learning_provenance;
    let committed = match l.training_input_disclosure.as_deref() {
        None => s(&l.training_input_digest),
        Some("not-held") => "none committed: not held by the issuer".to_string(),
        Some("not-disclosed") => "none committed: not disclosed by the issuer".to_string(),
        Some(other) => format!("none committed: {}", s(other)),
    };
    let (one, many) = if general { ("record", "records") } else { ("frame", "frames") };
    // QA QB-07: both times absent read as one "times not stated"; a record
    // that states either reads as before.
    let times = match (l.training_started_at.as_deref(), l.training_ended_at.as_deref()) {
        (None, None) => "times not stated".to_string(),
        (started, ended) => format!(
            "{} to {}",
            started.map_or_else(|| "not stated".to_string(), s),
            ended.map_or_else(|| "not stated".to_string(), s)
        ),
    };
    inspect_field(
        &mut out,
        "Training input",
        &format!(
            "{} ({}, {}, {times})",
            committed,
            plural(l.training_input_count, one, many),
            l.training_epochs.map_or_else(|| "epochs not stated".to_string(), |e| plural(e, "epoch", "epochs")),
        ),
    );
    if let Some(format) = &l.training_input_format {
        inspect_field(&mut out, "Record format", &s(format));
    }
    inspect_field(
        &mut out,
        "Merkle root",
        &if l.training_input_merkle_root.is_empty() { "none".to_string() } else { s(&l.training_input_merkle_root) },
    );
    let src = &l.training_input_provenance;
    inspect_field(
        &mut out,
        "Training data",
        &format!(
            "{}, residency {}, {}: \"{}\"",
            // QA QB-07: an empty source_type is a source not stated.
            if src.source_type.is_empty() { "source not stated".to_string() } else { s(&src.source_type) },
            match (&src.data_residency, &src.data_residency_countries) {
                (Some(country), _) => s(country),
                (None, Some(countries)) => s(&countries.join(", ")),
                (None, None) => "not stated".to_string(),
            },
            src.collection_period
                .as_ref()
                .map_or_else(|| "collection period not stated".to_string(), |p| format!("collected {} to {}", s(&p.start), s(&p.end))),
            s(&src.source_description)
        ),
    );
    let env = &l.training_environment;
    // QA QB-07: the accelerator software only when the record states it
    // (spec §8.5), so a record names no vendor it did not. Task 10.12a: the
    // members' general names, for any model's training software.
    let mut environment = format!("training software {}", or_none(&env.training_software));
    if let Some(software) = &env.accelerator_software {
        environment.push_str(&format!(", accelerator software {}", or_none(software)));
    }
    environment.push_str(&format!(
        ", hardware {}, TEE {}, software {}",
        or_none(&env.hardware_id),
        or_none(&env.tee_measurement),
        or_none(&env.software_hash)
    ));
    if let Some(accelerator) = &env.accelerator {
        environment.push_str(&format!(", accelerator {}", or_none(accelerator)));
    }
    inspect_field(&mut out, "Environment", &environment);

    match &p.deployment_context {
        Some(d) => {
            let egress = if d.inference_boundary.egress_allowed {
                format!(
                    "egress allowed to {}",
                    plural(d.inference_boundary.allowed_egress_destinations.len() as u64, "destination", "destinations")
                )
            } else {
                "egress not allowed".to_string()
            };
            inspect_field(
                &mut out,
                "Deployment",
                &format!(
                    "{} by {} at {}; boundary {}, {egress}",
                    s(&d.deployment_id),
                    s(&d.deployed_by),
                    s(&d.deployed_at),
                    s(&d.inference_boundary.kind)
                ),
            );
        }
        None => inspect_field(&mut out, "Deployment", "none stated"),
    }

    let pc = &p.policy_compliance;
    let passes = pc.results.iter().filter(|r| r.status == "pass").count() as u64;
    inspect_field(
        &mut out,
        "Policy",
        &format!(
            "\"{}\" for {} ({}, {} pass), as of {}: declared by the issuer, not evaluated",
            s(&pc.overall_status),
            s(&pc.policy_pack_id),
            plural(pc.results.len() as u64, "rule result", "rule results"),
            passes,
            s(&pc.evaluated_at)
        ),
    );

    let ln = &p.lineage;
    let mut lineage = format!(
        "{}, chain length {}, root {}",
        s(&ln.lineage_type),
        ln.lineage_chain_length,
        s(&ln.root_record_id)
    );
    if let (Some(id), Some(hash)) = (&ln.previous_record_id, &ln.previous_record_hash) {
        lineage.push_str(&format!("; previous {} ({})", s(id), s(hash)));
    }
    inspect_field(&mut out, "Lineage", &lineage);
    // Task 10.11a (D11-3): the optional documentation members, only when the
    // record carries them, and never as checked: a hash names a document,
    // nothing here reads one, and inspect applies no value rule.
    for (label, subject, member) in [
        ("Governance doc", "data governance", &p.data_governance),
        ("Oversight doc", "human oversight", &p.human_oversight),
    ] {
        if let Some(d) = member {
            inspect_field(
                &mut out,
                label,
                &format!("{} ({subject} documentation, by hash: declared, not checked)", s(&d.documentation_hash)),
            );
        }
    }
    inspect_field(
        &mut out,
        "Signature",
        &format!(
            "{} by {}, payload hash {} (as the record states them; not checked)",
            s(&p.signature.algorithm),
            s(&p.signature.signing_key_id),
            s(&p.signature.signed_payload_hash)
        ),
    );
    out
}

/// An optional field's value, or `none` for the empty string.
pub(crate) fn or_none(v: &str) -> String {
    if v.is_empty() {
        "none".into()
    } else {
        shown_value(v)
    }
}

/// An error reason quoting untrusted text (a parser message naming a
/// member, say): at most 320 characters, terminal-safe.
pub fn bounded(reason: &str) -> String {
    const MAX: usize = 320;
    let mut cut: String = reason.chars().take(MAX).collect();
    if cut.len() < reason.len() {
        cut.push('…');
    }
    display_safe(&cut)
}

/// The lineage line: how much of the declared chain was verified.
pub(crate) fn lineage_line(l: &LineageReport) -> String {
    let declared = l.declared_chain_length;
    match l.status {
        LineageStatus::Initial => "1 record (initial)".into(),
        LineageStatus::Complete => format!("{declared} records, verified back to the initial record"),
        LineageStatus::Partial => format!(
            "{declared} records declared; {} verified, the rest not supplied - not verified to the initial record",
            plural(l.verified_links.len() as u64, "predecessor link", "predecessor links")
        ),
        LineageStatus::NotChecked => format!(
            "{declared} records declared ({}); no predecessor supplied - not verified",
            shown_value(&l.lineage_type)
        ),
        LineageStatus::Broken => "broken".into(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mutate::{mutate, repo_file, terminal_safe, Lcg};
    use vmr_record::timestamp::Timestamp;
    use vmr_verify::{TrustStore, Verifier, VerifyOptions};

    /// The committed record vector, JSON form.
    pub fn vector_json() -> Vec<u8> {
        let doc: serde_json::Value =
            serde_json::from_slice(&repo_file("specs/test-vectors/record/example-v0.1.json")).unwrap();
        serde_json::to_vec_pretty(&doc["record"]).unwrap()
    }

    #[test]
    fn renderings_of_mutated_records_never_panic_and_are_terminal_safe() {
        // Law 9 and R6: 4 000 stacked mutations of the vector's two forms,
        // verified and rendered. The escaped-control inserts keep many of
        // them valid JSON, so the "Claims (not verified)" rendering of
        // attacker-chosen strings is reached, not only parse failures.
        let store = TrustStore::from_json(&repo_file("specs/test-vectors/verify/trust-stores/ts-basic.json")).unwrap();
        let verifier = Verifier::new(store);
        let opts = VerifyOptions::new(Timestamp::parse("2026-09-11T00:00:00Z").unwrap());
        let json = vector_json();
        let cose = vmr_record::Record::from_json(std::str::from_utf8(&json).unwrap()).unwrap().to_cose().unwrap();
        let mut rng = Lcg::new(0x5EED_5005);
        let mut claims = 0;
        for seed in [&json, &cose] {
            let mut current = seed.clone();
            for i in 0..2000 {
                if i % 8 == 0 {
                    current = seed.clone();
                }
                current = mutate(&mut rng, &current);
                let report = verifier.verify(&current, &opts);
                let out = verification(&report, TimeSource::Argument("--at"));
                assert!(terminal_safe(&out), "{out}");
                match report.verdict {
                    Verdict::Pass => assert!(out.starts_with(VALID_HEADLINE)),
                    Verdict::Fail => assert!(out.starts_with(NOT_VALID_HEADLINE)),
                }
                if out.contains("Claims (not verified):") {
                    claims += 1;
                }
            }
        }
        assert!(claims > 100, "the harness reaches the claims rendering ({claims} times)");
    }

    #[test]
    fn a_disclaimer_is_shown_whole_and_still_bounded() {
        // The line that limits a pack authority's claims is not cut at a
        // value's 200 characters: the five reference packs are under 400 and
        // must read whole. A pack is another party's file, though, and its
        // schema sets no length, so the bound stays - a hostile one is cut
        // and says how long it was, as any other value would be.
        let real = "A reference implementation of the VMR policy-pack format, not legal advice and not an \
                    official instrument. The clause references are this pack author's reading of the cited \
                    text; the European Union, the European AI Office and the national market surveillance \
                    authorities have neither authored nor endorsed this pack.";
        assert!(real.chars().count() > VALUE_MAX_CHARS, "the case is a disclaimer a value would cut");
        assert_eq!(shown_disclaimer(real), real, "shown whole");
        let hostile = "x".repeat(DISCLAIMER_MAX_CHARS + 1);
        assert_eq!(
            shown_disclaimer(&hostile),
            format!("{}…[{} characters in all]", "x".repeat(DISCLAIMER_MAX_CHARS), DISCLAIMER_MAX_CHARS + 1)
        );
    }

    #[test]
    fn a_shown_value_is_cut_before_it_is_escaped_and_says_how_long_it_was() {
        // Short values are display_safe's, unchanged.
        assert_eq!(shown_value("New Clark City Fab Operator"), "New Clark City Fab Operator");
        assert_eq!(shown_value("a\u{1b}b\\c"), "a\\u{001b}b\\\\c");
        let exactly = "y".repeat(VALUE_MAX_CHARS);
        assert_eq!(shown_value(&exactly), exactly);
        // One character more: cut, marked with the whole length.
        assert_eq!(shown_value(&format!("{exactly}z")), format!("{exactly}…[201 characters in all]"));
        // Characters are counted before escaping, so an escape is whole.
        let escapes = "\u{202e}".repeat(1000);
        assert_eq!(shown_value(&escapes), format!("{}…[1000 characters in all]", "\\u{202e}".repeat(VALUE_MAX_CHARS)));
        assert!(terminal_safe(&shown_value(&"\u{e0041}".repeat(250_000))));
    }

    #[test]
    fn bounded_reasons_are_short_and_terminal_safe() {
        let long = "x".repeat(1000) + "\u{1b}[2J";
        let b = bounded(&long);
        assert!(b.chars().count() <= 321 && b.ends_with('…'), "{b}");
        assert!(terminal_safe(&bounded("a\u{1b}b\u{202e}c\rd")));
    }
}
