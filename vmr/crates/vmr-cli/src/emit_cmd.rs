//! `vmr record emit` (TASKS 5.2; task 10.13a).
// ============================================================================
//  emit_cmd.rs — a signed record of a model's files out
//
//  A model's files (task 10.13a; docs/dev/task-10.13a.md §3, §12), with no
//  engine:
//    1. the output checked before anything is opened (a device, a directory,
//       one of the inputs - QA P5-02, P5-11 - or a path inside the folders
//       read, whose files it would change);
//    2. the manifest's statements for a model's files checked before any file
//       of the model is read: a model_format that is not a registered profile
//       (task 10.13a, D13a-9), a `model` member, the training given exactly
//       once;
//    3. the key, and the time (--issued-at or now, C2; a future --issued-at
//       refused, QA P5-04);
//    4. the files named and hashed by spec §7.2 (vmr-builder's walk), and the
//       training records' folder, when given;
//    5. the record built and signed by vmr-builder's GeneralBuilder, its id
//       given or derived from its content (C4);
//    6. serialized, refused over the 1 MiB a verifier reads, and the exact
//       bytes run through the verifier under a one-key store at T = issued_at
//       (C11);
//    7. written, with every statement's source said and every name hashed
//       listed (spec §7.2's SHOULD).
//
//  The derived id (C4) and the pre-write verification (C11) are public: a
//  build that adds the KHALM engine profile's input mode, outside this crate,
//  emits that profile's record through them (task 10.13a, D13a-3).
// ============================================================================

use crate::cli::{EmitArgs, FormatArg};
use crate::clock::{self, TimeSource};
use crate::error::CliError;
use crate::files::{self, shown};
use crate::keys;
use crate::manifest::{self, GeneralStatements, Manifest};
use crate::model_cmd;
use crate::output::Output;
use crate::render::{bounded, plural, shown_value};
use p256::ecdsa::SigningKey;
use std::path::{Path, PathBuf};
use crate::progress::StderrBar;
use vmr_builder::files::{read_folder_observed, read_model_observed};
use vmr_builder::general::{DigestSource, FileSet, GeneralBuilder, Training};
use vmr_record::record::{Issuer, JwkPublicKey, Record};
use vmr_record::timestamp::Timestamp;
use vmr_verify::report::Verdict;
use vmr_verify::trust_store::{
    AttestationLevel, IssuerDocument, KeyDocument, TrustStoreDocument, TRUST_STORE_VERSION,
};
use vmr_verify::{TrustStore, Verifier, VerifyOptions, MAX_RECORD_BYTES};

/// Run `record emit`: a record of a model's files, `bar` shown while they
/// are read.
pub fn run(args: &EmitArgs, bar: &mut StderrBar) -> Result<Output, CliError> {
    general(args, bar)
}

/// The placeholder id a draft is built with before its real id is derived
/// from its content (C4).
pub const PLACEHOLDER_ID: &str = "urn:uuid:00000000-0000-8000-8000-000000000000";

/// The default record id (C4): a UUIDv8 (RFC 9562) whose free bits are the
/// first bits of SHA-256("KHALM-VMR record-id v0.1" ‖ 0x00 ‖ payload),
/// `payload` being the canonical signed payload of the record built with
/// [`PLACEHOLDER_ID`]. Same content, same id; any other content (including
/// another issued_at), another id — with no randomness.
pub fn derived_id(unsigned_payload: &[u8]) -> String {
    let mut input = b"KHALM-VMR record-id v0.1\x00".to_vec();
    input.extend_from_slice(unsigned_payload);
    let digest = vmr_record::hash::sha256(&input);
    let mut bytes = [0u8; 16];
    for (dst, src) in bytes.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    if let Some(b) = bytes.get_mut(6) {
        *b = (*b & 0x0f) | 0x80; // version 8
    }
    if let Some(b) = bytes.get_mut(8) {
        *b = (*b & 0x3f) | 0x80; // the RFC 9562 variant, 0b10
    }
    let mut it = bytes.iter();
    let groups: Vec<String> = [4usize, 2, 2, 2, 6]
        .iter()
        .map(|&n| it.by_ref().take(n).map(|b| format!("{b:02x}")).collect())
        .collect();
    format!("urn:uuid:{}", groups.join("-"))
}

/// Where the record id came from.
pub enum IdSource {
    /// Given with --record-id.
    Argument,
    /// Derived from the record's content (C4).
    Derived,
}

/// C11: never write a record that would fail verification at the moment it
/// is written, by a verifier that trusts its key. The exact bytes are verified
/// under a store trusting only the signing key, for the declared issuer at the
/// declared level, from issued_at, at T = issued_at; since issued_at is not
/// after now (QA P5-04) and only time.not_future depends on T, the result is
/// the same at T = now. A pass proves only that the file is well-formed and
/// consistent — trust is the verifier's, with its own store, which also bounds
/// when the key may sign. `what` names the file ("record", "record").
pub fn refuse_unverifiable(bytes: &[u8], p: &Record, key: &SigningKey, what: &str) -> Result<(), CliError> {
    let refuse = |why: String| CliError::input(format!("refusing to write a {what} a verifier would reject: {why}"));
    let jwk = JwkPublicKey::from_verifying_key(key.verifying_key());
    let level = AttestationLevel::parse(&p.issuer.attestation_level)
        .ok_or_else(|| refuse(format!("attestation level {:?} is not a level", p.issuer.attestation_level)))?;
    let store = TrustStore::new(TrustStoreDocument {
        trust_store_version: TRUST_STORE_VERSION.into(),
        issuers: vec![IssuerDocument {
            issuer_id: p.issuer.issuer_id.clone(),
            issuer_name: p.issuer.issuer_name.clone(),
            keys: vec![KeyDocument {
                key_id: jwk.key_id(),
                public_key: jwk,
                attestation_level: level,
                valid_from: p.issued_at.clone(),
                valid_until: None,
                revoked: false,
            }],
        }],
        policy_authorities: Vec::new(),
    })
    .map_err(|e| refuse(e.to_string()))?;
    let at = Timestamp::parse(&p.issued_at).map_err(|v| refuse(v.to_string()))?;
    let report = Verifier::new(store).verify(bytes, &VerifyOptions::new(at));
    match (report.verdict, report.failure) {
        (Verdict::Pass, _) => Ok(()),
        (Verdict::Fail, Some(f)) => Err(refuse(format!("{}: {}", f.check, f.detail))),
        (Verdict::Fail, None) => Err(refuse("the verifier gave no reason".into())),
    }
}

// ---------------------------------------------------------------------------
//  A model's files (task 10.13a)
// ---------------------------------------------------------------------------

/// Everything a record of a model's files is built from.
struct GeneralInputs<'a> {
    files: &'a FileSet,
    statements: &'a GeneralStatements,
    manifest: &'a Manifest,
    key: &'a SigningKey,
    components: Option<&'a [String]>,
    records: Option<&'a FileSet>,
}

/// What the summary of a record of a model's files reports.
struct GeneralEmitted<'a> {
    args: &'a EmitArgs,
    model: &'a Path,
    files: &'a FileSet,
    records: Option<&'a FileSet>,
    record: &'a Record,
    size: usize,
    id_source: IdSource,
    time_source: TimeSource,
}

/// `record emit --model`.
fn general(args: &EmitArgs, bar: &mut StderrBar) -> Result<Output, CliError> {
    let Some(model) = args.model.as_deref() else {
        return Err(CliError::input("give --model: a folder of the model's files, or one file"));
    };
    // 1. The output, before anything is opened.
    let mut checked: Vec<(&Path, &str)> = vec![(args.manifest.as_path(), "--manifest"), (args.key.as_path(), "--key")];
    if model.is_file() {
        checked.push((model, "--model"));
    }
    files::check_output(&args.output, "record", "--output", &checked)?;
    refuse_output_inside(&args.output, model, "model folder")?;
    if let Some(records) = args.training_records.as_deref() {
        refuse_output_inside(&args.output, records, "training records folder")?;
    }

    // 2. The manifest's statements, before any file of the model is read.
    let manifest = manifest::load(&args.manifest)?;
    let statements = manifest::general_statements(&manifest, args.training_records.is_some()).map_err(|why| {
        CliError::input(format!(
            "manifest {} is not usable for a record of a model's files: {}; nothing was written",
            shown(&args.manifest),
            bounded(&why)
        ))
        .with_hint("the manifest of a record of a model's files is described in docs/CLI.md §4.3")
    })?;

    // 3. The key and the time.
    let key = keys::read_signing_key(&args.key)?;
    let (issued_at, time_source) = clock::given_or_now(args.issued_at, "--issued-at")?;
    if let TimeSource::Argument(flag) = time_source {
        clock::refuse_future(issued_at, flag, "record")?;
    }

    // 4. The model's files, and the training records' folder.
    let files = read_model_observed(model, bar);
    bar.finish();
    let files = files.map_err(|e| model_cmd::walk_refusal(&e))?;
    if files.is_empty() {
        return Err(model_cmd::no_files(model));
    }
    let records = match args.training_records.as_deref() {
        None => None,
        Some(dir) => {
            let set = read_folder_observed(dir, bar);
            bar.finish();
            let set = set.map_err(|e| model_cmd::walk_refusal(&e))?;
            if set.is_empty() {
                return Err(CliError::input(format!(
                    "training records folder {} holds no regular file; nothing was written",
                    shown(dir)
                )));
            }
            Some(set)
        }
    };
    let components = component_names(&args.component);

    // 5. Build and sign.
    let inputs = GeneralInputs {
        files: &files,
        statements: &statements,
        manifest: &manifest,
        key: &key,
        components: components.as_deref(),
        records: records.as_ref(),
    };
    let (record, id_source) = build_general(&inputs, &issued_at.to_string(), args.record_id.as_deref())?;

    // 6. The bytes: the size a verifier reads, then the pre-write verification.
    let bytes = match args.format {
        FormatArg::Cose => record
            .to_cose()
            .map_err(|e| CliError::input(format!("cannot encode the record as COSE_Sign1: {e}")))?,
        FormatArg::Json => record
            .to_json()
            .map(|text| format!("{text}\n").into_bytes())
            .map_err(|e| CliError::input(format!("cannot encode the record as JSON: {e}")))?,
    };
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(CliError::input(format!(
            "the record would be {} bytes; a record is at most {MAX_RECORD_BYTES} bytes, the most a verifier reads \
             (spec §6.1); nothing was written",
            bytes.len()
        ))
        .with_hint("name the files that are the model's learned state with --component: model_hash still covers every file"));
    }
    refuse_unverifiable(&bytes, &record, &key, "record")?;

    // 7. Write, and say where everything came from.
    files::write_public_new(&args.output, &bytes, args.force, "record")?;
    let emitted = GeneralEmitted {
        args,
        model,
        files: &files,
        records: records.as_ref(),
        record: &record,
        size: bytes.len(),
        id_source,
        time_source,
    };
    Ok(Output::ok(general_summary(&emitted)).with_rich(general_screen(&emitted)))
}

/// The terminal screen of a record of a model's files (docs/dev/cli-polish.md
/// CP-3, CP-5): vmr-cli's emit screen, with the model's hash, its files, its
/// declared format, bases and statement references, and its training data,
/// then every file hashed.
fn general_screen(e: &GeneralEmitted<'_>) -> Vec<crate::rich::Line> {
    use crate::rich::{human_size, plain, row, styled, Style};
    let s = shown_value;
    let p = e.record;
    let m = &p.model_identity;
    let n = e.files.len();
    let components = if e.args.component.is_empty() {
        "every file is a component".to_string()
    } else {
        format!("{} of {n} files are components", m.learned_state_components.len())
    };
    let links = match e.files.entries().iter().filter(|f| f.source == DigestSource::Read { through_link: true }).count() {
        0 => "no links".to_string(),
        1 => "1 name is a link".to_string(),
        k => format!("{k} names are links"),
    };
    let parameters = m.parameter_count.map_or_else(|| "parameters not stated".to_string(), |c| format!("{c} parameters"));
    let mut rows = vec![
        row("Model hash", vec![vec![plain(s(&m.model_hash))]]),
        // QA QPB-05: the exact byte total and the folder read, as the plain
        // text states them; the path on a line of its own.
        row(
            "Files",
            vec![
                vec![plain(format!(
                    "{} · {} ({} bytes) · read from",
                    plural(n as u64, "file", "files"),
                    human_size(e.files.total_bytes()),
                    e.files.total_bytes()
                ))],
                vec![plain(shown(e.model))],
                vec![plain(format!("{components} · {links}"))],
            ],
        ),
        row("Format", vec![crate::screens::declared(format!("\"{}\" · {parameters}", s(&m.model_format)))]),
    ];
    for (i, b) in m.derived_from.iter().flatten().enumerate() {
        rows.push(row(
            if i == 0 { "Derived from" } else { "" },
            vec![vec![plain(format!("{} of {}", s(&b.relation), s(&b.model_hash)))], vec![plain(format!("\"{}\"", s(&b.name)))]],
        ));
    }
    for (i, r) in m.statement_references.iter().flatten().enumerate() {
        rows.push(row(
            if i == 0 { "Statement ref" } else { "" },
            vec![vec![plain(format!("{} {}", s(&r.format), s(&r.digest)))], vec![styled("declared, not checked", Style::Note)]],
        ));
    }
    let l = &p.learning_provenance;
    let training = match (e.records, l.training_input_disclosure.as_deref()) {
        (Some(records), _) => {
            let mut lines = vec![
                vec![plain(format!(
                    "named-set-v1 · {} · its digest and Merkle root:",
                    plural(records.len() as u64, "record", "records")
                ))],
                vec![plain(s(&l.training_input_digest))],
                vec![plain(s(&l.training_input_merkle_root))],
            ];
            // QA QPB-05: the folder the records were read from.
            if let Some(dir) = e.args.training_records.as_deref() {
                lines.push(vec![plain("read from")]);
                lines.push(vec![plain(shown(dir))]);
            }
            lines
        }
        (_, Some("not-disclosed")) => vec![vec![plain("none committed · not disclosed by the issuer")]],
        _ => vec![vec![plain("none committed · not held by the issuer")]],
    };
    rows.push(row("Training data", training));
    let mut files = vec![Vec::new(), vec![plain("  "), styled("Files hashed", Style::Bold), styled(format!("   {n}"), Style::Dim)]];
    files.extend(crate::screens::file_table(e.files, e.args.full, "--full"));
    let form = match e.args.format {
        FormatArg::Cose => "COSE_Sign1",
        FormatArg::Json => "JSON",
    };
    let written = crate::screens::Written {
        record: p,
        output: &e.args.output,
        form,
        size: e.size,
        derived_id: matches!(e.id_source, IdSource::Derived),
        time: e.time_source,
    };
    crate::screens::emitted(&written, rows, files)
}

/// Refuse an output inside `folder` (a folder read as a model's files or its
/// training records): writing it there would change the files it describes.
fn refuse_output_inside(output: &Path, folder: &Path, what: &str) -> Result<(), CliError> {
    let Ok(root) = std::fs::canonicalize(folder) else {
        return Ok(()); // reading it reports that
    };
    if !root.is_dir() {
        return Ok(());
    }
    let parent = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let Ok(dir) = std::fs::canonicalize(&parent) else {
        return Ok(()); // writing it reports that
    };
    if dir.starts_with(&root) {
        return Err(CliError::input(format!(
            "record {} is inside the {what} {}: writing it there would change the files it describes; nothing was \
             written",
            shown(output),
            shown(folder)
        ))
        .with_hint("give --output a path outside that folder"));
    }
    Ok(())
}

/// The --component names as §7.2 names: on Windows, whose path separator is
/// `\`, a typed `\` is read as `/` (spec §7.2).
fn component_names(given: &[String]) -> Option<Vec<String>> {
    if given.is_empty() {
        return None;
    }
    Some(given.iter().map(|n| if cfg!(windows) { n.replace('\\', "/") } else { n.clone() }).collect())
}

/// The record, with its id as given or derived from its content.
fn build_general(g: &GeneralInputs<'_>, issued_at: &str, explicit_id: Option<&str>) -> Result<(Record, IdSource), CliError> {
    if let Some(id) = explicit_id {
        return Ok((general_record(g, issued_at, id)?, IdSource::Argument));
    }
    let draft = general_record(g, issued_at, PLACEHOLDER_ID)?;
    let payload = draft
        .signed_payload()
        .map_err(|e| CliError::input(format!("cannot derive the record's id: {e}")))?;
    let id = derived_id(&payload);
    Ok((general_record(g, issued_at, &id)?, IdSource::Derived))
}

fn general_record(g: &GeneralInputs<'_>, issued_at: &str, id: &str) -> Result<Record, CliError> {
    let m = g.manifest;
    let st = g.statements;
    let training = match (g.records, st.input_disclosure.as_deref()) {
        (Some(records), _) => Training::Records(records.clone()),
        (None, Some("not-held")) => Training::NotHeld,
        (None, Some("not-disclosed")) => Training::NotDisclosed,
        (None, _) => {
            return Err(CliError::input(
                "the training is not given: give --training-records or the manifest's training.input_disclosure",
            ))
        }
    };
    let mut b = GeneralBuilder::new(g.files.clone())
        .record_id(id)
        .issued_at(issued_at)
        .issuer(Issuer {
            issuer_id: m.issuer.issuer_id.clone(),
            issuer_name: m.issuer.issuer_name.clone(),
            public_key: JwkPublicKey::from_verifying_key(g.key.verifying_key()),
            // Left empty: the assembly derives it from the signing key.
            key_id: String::new(),
            attestation_level: m.issuer.attestation_level.clone(),
        })
        .model_format(st.model_format.clone())
        .architecture(st.model.architecture.clone())
        .training(training)
        .training_environment(m.training.environment.clone())
        .training_input_provenance(m.training.input_provenance.clone())
        .policy_compliance(m.policy_compliance.clone())
        .lineage(m.lineage.to_lineage(id));
    if let Some(n) = st.model.parameter_count {
        b = b.parameter_count(n);
    }
    if let Some(names) = g.components {
        b = b.components(names.to_vec());
    }
    if let Some(bases) = &st.model.derived_from {
        b = b.derived_from(bases.clone());
    }
    if let Some(references) = &st.model.statement_references {
        b = b.statement_references(references.clone());
    }
    if let Some(epochs) = m.training.epochs {
        b = b.training_epochs(epochs);
    }
    if let Some(t) = &m.training.started_at {
        b = b.training_started_at(t.clone());
    }
    if let Some(t) = &m.training.ended_at {
        b = b.training_ended_at(t.clone());
    }
    if let Some(d) = &m.deployment_context {
        b = b.deployment_context(d.clone());
    }
    if let Some(d) = &m.data_governance {
        b = b.data_governance(d.clone());
    }
    if let Some(d) = &m.human_oversight {
        b = b.human_oversight(d.clone());
    }
    b.build(g.key).map_err(|e| match e {
        // The builder refuses what a verifier must refuse, the issuer-side
        // time order and a component that is not a file of the model, naming
        // the field and the rule.
        vmr_builder::Error::InvalidInput(why) => CliError::input(format!(
            "the record cannot be built from these inputs: {}; nothing was written",
            bounded(&why)
        ))
        .with_hint(
            "a /section/member path names a record field; the manifest's members are in docs/CLI.md §4.3, the value \
             rules in specs/record-format-v0.1.md §2, the model's rules in §7, the lineage rules in §6.5",
        ),
        other => CliError::input(format!("the record could not be built: {}", bounded(&other.to_string()))),
    })
}

fn field(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!("  {:<23}{value}\n", format!("{label}:")));
}

fn continuation(out: &mut String, value: &str) {
    out.push_str(&format!("  {:<23}{value}\n", ""));
}

fn general_summary(e: &GeneralEmitted<'_>) -> String {
    // File- and manifest-derived values are bounded like a record's (QA P5-05).
    let s = shown_value;
    let p = e.record;
    let m = &p.model_identity;
    let mut out = format!(
        "Emitted record: {} {}\n",
        s(&p.record_id),
        match e.id_source {
            IdSource::Argument => "(--record-id)",
            IdSource::Derived => "(derived from the record's content)",
        }
    );
    let form = match e.args.format {
        FormatArg::Cose => "COSE_Sign1",
        FormatArg::Json => "JSON",
    };
    field(&mut out, "Written to", &format!("{} ({form} form, {} bytes)", shown(&e.args.output), e.size));
    field(
        &mut out,
        "Issuer (declared)",
        &format!(
            "{} (\"{}\"), attestation level {}",
            s(&p.issuer.issuer_id),
            s(&p.issuer.issuer_name),
            s(&p.issuer.attestation_level)
        ),
    );
    field(&mut out, "Signing key", &s(&p.issuer.key_id));
    field(&mut out, "Issued at", &format!("{} {}", s(&p.issued_at), e.time_source.label()));
    field(&mut out, "Model format", &format!("\"{}\" (declared in the manifest)", s(&m.model_format)));
    field(&mut out, "Model hash", &model_cmd::hash_value(e.files, e.model));
    let n = e.files.len();
    let components = if e.args.component.is_empty() {
        format!("every file of the model ({n})")
    } else {
        format!("{} of {n} files (--component)", m.learned_state_components.len())
    };
    field(&mut out, "Components", &components);
    let links = e.files.entries().iter().filter(|f| f.source == DigestSource::Read { through_link: true }).count();
    let links = match links {
        0 => "none".to_string(),
        1 => "1 name is a link, hashed as the regular file it resolves to".to_string(),
        n => format!("{n} names are links, each hashed as the regular file it resolves to"),
    };
    field(&mut out, "Links", &links);
    for (i, b) in m.derived_from.iter().flatten().enumerate() {
        let value = format!("{} of {} (\"{}\")", s(&b.relation), s(&b.model_hash), s(&b.name));
        if i == 0 {
            field(&mut out, "Derived from", &value);
        } else {
            continuation(&mut out, &value);
        }
    }
    for (i, r) in m.statement_references.iter().flatten().enumerate() {
        let value = format!("{} {} (declared, not checked)", s(&r.format), s(&r.digest));
        if i == 0 {
            field(&mut out, "Statement refs", &value);
        } else {
            continuation(&mut out, &value);
        }
    }
    let l = &p.learning_provenance;
    let training = match (e.records, l.training_input_disclosure.as_deref(), e.args.training_records.as_deref()) {
        (Some(records), _, Some(dir)) => format!(
            "named-set-v1, {}, digest {}, root {} (from {})",
            plural(records.len() as u64, "record", "records"),
            s(&l.training_input_digest),
            s(&l.training_input_merkle_root),
            shown(dir)
        ),
        (_, Some("not-disclosed"), _) => "none committed: not disclosed by the issuer".to_string(),
        _ => "none committed: not held by the issuer".to_string(),
    };
    field(&mut out, "Training records", &training);
    field(
        &mut out,
        "Policy (declared)",
        &format!(
            "\"{}\" for {}: declared in the manifest, not evaluated",
            s(&p.policy_compliance.overall_status),
            s(&p.policy_compliance.policy_pack_id)
        ),
    );
    field(
        &mut out,
        "Lineage",
        &format!("{}, chain length {}", s(&p.lineage.lineage_type), p.lineage.lineage_chain_length),
    );
    out.push_str("Files hashed:\n");
    out.push_str(&model_cmd::file_lines(e.files));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmr_record::validate::Pattern;

    #[test]
    fn a_derived_id_is_a_canonical_uuidv8_urn_and_a_function_of_the_payload() {
        let a = derived_id(b"payload one");
        assert!(Pattern::UuidUrn.matches(&a), "{a}");
        assert_eq!(a, derived_id(b"payload one"), "deterministic");
        assert_ne!(a, derived_id(b"payload two"));
        let hex: Vec<char> = a.trim_start_matches("urn:uuid:").chars().collect();
        assert_eq!(hex[14], '8', "version 8: {a}");
        assert!("89ab".contains(hex[19]), "RFC 9562 variant: {a}");
        assert!(Pattern::UuidUrn.matches(PLACEHOLDER_ID));
    }

    #[test]
    fn a_typed_component_name_uses_slashes_on_every_system() {
        assert_eq!(component_names(&[]), None);
        let names = component_names(&["a/b.bin".to_string()]).unwrap();
        assert_eq!(names, ["a/b.bin"]);
        let typed = component_names(&["a\\b.bin".to_string()]).unwrap();
        if cfg!(windows) {
            assert_eq!(typed, ["a/b.bin"], "Windows' separator becomes /");
        } else {
            assert_eq!(typed, ["a\\b.bin"], "a backslash is a name character where it is not the separator");
        }
    }
}
