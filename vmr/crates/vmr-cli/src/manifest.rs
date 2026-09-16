//! The emit manifest, `manifest_version` 0.1 (docs/dev/phase5.md §3.3).
// ============================================================================
//  manifest.rs — the issuer's descriptive statements, in one file
//
//  A record has dozens of descriptive fields (issuer, training window and
//  environment, data provenance, deployment, the declared policy, lineage).
//  One JSON file carries them instead of dozens of flags. Everything the
//  inputs determine — state hashes, component sizes, parameter count,
//  training digest, Merkle root, frame count, key id, public key, signature
//  — comes from the inputs, never from here.
//
//  Strict like the formats it feeds: closed objects at every level
//  (unknown, duplicate and null members rejected, and an object written as
//  the array of its values: both reads go through
//  vmr_record::strict_json, QA QT-01), a version checked first (a later
//  manifest is reported as such). The nested sections reuse the
//  record's own types and member names. Value rules (DIDs, timestamps,
//  ids, hashes, enums) are the record schema's, and lineage consistency
//  is spec §6.5's; the builder enforces both before it signs, and emit's
//  pre-write verification (C11) stays behind it.
//
//  `record emit` reads it for a record of a model's files (task 10.13a:
//  `model`, the optional training times, `training.input_disclosure`, an
//  optional deployment). A build that adds the KHALM engine profile reads the
//  same manifest and takes that profile's statements from it itself.
// ============================================================================

use crate::error::CliError;
use crate::files::{self, shown, ReadError};
use crate::names::TOOL;
use serde::{Deserialize, Deserializer};
use std::path::Path;
use vmr_record::record::{
    Architecture, BaseModel, DeploymentContext, DocumentationRef, Lineage, PolicyCompliance, StatementReference,
    TrainingEnvironment, TrainingInputProvenance,
};
use vmr_record::validate::KHALM_ENGINE_PROFILE;

/// The only manifest version this CLI reads.
pub const MANIFEST_VERSION: &str = "0.1";

/// The largest manifest read: 1 MiB (the record it describes is at most
/// that).
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// A manifest, member for member.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// `"0.1"`.
    pub manifest_version: String,
    /// Who issues the record (its key is the `--key` file's).
    pub issuer: ManifestIssuer,
    /// The model format string. A record of a model's files requires it
    /// (task 10.13a); the engine build's record of the KHALM engine profile
    /// defaults it to `snn-compact-v1`. Absent: `None`; `null` is refused.
    #[serde(default, deserialize_with = "present_some")]
    pub model_format: Option<String>,
    /// How the model was trained.
    pub training: ManifestTraining,
    /// The record's `deployment_context`, as the party deploying the model
    /// states it. Optional for a record of a model's files (spec §7.6);
    /// required by the engine profile's record.
    #[serde(default, deserialize_with = "present_some")]
    pub deployment_context: Option<DeploymentContext>,
    /// The record's `policy_compliance`: the issuer's DECLARATION, which
    /// no part of this CLI evaluates (decision C6).
    pub policy_compliance: PolicyCompliance,
    /// The lineage.
    pub lineage: ManifestLineage,
    /// The record's optional `data_governance`: the hash of the document
    /// the issuer names as its data governance documentation, as the issuer
    /// states it (task 10.11a). vmr reads no document. Absent: none; `null`
    /// is refused.
    #[serde(default, deserialize_with = "present_some")]
    pub data_governance: Option<DocumentationRef>,
    /// The record's optional `human_oversight`, as `data_governance`.
    #[serde(default, deserialize_with = "present_some")]
    pub human_oversight: Option<DocumentationRef>,
    /// What a record of a model's files states about the model (task
    /// 10.13a): its architecture, parameter count, bases and other signed
    /// statements about it. The engine profile's record refuses it.
    #[serde(default, deserialize_with = "present_some")]
    pub model: Option<ManifestModel>,
}

/// The issuer section without its key (the key is the `--key` file's).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestIssuer {
    /// The issuer's DID.
    pub issuer_id: String,
    /// The issuer's name, as it states it (a verifier shows its trust
    /// store's name instead).
    pub issuer_name: String,
    /// `hardware`, `software` or `self`.
    pub attestation_level: String,
}

/// The training facts the inputs cannot tell.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestTraining {
    /// `learning_provenance.training_epochs`: optional for a record of a
    /// model's files, required by the engine profile's record.
    #[serde(default, deserialize_with = "present_some")]
    pub epochs: Option<u64>,
    /// `learning_provenance.training_started_at`, as `epochs`.
    #[serde(default, deserialize_with = "present_some")]
    pub started_at: Option<String>,
    /// `learning_provenance.training_ended_at`, as `epochs`.
    #[serde(default, deserialize_with = "present_some")]
    pub ended_at: Option<String>,
    /// `learning_provenance.training_environment`.
    pub environment: TrainingEnvironment,
    /// `learning_provenance.training_input_provenance`.
    pub input_provenance: TrainingInputProvenance,
    /// `learning_provenance.training_input_disclosure` for a record of a
    /// model's files whose training records are not given: `not-held` or
    /// `not-disclosed` (spec §8.4). The engine profile's record refuses it.
    #[serde(default, deserialize_with = "present_some")]
    pub input_disclosure: Option<String>,
}

/// A model's statements about itself, for a record of its files (task
/// 10.13a): every member is the issuer's, signed as stated.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestModel {
    /// `model_identity.architecture`.
    pub architecture: Architecture,
    /// `model_identity.parameter_count`: the issuer's count; absent, not
    /// stated (spec §7.3).
    #[serde(default, deserialize_with = "present_some")]
    pub parameter_count: Option<u64>,
    /// `model_identity.derived_from`: the bases, each by its `model_hash`
    /// (spec §7.5).
    #[serde(default, deserialize_with = "present_some")]
    pub derived_from: Option<Vec<BaseModel>>,
    /// `model_identity.statement_references`: other signed statements about
    /// the model, each by format and digest (spec §7.7).
    #[serde(default, deserialize_with = "present_some")]
    pub statement_references: Option<Vec<StatementReference>>,
}

/// The lineage: `{"lineage_type": "initial"}` alone for a first record;
/// every other type names its predecessor, chain length and root.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestLineage {
    /// `initial`, `training-update`, `fine-tune`, `quantization`,
    /// `deployment` or `policy-change`.
    pub lineage_type: String,
    /// The predecessor's record id.
    #[serde(default, deserialize_with = "present_some")]
    pub previous_record_id: Option<String>,
    /// The predecessor's signed payload hash (spec §6.5).
    #[serde(default, deserialize_with = "present_some")]
    pub previous_record_hash: Option<String>,
    /// The chain length, this record included.
    #[serde(default, deserialize_with = "present_some")]
    pub lineage_chain_length: Option<u64>,
    /// The chain's first record id.
    #[serde(default, deserialize_with = "present_some")]
    pub root_record_id: Option<String>,
}

/// An optional member: absent → `None`; present → `Some`; `null` → error.
fn present_some<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

impl ManifestLineage {
    /// The record's lineage section for a record with id `record_id`.
    /// An initial record is its own root, chain length 1.
    pub fn to_lineage(&self, record_id: &str) -> Lineage {
        if self.lineage_type == "initial" {
            Lineage {
                previous_record_id: None,
                previous_record_hash: None,
                lineage_chain_length: 1,
                root_record_id: record_id.to_string(),
                lineage_type: self.lineage_type.clone(),
            }
        } else {
            Lineage {
                previous_record_id: self.previous_record_id.clone(),
                previous_record_hash: self.previous_record_hash.clone(),
                lineage_chain_length: self.lineage_chain_length.unwrap_or(0),
                root_record_id: self.root_record_id.clone().unwrap_or_default(),
                lineage_type: self.lineage_type.clone(),
            }
        }
    }

    /// The shape rule: an initial lineage names nothing else (the CLI
    /// derives it); every other type names all four members.
    fn check(&self) -> Result<(), String> {
        let named = [
            ("previous_record_id", self.previous_record_id.is_some()),
            ("previous_record_hash", self.previous_record_hash.is_some()),
            ("lineage_chain_length", self.lineage_chain_length.is_some()),
            ("root_record_id", self.root_record_id.is_some()),
        ];
        if self.lineage_type == "initial" {
            if let Some((member, _)) = named.iter().find(|(_, present)| *present) {
                return Err(format!(
                    "lineage: an initial lineage names nothing but its type ({TOOL} sets chain length 1 and \
                     root = the record's own id); remove `{member}`"
                ));
            }
        } else {
            let missing: Vec<&str> = named.iter().filter(|(_, present)| !present).map(|(m, _)| *m).collect();
            if !missing.is_empty() {
                return Err(format!(
                    "lineage: a {:?} lineage must name its predecessor; missing: {}",
                    self.lineage_type,
                    missing.join(", ")
                ));
            }
        }
        Ok(())
    }
}

/// What a record of a model's files takes from the manifest (task 10.13a),
/// checked before any file of the model is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralStatements {
    /// The model's format, as the issuer names it; never a registered profile.
    pub model_format: String,
    /// The manifest's `model` member.
    pub model: ManifestModel,
    /// `not-held` or `not-disclosed`, when the training records are not given.
    pub input_disclosure: Option<String>,
}

/// The manifest's statements for a record of a model's files: a
/// `model_format` that is not a registered profile identifier (task 10.13a,
/// D13a-9), a `model` member, and the training given exactly once - by
/// `--training-records` (`records_given`) or by `training.input_disclosure`.
pub fn general_statements(m: &Manifest, records_given: bool) -> Result<GeneralStatements, String> {
    let model_format = match m.model_format.as_deref() {
        None | Some("") => {
            return Err("a record of a model's files names the model's format: the manifest has no model_format, \
                        or an empty one (spec §7.1)"
                .into())
        }
        Some(KHALM_ENGINE_PROFILE) => {
            return Err(format!(
                "model_format \"{KHALM_ENGINE_PROFILE}\" is the KHALM engine profile, made only from an engine's own \
                 state (spec §7.4): a model's files are described in general (spec §7.3), never under a profile's name"
            ))
        }
        Some(format) => format.to_string(),
    };
    let model = m.model.clone().ok_or_else(|| {
        "the manifest has no \"model\" member: a record of a model's files states the model's architecture there \
         (docs/CLI.md §4.3)"
            .to_string()
    })?;
    let input_disclosure = match (m.training.input_disclosure.as_deref(), records_given) {
        (Some(_), true) => {
            return Err("the training is given twice, by --training-records and by the manifest's \
                        training.input_disclosure: give one"
                .into())
        }
        (None, false) => {
            return Err("the training is not given: give --training-records (the folder of the training records) \
                        or the manifest's training.input_disclosure (\"not-held\" or \"not-disclosed\")"
                .into())
        }
        (Some(d), false) if d == "not-held" || d == "not-disclosed" => Some(d.to_string()),
        (Some(d), false) => {
            return Err(format!("training.input_disclosure is {d:?}: it is \"not-held\" or \"not-disclosed\" (spec §8.4)"))
        }
        (None, true) => None,
    };
    Ok(GeneralStatements { model_format, model, input_disclosure })
}

/// The example manifest an unusable manifest's hint names: a record of a
/// model's files, which is what this tool makes (QA13-08).
pub const MANIFEST_EXAMPLE: &str = "docs/examples/phi-4-mini-instruct/manifest.json";

/// Read and check a manifest file.
pub fn load(path: &Path) -> Result<Manifest, CliError> {
    load_with_example(path, MANIFEST_EXAMPLE)
}

/// Read and check a manifest file; an unusable one's hint names `example`. A
/// build that extends this tool with another kind of record names its own.
pub fn load_with_example(path: &Path, example: &str) -> Result<Manifest, CliError> {
    let bytes = files::read_bounded(path, MAX_MANIFEST_BYTES).map_err(|e| match e {
        ReadError::TooLarge(size) => CliError::input(format!(
            "manifest {} is {size} bytes; a manifest is at most 1 MiB, and it was not read",
            shown(path)
        )),
        ReadError::Io(e) => CliError::input(format!("cannot read manifest {}: {e}", shown(path))),
    })?;
    parse(&bytes).map_err(|why| {
        let e = CliError::input(format!("manifest {} is not usable: {}", shown(path), crate::render::bounded(&why)));
        match files::byte_order_mark(&bytes) {
            Some(_) => e.with_hint(files::SAVE_WITHOUT_BOM),
            None => e.with_hint(format!("the manifest format is in docs/CLI.md; {example} is an example")),
        }
    })
}

/// Parse and check a manifest: syntax, version, structure, lineage shape.
pub fn parse(bytes: &[u8]) -> Result<Manifest, String> {
    // Refused like any file that is not UTF-8 JSON, but named (QA P5-07).
    if let Some(bom) = files::byte_order_mark(bytes) {
        return Err(format!("{bom}, which a manifest may not have (it is UTF-8 JSON)"));
    }
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not UTF-8: {e}"))?;
    serde_json::from_str::<serde::de::IgnoredAny>(text).map_err(|e| format!("not JSON: {e}"))?;
    #[derive(Deserialize)]
    struct VersionOnly {
        manifest_version: Option<serde_json::Value>,
    }
    if let Ok(VersionOnly { manifest_version: Some(v) }) = vmr_record::strict_json::from_str::<VersionOnly>(text) {
        if v != MANIFEST_VERSION {
            return Err(format!("manifest_version is {v}; this {TOOL} reads \"{MANIFEST_VERSION}\""));
        }
    }
    let manifest: Manifest = vmr_record::strict_json::from_str(text).map_err(|e| e.to_string())?;
    manifest.lineage.check()?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo() -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/demo/record-manifest.json"),
        )
        .unwrap()
    }

    fn edited(edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut v: serde_json::Value = serde_json::from_str(&demo()).unwrap();
        edit(&mut v);
        serde_json::to_vec(&v).unwrap()
    }

    #[test]
    fn the_demo_manifest_is_a_valid_initial_manifest() {
        let m = parse(demo().as_bytes()).unwrap();
        assert_eq!(m.manifest_version, "0.1");
        assert_eq!(m.issuer.issuer_id, "did:web:factory-operator.ph");
        assert_eq!(m.lineage.lineage_type, "initial");
        let l = m.lineage.to_lineage("urn:uuid:5d1f6a2e-3b7c-4e8d-9f10-2a3b4c5d6e7f");
        assert_eq!((l.lineage_chain_length, l.root_record_id.as_str()), (1, "urn:uuid:5d1f6a2e-3b7c-4e8d-9f10-2a3b4c5d6e7f"));
    }

    #[test]
    fn the_demo_declares_its_evaluation_of_the_eu_ai_act_reference_pack() {
        // QA P5-09 and the owner's decision of 2026-09-12: the demo declares
        // the EU AI Act reference pack, and never "compliant" over nothing.
        // Until an evaluator and that pack existed it declared "indeterminate"
        // with no rule results. Task 7.6 carries in the evaluation `vmr
        // record verify --policy-pack` made of the demo record
        // (docs/dev/task-7.6.md §4): every rule, in the pack's order, with the
        // status written here by hand (§5), at the record's issued_at.
        let m = parse(demo().as_bytes()).unwrap();
        assert_eq!(m.deployment_context.as_ref().unwrap().policy_pack_id, "khalm-reading-eu-ai-act-2026");
        let pc = &m.policy_compliance;
        assert_eq!(pc.policy_pack_id, "khalm-reading-eu-ai-act-2026");
        assert_eq!(pc.evaluated_at, "2026-09-11T00:00:00Z");
        assert_eq!(pc.overall_status, "compliant");
        let statuses: Vec<(&str, &str)> = pc.results.iter().map(|r| (r.rule_id.as_str(), r.status.as_str())).collect();
        assert_eq!(
            statuses,
            [
                ("eu-ai-act-record-keeping", "pass"),
                ("eu-ai-act-accuracy-robustness", "pass"),
                ("eu-ai-act-technical-documentation", "pass"),
                ("eu-ai-act-cybersecurity-attestation", "pass"),
                ("eu-ai-act-data-governance", "pass"),
                // The demo pins no human oversight document (D11-7).
                ("eu-ai-act-human-oversight", "fail"),
            ]
        );
        assert!(pc.results.iter().all(|r| r.evidence_hash.starts_with("sha256:")));
    }

    /// A demo document the manifest pins by hash (task 7.6), as committed.
    /// `.gitattributes` keeps it LF on every checkout; a carriage return
    /// would change its hash, so it is refused here by name.
    fn demo_document(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/demo").join(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(!bytes.contains(&b'\r'), "{name} holds a carriage return: its hash is pinned over LF line endings");
        bytes
    }

    /// `sha256:` and the lower-case hex of the SHA-256 of `bytes`.
    fn hash_of(bytes: &[u8]) -> String {
        vmr_record::hash::format_hash(&vmr_record::hash::sha256(bytes))
    }

    #[test]
    fn the_demo_pins_its_data_governance_document_by_hash_and_no_oversight_document() {
        // Task 7.6 (docs/dev/task-10.11a.md D11-7): the demo declares data
        // governance only, by the SHA-256 of docs/demo/data-governance.md.
        let m = parse(demo().as_bytes()).unwrap();
        let hash = hash_of(&demo_document("data-governance.md"));
        assert_eq!(m.data_governance.as_ref().map(|d| d.documentation_hash.as_str()), Some(hash.as_str()));
        assert!(m.human_oversight.is_none(), "the demo pins no human oversight document (D11-7)");
    }

    #[test]
    fn the_documentation_members_are_optional_hashes_and_never_null() {
        // Task 10.11a (D11-2): the manifest may name the issuer's data
        // governance and human oversight documentation by hash, as the
        // record's own members. Absent means none; `null`, an unknown
        // member and a missing hash are refused. The hash is the issuer's
        // statement: vmr reads no document, and the builder checks the hash's
        // form before it signs.
        let hash = format!("sha256:{}", "ab".repeat(32));
        let m = parse(&edited(|v| {
            v.as_object_mut().unwrap().remove("data_governance");
            v.as_object_mut().unwrap().remove("human_oversight");
        }))
        .unwrap();
        assert!(m.data_governance.is_none() && m.human_oversight.is_none());
        let m = parse(&edited(|v| v["data_governance"] = serde_json::json!({ "documentation_hash": hash }))).unwrap();
        assert_eq!(m.data_governance.as_ref().map(|d| d.documentation_hash.as_str()), Some(hash.as_str()));
        assert!(m.human_oversight.is_none());
        for (member, value, expect) in [
            ("data_governance", serde_json::Value::Null, "invalid type: null"),
            ("human_oversight", serde_json::json!({ "documentation_hash": hash, "path": "oversight.pdf" }), "unknown field `path`"),
            ("human_oversight", serde_json::json!({}), "missing field `documentation_hash`"),
            ("data_governance", serde_json::json!(hash), "invalid type: string"),
        ] {
            let err = parse(&edited(|v| v[member] = value.clone())).unwrap_err();
            assert!(err.contains(expect), "{member} = {value}: expected `{expect}`, got: {err}");
        }
    }

    #[test]
    fn model_format_is_optional_but_never_null() {
        // A record of a model's files requires model_format (task 10.13a); the
        // manifest may leave it out for the engine build, whose record of the
        // KHALM engine profile defaults it. `null` is refused either way.
        let m = parse(&edited(|v| {
            v.as_object_mut().unwrap().remove("model_format");
        }))
        .unwrap();
        assert_eq!(m.model_format, None);
        assert!(general_statements(&m, false).unwrap_err().contains("no model_format"));
        assert!(parse(&edited(|v| v["model_format"] = serde_json::Value::Null)).is_err());
    }

    #[test]
    fn a_manifest_for_a_models_files_takes_what_its_record_needs() {
        // Task 10.13a: the demo is the engine profile's manifest.
        let demo_manifest = parse(demo().as_bytes()).unwrap();
        let err = general_statements(&demo_manifest, false).unwrap_err();
        assert!(err.contains("KHALM engine profile"), "{err}");
        let architecture = serde_json::json!({"type": "transformer", "topology": "", "precision": ""});
        let general = parse(&edited(|v| {
            v["model_format"] = "gguf".into();
            v["model"] = serde_json::json!({ "architecture": architecture.clone() });
            v["training"]["input_disclosure"] = "not-held".into();
        }))
        .unwrap();
        let st = general_statements(&general, false).unwrap();
        assert_eq!((st.model_format.as_str(), st.input_disclosure.as_deref()), ("gguf", Some("not-held")));
        assert!(general_statements(&general, true).unwrap_err().contains("given twice"));
        let bad = parse(&edited(|v| {
            v["model_format"] = "gguf".into();
            v["model"] = serde_json::json!({ "architecture": architecture.clone() });
            v["training"]["input_disclosure"] = "held".into();
        }))
        .unwrap();
        assert!(general_statements(&bad, false).unwrap_err().contains("not-held"));
        let no_model = parse(&edited(|v| v["model_format"] = "gguf".into())).unwrap();
        assert!(general_statements(&no_model, true).unwrap_err().contains("\"model\""));
        let extra = edited(|v| v["model"] = serde_json::json!({ "architecture": architecture.clone(), "x": 1 }));
        assert!(parse(&extra).unwrap_err().contains("unknown field `x`"));
    }

    #[test]
    fn every_level_is_closed_and_the_version_comes_first() {
        for (edit, expect) in [
            (Box::new(|v: &mut serde_json::Value| v["x"] = 1.into()) as Box<dyn Fn(&mut serde_json::Value)>, "unknown field `x`"),
            (Box::new(|v| v["issuer"]["public_key"] = 1.into()), "unknown field `public_key`"),
            (Box::new(|v| v["training"]["environment"]["x"] = 1.into()), "unknown field `x`"),
            (Box::new(|v| v["lineage"]["x"] = 1.into()), "unknown field `x`"),
            (Box::new(|v| v["manifest_version"] = "0.2".into()), "manifest_version is \"0.2\""),
            (Box::new(|v| {
                v["manifest_version"] = "0.2".into();
                v["future_member"] = 1.into();
            }), "manifest_version is \"0.2\""),
            (Box::new(|v| {
                v.as_object_mut().unwrap().remove("training");
            }), "missing field `training`"),
            (Box::new(|v| v["lineage"]["previous_record_id"] = serde_json::Value::Null), "invalid type: null"),
        ] {
            let err = parse(&edited(edit)).unwrap_err();
            assert!(err.contains(expect), "expected `{expect}`, got: {err}");
        }
        assert!(parse(b"{").unwrap_err().starts_with("not JSON"));
        assert!(parse(b"\xff").unwrap_err().starts_with("not UTF-8"));
        assert!(parse(br#"{"manifest_version":"0.1","manifest_version":"0.1"}"#).is_err(), "duplicate member");
    }

    #[test]
    fn an_object_written_as_the_array_of_its_values_is_refused_at_every_level() {
        // QA QT-01: serde's derive reads a struct from the array of its
        // values in declaration order, so each text below read as the
        // manifest, which is closed objects at every level (docs/CLI.md
        // §4.3). The demo, with a data_governance member and one policy
        // result so that every object kind appears; each object respelled,
        // one at a time.
        const OBJECTS: &[(&str, &[&str])] = &[
            ("", &["manifest_version", "issuer", "model_format", "training", "deployment_context", "policy_compliance", "lineage", "data_governance"]),
            ("/issuer", &["issuer_id", "issuer_name", "attestation_level"]),
            ("/training", &["epochs", "started_at", "ended_at", "environment", "input_provenance"]),
            ("/training/environment", &["hardware_id", "tee_measurement", "software_hash", "accelerator_software", "training_software"]),
            ("/training/input_provenance", &["source_type", "source_description", "data_residency", "collection_period"]),
            ("/training/input_provenance/collection_period", &["start", "end"]),
            ("/deployment_context", &["deployment_id", "deployed_at", "deployed_by", "hardware_id", "tee_measurement", "software_hash", "inference_boundary", "policy_pack_id"]),
            ("/deployment_context/inference_boundary", &["type", "egress_allowed", "allowed_egress_destinations"]),
            ("/policy_compliance", &["policy_pack_id", "evaluated_at", "results", "overall_status"]),
            ("/policy_compliance/results/0", &["rule_id", "status", "evidence_hash"]),
            ("/lineage", &["lineage_type"]),
            ("/data_governance", &["documentation_hash"]),
        ];
        fn objects(v: &serde_json::Value, at: &str, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Object(m) => {
                    out.push(at.to_string());
                    m.iter().for_each(|(k, c)| objects(c, &format!("{at}/{k}"), out));
                }
                serde_json::Value::Array(items) => {
                    items.iter().enumerate().for_each(|(i, c)| objects(c, &format!("{at}/{i}"), out));
                }
                _ => {}
            }
        }
        let hash = format!("sha256:{}", "ab".repeat(32));
        let base: serde_json::Value = serde_json::from_slice(&edited(|v| {
            v["data_governance"] = serde_json::json!({ "documentation_hash": hash });
            v["policy_compliance"]["results"] =
                serde_json::json!([{ "rule_id": "example-rule", "status": "pass", "evidence_hash": hash }]);
        }))
        .unwrap();
        let expected = parse(&serde_json::to_vec(&base).unwrap()).unwrap();
        let mut found = Vec::new();
        objects(&base, "", &mut found);
        found.sort();
        let mut listed: Vec<String> = OBJECTS.iter().map(|(p, _)| p.to_string()).collect();
        listed.sort();
        assert_eq!(found, listed, "every object of the manifest is respelled");
        for (pointer, fields) in OBJECTS {
            let mut doc = base.clone();
            let object = doc.pointer_mut(pointer).unwrap();
            assert_eq!(object.as_object().unwrap().len(), fields.len(), "{pointer}");
            let values = fields.iter().map(|f| object[*f].clone()).collect();
            *object = serde_json::Value::Array(values);
            let text = serde_json::to_vec(&doc).unwrap();
            assert_eq!(serde_json::from_slice::<Manifest>(&text).unwrap(), expected, "{pointer}: serde_json reads it as the manifest");
            let err = parse(&text).unwrap_err();
            assert!(err.contains("invalid type: sequence, expected "), "{pointer}: {err}");
        }
    }

    #[test]
    fn the_version_probe_names_a_version_that_holds_no_array() {
        // QA QT-01 QJ-05: `manifest_version` is read first, as a JSON value
        // through the strict reader, only to choose which refusal to print
        // (docs/CLI.md §4.3). A version other than "0.1" that holds no array
        // is named as a version; one that is or holds an array, like a
        // manifest that is itself an array, cannot be read so, and the typed
        // parse refuses it as a value of the wrong type. Nothing is accepted
        // either way: the typed parse decides that.
        for (version, expect) in [
            (serde_json::json!("0.2"), "manifest_version is \"0.2\"; this vmr reads \"0.1\""),
            (serde_json::json!(2), "manifest_version is 2; this vmr reads \"0.1\""),
            (serde_json::json!({ "v": "0.2" }), "manifest_version is {\"v\":\"0.2\"}; this vmr reads \"0.1\""),
            (serde_json::json!(["0.2"]), "invalid type: sequence, expected a string"),
            (serde_json::json!({ "v": ["0.2"] }), "invalid type: map, expected a string"),
        ] {
            let err = parse(&edited(|v| v["manifest_version"] = version.clone())).unwrap_err();
            assert!(err.starts_with(expect), "{version}: expected `{expect}`, got: {err}");
        }
        let err = parse(br#"["0.2"]"#).unwrap_err();
        assert!(err.starts_with("invalid type: sequence, expected struct Manifest"), "{err}");
    }

    #[test]
    fn a_manifest_with_a_byte_order_mark_is_refused_saying_so() {
        // QA P5-07: refused as before (a manifest is UTF-8 JSON), but the
        // reason names the invisible first bytes instead of "expected value
        // at line 1 column 1".
        let bom = [&[0xef, 0xbb, 0xbf][..], demo().as_bytes()].concat();
        let err = parse(&bom).unwrap_err();
        assert!(err.starts_with("the file starts with a UTF-8 byte order mark (EF BB BF)"), "{err}");
        let utf16: Vec<u8> = [0xff, 0xfe].into_iter().chain(demo().encode_utf16().flat_map(u16::to_le_bytes)).collect();
        let err = parse(&utf16).unwrap_err();
        assert!(err.starts_with("the file is UTF-16 text"), "{err}");
    }

    #[test]
    fn the_lineage_shape_rule() {
        let err = parse(&edited(|v| v["lineage"]["root_record_id"] = "urn:uuid:x".into())).unwrap_err();
        assert!(err.contains("remove `root_record_id`"), "{err}");
        let err = parse(&edited(|v| v["lineage"] = serde_json::json!({"lineage_type": "fine-tune"}))).unwrap_err();
        assert!(err.contains("missing: previous_record_id, previous_record_hash, lineage_chain_length, root_record_id"), "{err}");
        let full = serde_json::json!({
            "lineage_type": "fine-tune",
            "previous_record_id": "urn:uuid:11111111-2222-4333-8444-555555555555",
            "previous_record_hash": "sha256:2eca0dd33554f5113d03ef96bc01deb56fafd8484bbf95f04bd308ee6c075967",
            "lineage_chain_length": 3,
            "root_record_id": "urn:uuid:00000000-0000-4000-8000-000000000000"
        });
        let m = parse(&edited(|v| v["lineage"] = full)).unwrap();
        let l = m.lineage.to_lineage("urn:uuid:ffffffff-0000-4000-8000-000000000000");
        assert_eq!(l.lineage_chain_length, 3);
        assert_eq!(l.root_record_id, "urn:uuid:00000000-0000-4000-8000-000000000000");
        assert!(l.previous_record_hash.is_some());
    }

    #[test]
    fn mutated_manifests_never_panic_and_reasons_are_terminal_safe() {
        use crate::mutate::{mutate, repo_file, terminal_safe, Lcg};
        let seed = repo_file("docs/demo/record-manifest.json");
        let mut rng = Lcg::new(0x5EED_5001);
        let mut current = seed.clone();
        for i in 0..3000 {
            if i % 8 == 0 {
                current = seed.clone();
            }
            current = mutate(&mut rng, &current);
            if let Err(why) = parse(&current) {
                assert!(terminal_safe(&crate::render::bounded(&why)), "{why}");
            }
        }
    }
}
