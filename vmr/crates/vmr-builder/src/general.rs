//! The general description (spec §7.3) of a model from its files, and its
//! `named-set-v1` training records (spec §8.2).
// ============================================================================
//  general.rs — a record of any AI model, from any vendor, whose weights the
//  issuer holds
//
//  A model is a set of named files (spec §7.2): each file's name, the
//  SHA-256 of its bytes and its size. `model_hash` is the named-set digest of
//  every file; the components are every file, or the files the issuer names
//  as the learned state, and `learned_state_hash` is their named-set digest.
//  Training records are another set of named byte strings, committed by their
//  count, named-set digest and Merkle root; or the issuer says it does not
//  hold them, or does not disclose them (§8.4).
//
//  Nothing here reads a file, parses a model format or guesses a statement:
//  the format, architecture, parameter count, bases and references are the
//  issuer's, signed as stated. No registered profile identifier is ever the
//  format of a model's files (task 10.13a, D13a-9): the KHALM engine profile
//  is made only from an engine's own state (vmr-provenance).
// ============================================================================

use crate::assemble::{sign_record, RecordParts};
use crate::error::Error;
use p256::ecdsa::SigningKey;
use vmr_record::hash::{format_hash, sha256, DIGEST_LEN};
use vmr_record::merkle::MerkleStream;
use vmr_record::named_set::{member_encoding, validate_name};
use vmr_record::record::{
    Architecture, BaseModel, DeploymentContext, DocumentationRef, Issuer, LearningProvenance, Lineage, ModelIdentity,
    Record, PolicyCompliance, StateComponent, StatementReference, TrainingEnvironment, TrainingInputProvenance,
};
use vmr_record::validate::KHALM_ENGINE_PROFILE;

/// The largest integer a record states exactly: 2^53 - 1.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The record format of named training records (spec §8.2).
pub const NAMED_SET_V1: &str = "named-set-v1";

/// Where a file's digest came from (task 10.13a, D13a-16): always read by
/// this tool, today. A later input that takes digests from another signed
/// statement adds a variant here, and nothing that builds a record changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestSource {
    /// This tool read the file's bytes. `through_link` when the name is a
    /// link that resolves to a regular file, hashed as that file under the
    /// link's own name (spec §7.2).
    Read {
        /// Whether the name is a link to the file read.
        through_link: bool,
    },
}

/// One named file of a model or of a set of records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// The file's name (spec §7.2): its path in the folder with `/`, or, for a
    /// model given as one file, the file's own name.
    pub name: String,
    /// The SHA-256 of the file's bytes.
    pub digest: [u8; DIGEST_LEN],
    /// The number of bytes.
    pub size_bytes: u64,
    /// Where the digest came from.
    pub source: DigestSource,
}

/// A set of named files in spec §7.2's order: ascending by the names' UTF-8
/// bytes, each name once, every name one of §7.2.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileSet {
    entries: Vec<FileEntry>,
}

impl FileSet {
    /// The set of `entries`, in §7.2's order. Refuses a name §7.2 refuses, a
    /// name given twice, and a size a record cannot state (over 2^53 - 1).
    pub fn from_entries(mut entries: Vec<FileEntry>) -> Result<FileSet, Error> {
        entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        let mut previous: Option<&str> = None;
        for e in &entries {
            validate_name(&e.name).map_err(|why| {
                Error::InvalidInput(format!("\"{}\" is not a name of spec §7.2: {}", e.name, why.reason()))
            })?;
            if previous == Some(e.name.as_str()) {
                return Err(Error::InvalidInput(format!(
                    "\"{}\" is named twice: a set holds each name once (spec §7.2)",
                    e.name
                )));
            }
            if e.size_bytes > MAX_SAFE_INTEGER {
                return Err(Error::InvalidInput(format!(
                    "\"{}\" is {} bytes, more than a record can state (2^53 - 1)",
                    e.name, e.size_bytes
                )));
            }
            previous = Some(e.name.as_str());
        }
        Ok(FileSet { entries })
    }

    /// The files, in §7.2's order.
    pub fn entries(&self) -> &[FileEntry] {
        &self.entries
    }

    /// How many files.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set holds no file.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The bytes of every file together.
    pub fn total_bytes(&self) -> u64 {
        self.entries.iter().fold(0u64, |sum, e| sum.saturating_add(e.size_bytes))
    }

    /// The file named `name`, if the set holds it.
    pub fn get(&self, name: &str) -> Option<&FileEntry> {
        self.entries
            .binary_search_by(|e| e.name.as_bytes().cmp(name.as_bytes()))
            .ok()
            .and_then(|i| self.entries.get(i))
    }

    /// The named-set digest of the files (spec §7.2).
    pub fn named_set_digest(&self) -> [u8; DIGEST_LEN] {
        digest_of(self.entries.iter())
    }
}

/// The named-set digest of `entries`, given in §7.2's order: SHA-256 over
/// their member encodings.
fn digest_of<'a>(entries: impl Iterator<Item = &'a FileEntry>) -> [u8; DIGEST_LEN] {
    let mut encodings = Vec::new();
    for e in entries {
        encodings.extend_from_slice(&member_encoding(&e.name, &e.digest));
    }
    sha256(&encodings)
}

/// A `named-set-v1` commitment to training records (spec §8.2, §8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordsCommitment {
    /// The number of records.
    pub count: u64,
    /// Their named-set digest: `training_input_digest`.
    pub digest: [u8; DIGEST_LEN],
    /// The Merkle root over one leaf per record, whose leaf data is the
    /// record's member encoding: `training_input_merkle_root`.
    pub merkle_root: [u8; DIGEST_LEN],
}

/// Commit `records` in the `named-set-v1` format: their count, named-set
/// digest and Merkle root, one pass in §7.2's order.
pub fn commit_records(records: &FileSet) -> RecordsCommitment {
    let mut merkle = MerkleStream::new();
    let mut encodings = Vec::new();
    for e in records.entries() {
        let encoding = member_encoding(&e.name, &e.digest);
        merkle.push(&encoding);
        encodings.extend_from_slice(&encoding);
    }
    RecordsCommitment { count: records.len() as u64, digest: sha256(&encodings), merkle_root: merkle.finish() }
}

/// The training a record commits to (spec §8.2, §8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Training {
    /// The issuer holds the records and commits to them, `named-set-v1`.
    Records(FileSet),
    /// The issuer does not hold the records (`not-held`).
    NotHeld,
    /// The issuer holds the records and does not commit to them here
    /// (`not-disclosed`).
    NotDisclosed,
}

/// Builds and signs the general description of a model from its files.
/// Every time-bearing or identity-bearing field is an input: nothing is read
/// from a clock or drawn at random, so the same inputs and key give the same
/// record, byte for byte.
#[derive(Debug, Clone)]
pub struct GeneralBuilder {
    files: FileSet,
    record_id: Option<String>,
    issued_at: Option<String>,
    issuer: Option<Issuer>,
    model_format: Option<String>,
    architecture: Option<Architecture>,
    parameter_count: Option<u64>,
    components: Option<Vec<String>>,
    derived_from: Option<Vec<BaseModel>>,
    statement_references: Option<Vec<StatementReference>>,
    training: Option<Training>,
    training_epochs: Option<u64>,
    training_started_at: Option<String>,
    training_ended_at: Option<String>,
    training_environment: Option<TrainingEnvironment>,
    training_input_provenance: Option<TrainingInputProvenance>,
    deployment_context: Option<DeploymentContext>,
    policy_compliance: Option<PolicyCompliance>,
    lineage: Option<Lineage>,
    data_governance: Option<DocumentationRef>,
    human_oversight: Option<DocumentationRef>,
}

impl GeneralBuilder {
    /// Start a record of the model whose files are `files`.
    pub fn new(files: FileSet) -> Self {
        GeneralBuilder {
            files,
            record_id: None,
            issued_at: None,
            issuer: None,
            model_format: None,
            architecture: None,
            parameter_count: None,
            components: None,
            derived_from: None,
            statement_references: None,
            training: None,
            training_epochs: None,
            training_started_at: None,
            training_ended_at: None,
            training_environment: None,
            training_input_provenance: None,
            deployment_context: None,
            policy_compliance: None,
            lineage: None,
            data_governance: None,
            human_oversight: None,
        }
    }

    /// The record's id (`urn:uuid:...`). Required.
    pub fn record_id(mut self, v: impl Into<String>) -> Self {
        self.record_id = Some(v.into());
        self
    }

    /// The issuance timestamp (RFC 3339 UTC). Required; never generated.
    pub fn issued_at(mut self, v: impl Into<String>) -> Self {
        self.issued_at = Some(v.into());
        self
    }

    /// The issuer section; `key_id` may be empty (derived from the key).
    /// Required.
    pub fn issuer(mut self, v: Issuer) -> Self {
        self.issuer = Some(v);
        self
    }

    /// The model's format as the issuer names it (spec §7.1), never a
    /// registered profile identifier. Required.
    pub fn model_format(mut self, v: impl Into<String>) -> Self {
        self.model_format = Some(v.into());
        self
    }

    /// The issuer's description of the architecture. Required.
    pub fn architecture(mut self, v: Architecture) -> Self {
        self.architecture = Some(v);
        self
    }

    /// The issuer's count of learned parameters (spec §7.3). Optional:
    /// without it the record does not state one.
    pub fn parameter_count(mut self, v: u64) -> Self {
        self.parameter_count = Some(v);
        self
    }

    /// The files the issuer names as the model's learned state. Optional:
    /// without it every file is a component (spec §7.3's SHOULD).
    pub fn components(mut self, names: Vec<String>) -> Self {
        self.components = Some(names);
        self
    }

    /// The models this model was made from, each by its `model_hash` (spec
    /// §7.5). Optional.
    pub fn derived_from(mut self, v: Vec<BaseModel>) -> Self {
        self.derived_from = Some(v);
        self
    }

    /// Other signed statements about the model, each by format and digest
    /// (spec §7.7). Optional; nothing reads them.
    pub fn statement_references(mut self, v: Vec<StatementReference>) -> Self {
        self.statement_references = Some(v);
        self
    }

    /// The training records, or that the issuer does not hold or does not
    /// disclose them. Required.
    pub fn training(mut self, v: Training) -> Self {
        self.training = Some(v);
        self
    }

    /// Training epochs. Optional.
    pub fn training_epochs(mut self, v: u64) -> Self {
        self.training_epochs = Some(v);
        self
    }

    /// When training started. Optional.
    pub fn training_started_at(mut self, v: impl Into<String>) -> Self {
        self.training_started_at = Some(v.into());
        self
    }

    /// When training ended. Optional.
    pub fn training_ended_at(mut self, v: impl Into<String>) -> Self {
        self.training_ended_at = Some(v.into());
        self
    }

    /// The training environment (spec §8.5). Required.
    pub fn training_environment(mut self, v: TrainingEnvironment) -> Self {
        self.training_environment = Some(v);
        self
    }

    /// The training data's declared provenance (spec §8.5). Required.
    pub fn training_input_provenance(mut self, v: TrainingInputProvenance) -> Self {
        self.training_input_provenance = Some(v);
        self
    }

    /// The deployment context, stated by the party deploying the model.
    /// Optional (spec §7.6).
    pub fn deployment_context(mut self, v: DeploymentContext) -> Self {
        self.deployment_context = Some(v);
        self
    }

    /// The issuer's declared policy evaluation. Required.
    pub fn policy_compliance(mut self, v: PolicyCompliance) -> Self {
        self.policy_compliance = Some(v);
        self
    }

    /// The lineage section. Required.
    pub fn lineage(mut self, v: Lineage) -> Self {
        self.lineage = Some(v);
        self
    }

    /// The data governance documentation, by hash. Optional.
    pub fn data_governance(mut self, v: DocumentationRef) -> Self {
        self.data_governance = Some(v);
        self
    }

    /// The human oversight documentation, by hash. Optional.
    pub fn human_oversight(mut self, v: DocumentationRef) -> Self {
        self.human_oversight = Some(v);
        self
    }

    fn require<T: Clone>(field: &Option<T>, name: &str) -> Result<T, Error> {
        field.clone().ok_or_else(|| Error::InvalidInput(format!("missing required field: {name}")))
    }

    /// The model identity this builder states: `model_hash` over every file,
    /// the components and their `learned_state_hash`, and the issuer's
    /// statements. Refuses a registered profile identifier as the format, a
    /// model of no files, and a component that is not one file of the model.
    pub fn model_identity(&self) -> Result<ModelIdentity, Error> {
        let model_format = Self::require(&self.model_format, "model_format")?;
        if model_format.is_empty() {
            return Err(Error::InvalidInput(
                "model_format is empty: a record names its model's format (spec §7.1)".into(),
            ));
        }
        if model_format == KHALM_ENGINE_PROFILE {
            return Err(Error::InvalidInput(format!(
                "model_format \"{model_format}\" is the registered identifier of the KHALM engine profile (spec \
                 §7.4), made only from an engine's own state: a model's files are described in general \
                 (spec §7.3), never under a profile's name"
            )));
        }
        if self.files.is_empty() {
            return Err(Error::InvalidInput(
                "a model is at least one file: the general description lists one or more components (spec §7.3)"
                    .into(),
            ));
        }
        let architecture = Self::require(&self.architecture, "architecture")?;
        let chosen: Vec<&FileEntry> = match &self.components {
            None => self.files.entries().iter().collect(),
            Some(names) => self.chosen_components(names)?,
        };
        let learned_state_components = chosen
            .iter()
            .map(|e| StateComponent { name: e.name.clone(), hash: format_hash(&e.digest), size_bytes: e.size_bytes })
            .collect();
        Ok(ModelIdentity {
            model_hash: format_hash(&self.files.named_set_digest()),
            model_format,
            parameter_count: self.parameter_count,
            architecture,
            learned_state_hash: format_hash(&digest_of(chosen.iter().copied())),
            learned_state_components,
            derived_from: self.derived_from.clone(),
            statement_references: self.statement_references.clone(),
        })
    }

    /// The components named in `names`: each a name of §7.2, a file of the
    /// model, given once; returned in §7.2's order.
    fn chosen_components(&self, names: &[String]) -> Result<Vec<&FileEntry>, Error> {
        if names.is_empty() {
            return Err(Error::InvalidInput(
                "no component named: a record lists at least one component (spec §7.3)".into(),
            ));
        }
        let mut sorted: Vec<&String> = names.iter().collect();
        sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let mut chosen = Vec::with_capacity(sorted.len());
        let mut previous: Option<&str> = None;
        for name in sorted {
            validate_name(name).map_err(|why| {
                Error::InvalidInput(format!("component \"{name}\" is not a name of spec §7.2: {}", why.reason()))
            })?;
            if previous == Some(name.as_str()) {
                return Err(Error::InvalidInput(format!("component \"{name}\" is named twice")));
            }
            let entry = self.files.get(name).ok_or_else(|| {
                Error::InvalidInput(format!("component \"{name}\" is not a file of the model"))
            })?;
            chosen.push(entry);
            previous = Some(name.as_str());
        }
        Ok(chosen)
    }

    /// Assemble the record and sign it through the engine-free assembly
    /// (`crate::assemble::sign_record`), which refuses what a verifier must
    /// refuse and the issuer-side time order before the key is used.
    pub fn build(&self, key: &SigningKey) -> Result<Record, Error> {
        let model_identity = self.model_identity()?;
        let training = Self::require(&self.training, "training")?;
        let record_id = Self::require(&self.record_id, "record_id")?;
        let issued_at = Self::require(&self.issued_at, "issued_at")?;
        let issuer = Self::require(&self.issuer, "issuer")?;
        let training_environment = Self::require(&self.training_environment, "training_environment")?;
        let training_input_provenance = Self::require(&self.training_input_provenance, "training_input_provenance")?;
        let policy_compliance = Self::require(&self.policy_compliance, "policy_compliance")?;
        let lineage = Self::require(&self.lineage, "lineage")?;
        let (digest, root, count, format, disclosure) = match &training {
            Training::Records(records) => {
                let c = commit_records(records);
                (format_hash(&c.digest), format_hash(&c.merkle_root), c.count, Some(NAMED_SET_V1.to_string()), None)
            }
            Training::NotHeld => (String::new(), String::new(), 0, None, Some("not-held".to_string())),
            Training::NotDisclosed => (String::new(), String::new(), 0, None, Some("not-disclosed".to_string())),
        };
        let learning_provenance = LearningProvenance {
            training_input_digest: digest,
            training_input_merkle_root: root,
            training_input_count: count,
            training_epochs: self.training_epochs,
            training_started_at: self.training_started_at.clone(),
            training_ended_at: self.training_ended_at.clone(),
            training_environment,
            training_input_provenance,
            training_input_format: format,
            training_input_disclosure: disclosure,
        };
        sign_record(
            RecordParts {
                record_id,
                issued_at,
                issuer,
                model_identity,
                learning_provenance,
                deployment_context: self.deployment_context.clone(),
                policy_compliance,
                lineage,
                data_governance: self.data_governance.clone(),
                human_oversight: self.human_oversight.clone(),
            },
            key,
        )
    }
}
