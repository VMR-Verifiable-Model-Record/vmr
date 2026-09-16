//! The Verifiable Model Record v0.1 schema and its serialization/signing methods.
// ============================================================================
//  record.rs — the Verifiable Model Record, v0.1 (TASKS 3.7)
//
//  The schema mirrors docs/tlm_product_design_spec.md §2 and is pinned by
//  specs/record-schema/v0.1.json. Field names are snake_case and are
//  serialized as-is; the JSON Schema file is the normative reference.
//
//  Signing contract (§2.9): the signature covers the JCS canonical form of
//  the record with the `signature` section REMOVED.
//
//  Unknown fields (QA P3-01): every struct denies unknown fields, and the
//  schema closes every object (`additionalProperties: false`). The signed
//  payload is re-serialized from the parsed struct, so a member the parser
//  dropped would never reach the signature check while staying in the
//  document other tools read. A record carrying any member the schema
//  does not define is therefore rejected at parse time, at every level.
//
//  Objects written as arrays (QA QT-01): serde's derive also reads a struct
//  from the array of its values in declaration order, which re-serialises to
//  the signed payload. Both record forms are therefore read through
//  crate::strict_json, which reads a JSON array only as a sequence.
// ============================================================================

use crate::canonical::{jcs, MAX_SAFE_INTEGER};
use crate::error::Error;
use crate::hash::{format_hash, sha256};
use coset::CborSerializable;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The Verifiable Model Record: a signed, portable record of what a model learned,
/// where it learned it, and under which policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Schema version this record conforms to ("0.1").
    pub record_version: String,
    /// Globally unique record identifier (`urn:uuid:...`), caller-supplied.
    pub record_id: String,
    /// Issuance timestamp, caller-supplied (RFC 3339 UTC). Never generated
    /// from a clock: determinism requires the caller to own time.
    pub issued_at: String,
    /// Who created this record.
    pub issuer: Issuer,
    /// What was learned.
    pub model_identity: ModelIdentity,
    /// How it learned.
    pub learning_provenance: LearningProvenance,
    /// Where it runs, stated by the party deploying the model. Optional
    /// (spec §2 rule 3, §7.6; task 10.11b, D11b-10): a record for a model
    /// its issuer does not deploy omits it, and `null` is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub deployment_context: Option<DeploymentContext>,
    /// What rules it satisfies.
    pub policy_compliance: PolicyCompliance,
    /// What came before.
    pub lineage: Lineage,
    /// The document the issuer names as its data governance documentation,
    /// pinned by hash (task 10.11a). Optional: omitted when `None`, and
    /// `null` is rejected (spec §2.3), so a record without it serialises
    /// exactly as one did before the member existed.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub data_governance: Option<DocumentationRef>,
    /// The document the issuer names as its human oversight documentation,
    /// pinned by hash (task 10.11a). Optional, as `data_governance` is.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub human_oversight: Option<DocumentationRef>,
    /// The cryptographic binding (excluded from the signed payload).
    ///
    /// Required in the JSON form (spec §2, schema `required`): a document
    /// without it is rejected by the parser, not given an empty section
    /// (Phase 4 task 4.0b). The signature-free COSE payload is parsed through
    /// a separate internal type (`UnsignedRecord`).
    pub signature: SignatureSection,
}

/// The COSE payload: a record without its `signature` section (spec §3).
/// Parsed only by [`crate::cose::decode_record`]; its fields are exactly
/// [`Record`]'s, and the exhaustive destructuring there makes the compiler
/// keep the two in step.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnsignedRecord {
    pub(crate) record_version: String,
    pub(crate) record_id: String,
    pub(crate) issued_at: String,
    pub(crate) issuer: Issuer,
    pub(crate) model_identity: ModelIdentity,
    pub(crate) learning_provenance: LearningProvenance,
    #[serde(default, deserialize_with = "present_some")]
    pub(crate) deployment_context: Option<DeploymentContext>,
    pub(crate) policy_compliance: PolicyCompliance,
    pub(crate) lineage: Lineage,
    #[serde(default, deserialize_with = "present_some")]
    pub(crate) data_governance: Option<DocumentationRef>,
    #[serde(default, deserialize_with = "present_some")]
    pub(crate) human_oversight: Option<DocumentationRef>,
    /// A `signature` member has no place in the signed payload. It is
    /// accepted by the parser only so that decoding can reject it as a
    /// non-canonical payload — the reason every conformant COSE verifier
    /// would give — rather than as an unknown field.
    #[serde(default)]
    pub(crate) signature: Option<serde::de::IgnoredAny>,
}

/// A document the issuer names, pinned by SHA-256: the value of
/// `data_governance` and `human_oversight` (task 10.11a).
///
/// The hash says which document the issuer relied on. It says nothing about
/// what the document contains, whether anyone can obtain it, or whether it
/// meets a requirement: a verifier never fetches or hashes the document, and
/// the builder never reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationRef {
    /// `sha256:<hex>` of the document's bytes (spec §2 rule 5; no `""`).
    pub documentation_hash: String,
}

/// Deserialize an optional member that, when present, must be a string:
/// absent → `None` (with `#[serde(default)]`), `null` → an error. Spec §2.3:
/// optional members are omitted, never `null` (Phase 4 task 4.0b).
fn present_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

/// Deserialize an optional member of any type the same way: absent → `None`
/// (with `#[serde(default)]`), `null` → an error (spec §2.3; task 10.11a).
fn present_some<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// An optional record integer: absent → `None` (with `#[serde(default)]`),
/// `null` → an error, a value above 2^53 - 1 → an error (task 10.11b).
fn present_safe_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    safe_u64(d).map(Some)
}

/// Deserialize a record integer field: at most 2^53 - 1 (QA P3-10).
fn safe_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let v = u64::deserialize(d)?;
    if v > MAX_SAFE_INTEGER {
        return Err(serde::de::Error::custom(format!(
            "integer {v} exceeds 2^53 - 1, the largest exact JSON (IEEE-754) integer"
        )));
    }
    Ok(v)
}

impl Record {
    /// Every integer field must be at most 2^53 - 1 (QA P3-10): a larger
    /// value has no exact ECMAScript number, so its JCS form could not be
    /// both RFC 8785-conformant and faithful. Checked before anything is
    /// canonicalized or signed; the parser enforces the same limit.
    fn check_integer_range(&self) -> Result<(), Error> {
        let mut fields: Vec<(&str, u64)> =
            self.model_identity.parameter_count.map(|n| ("model_identity.parameter_count", n)).into_iter().collect();
        fields.extend([
            ("learning_provenance.training_input_count", self.learning_provenance.training_input_count),
            ("lineage.lineage_chain_length", self.lineage.lineage_chain_length),
        ]);
        if let Some(epochs) = self.learning_provenance.training_epochs {
            fields.push(("learning_provenance.training_epochs", epochs));
        }
        for c in &self.model_identity.learned_state_components {
            fields.push(("model_identity.learned_state_components[].size_bytes", c.size_bytes));
        }
        match fields.into_iter().find(|&(_, v)| v > MAX_SAFE_INTEGER) {
            Some((name, v)) => Err(Error::InvalidInput(format!(
                "{name} = {v} exceeds 2^53 - 1, the largest exact JSON (IEEE-754) integer"
            ))),
            None => Ok(()),
        }
    }

    /// The canonical signed payload: JCS of this record with the
    /// `signature` section removed. Fails if an integer field exceeds
    /// 2^53 - 1.
    pub fn signed_payload(&self) -> Result<Vec<u8>, Error> {
        self.check_integer_range()?;
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("signature");
        }
        Ok(jcs(&value).into_bytes())
    }

    /// `sha256:<hex>` of the signed payload.
    pub fn signed_payload_hash(&self) -> Result<String, Error> {
        Ok(format_hash(&sha256(&self.signed_payload()?)))
    }

    /// Serialize to (pretty-printed) JSON.
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse a record from JSON. Every object must be a JSON object: one
    /// written as the array of its values, which serde's derive would read as
    /// the struct, is refused (spec §2 rule 2; QA QT-01,
    /// [`crate::strict_json`]).
    pub fn from_json(text: &str) -> Result<Self, Error> {
        Ok(crate::strict_json::from_str(text)?)
    }

    /// The exact bytes the ES256 signature covers: the COSE_Sign1
    /// Sig_structure of this record's canonical signed payload (protected
    /// header: `alg = ES256`, `kid = signing_key_id`; empty external AAD).
    /// The JSON form and the COSE envelope sign the same bytes, so one
    /// record has one signature in both representations.
    pub fn signature_tbs(&self) -> Result<Vec<u8>, Error> {
        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .key_id(self.signature.signing_key_id.as_bytes().to_vec())
            .build();
        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(self.signed_payload()?)
            .build();
        Ok(sign1.tbs_data(&[]))
    }

    /// Envelope this record as a COSE_Sign1 byte string carrying the
    /// record's own signature (no re-signing — the JSON and COSE forms
    /// are the same artifact).
    pub fn to_cose(&self) -> Result<Vec<u8>, Error> {
        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .key_id(self.signature.signing_key_id.as_bytes().to_vec())
            .build();
        let sig = self.signature.parsed_signature()?;
        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(self.signed_payload()?)
            .signature(sig.to_bytes().to_vec())
            .build();
        Ok(sign1.to_vec()?)
    }

    /// Decode a COSE_Sign1 envelope back into a record, reconstructing
    /// the `signature` section from the envelope's header and signature.
    ///
    /// Strict (spec §4.4): the envelope must be exactly the canonical form
    /// [`Record::to_cose`] produces — untagged, protected header
    /// `{1: -7, 4: kid}`, empty unprotected header, a 64-byte `r ‖ s`, and a
    /// payload that is byte-for-byte the canonical signed payload (no
    /// `signature` member, no other encoding of the same content: the COSE
    /// signature covers the payload bytes as they stand, so re-canonicalizing
    /// here would accept what every conformant COSE verifier rejects). See
    /// [`crate::cose::decode_record`], which this delegates to, for the
    /// typed reasons.
    pub fn from_cose(bytes: &[u8]) -> Result<Self, Error> {
        crate::cose::decode_record(bytes).map_err(Error::from)
    }

    /// Verify this record against `key`. **This proves integrity, not
    /// trust.**
    ///
    /// `Ok(())` means exactly: the record is internally consistent and was
    /// signed by the private key belonging to `key`. Checked, in order:
    ///
    /// 1. `signature.algorithm` is exactly `ES256` (QA P3-05);
    /// 2. `signature.signed_payload_hash` is the hash of the recomputed
    ///    canonical payload (QA P3-05);
    /// 3. key binding (QA P3-07): `key` is `issuer.public_key`, whose RFC 7638
    ///    thumbprint URN is `issuer.key_id`, which equals
    ///    `signature.signing_key_id` (the COSE `kid`);
    /// 4. the ES256 signature over the COSE Sig_structure, low-s only.
    ///
    /// It does **not** mean the record comes from the issuer it names.
    /// `issuer_id` and `issuer_name` are claims: anyone can generate a key,
    /// embed it, and sign any content, and that record verifies against its
    /// own embedded key. Trust comes only from where `key` comes from — a
    /// trust store that maps the key id to a known issuer (Phase 4). Never
    /// pass the record's own `issuer.public_key` here and call the result
    /// "verified".
    ///
    /// Equivalent to [`Record::check_integrity`] with its typed reason
    /// converted into an [`Error`] (same variants and messages as before the
    /// typed form existed).
    pub fn verify_signature(
        &self,
        key: &p256::ecdsa::VerifyingKey,
    ) -> Result<(), Error> {
        self.check_integrity(key).map_err(Error::from)
    }
}

/// Prefix of the signature section's `signature` string.
const SIGNATURE_PREFIX: &str = "base64url:";

impl SignatureSection {
    /// The `signature` field for `sig`: `base64url:` followed by the
    /// unpadded base64url of the 64-byte `r || s` — the same bytes the COSE
    /// envelope carries (QA P3-02).
    pub fn signature_field(sig: &p256::ecdsa::Signature) -> String {
        format!("{SIGNATURE_PREFIX}{}", crate::sign::signature_to_b64url(sig))
    }

    /// Parse the `signature` field: the `base64url:` prefix is required and
    /// the value must decode to exactly 64 raw `r || s` bytes.
    pub fn parsed_signature(&self) -> Result<p256::ecdsa::Signature, Error> {
        let text = self.signature.strip_prefix(SIGNATURE_PREFIX).ok_or_else(|| {
            Error::InvalidInput(format!(
                "signature field must start with '{SIGNATURE_PREFIX}'"
            ))
        })?;
        crate::sign::signature_from_b64url(text)
    }
}

/// §2.3 — who created this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    /// DID of the issuer (`did:web:...`).
    pub issuer_id: String,
    /// Human-readable issuer name.
    pub issuer_name: String,
    /// The issuer's public key as a JWK.
    pub public_key: JwkPublicKey,
    /// The RFC 7638 SHA-256 JWK thumbprint of `public_key`, in RFC 9278 URN
    /// form: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<base64url>`
    /// (see [`crate::jwk`]).
    pub key_id: String,
    /// `hardware`, `software`, or `self`.
    pub attestation_level: String,
}

/// An EC P-256 public key in JWK form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwkPublicKey {
    /// `EC`
    pub kty: String,
    /// `P-256`
    pub crv: String,
    /// Base64url x coordinate.
    pub x: String,
    /// Base64url y coordinate.
    pub y: String,
}

/// §2.4 — what was learned (spec §7).
///
/// `model_format` selects the rules the section follows (spec §7.1): the
/// registered profile `snn-compact-v1` (the KHALM engine's state, §7.4), or
/// the general description (§7.3) for every other value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelIdentity {
    /// `sha256:<hex>`: in general, the named-set digest of every file the
    /// model is distributed as (§7.3); in the profile, `learned_state_hash`.
    pub model_hash: String,
    /// The model's format, which selects the rules of §7.
    pub model_format: String,
    /// The issuer's count of learned parameters (at most 2^53 - 1). Optional
    /// (spec §2 rule 3; QA QB-09): absent, the issuer does not state it, as
    /// the general description allows (§7.3); the profile `snn-compact-v1`
    /// requires and checks it (§7.4). Omitted when `None`, and `null` is
    /// rejected.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_safe_u64")]
    pub parameter_count: Option<u64>,
    /// Descriptive architecture facts (not prescriptive).
    pub architecture: Architecture,
    /// `sha256:<hex>`: in general, the named-set digest of the components
    /// (§7.3); in the profile, the SHA-256 of the engine's serialised state.
    pub learned_state_hash: String,
    /// The components, one or more (§7.3; exactly three in the profile).
    pub learned_state_components: Vec<StateComponent>,
    /// The models this model was made from (§7.5). Optional: omitted when
    /// `None`, and `null` is rejected (task 10.11b, D11b-6).
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub derived_from: Option<Vec<BaseModel>>,
    /// Other signed statements about the same model, each by its format and
    /// digest, ascending by digest (spec §7.7; task 10.11e). Optional: omitted
    /// when `None`, and `null` is rejected. A verifier checks their form only,
    /// never the statements they name.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub statement_references: Option<Vec<StatementReference>>,
}

/// A signed statement about the model that a record names (spec §7.7; task
/// 10.11e, D11e-2 to D11e-4). Nothing here says where the statement is, and
/// nothing reads it: an entry is checked for its form only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatementReference {
    /// The kind of statement, and which of its bytes `digest` hashes: a
    /// registered format without `.` (`oms-v1`, `vmr-audit-checkpoint-v1`),
    /// or the issuer's own with one.
    pub format: String,
    /// `sha256:<hex>` of the bytes `format` names (for `oms-v1`, the DSSE
    /// envelope's payload after base64 decoding; for
    /// `vmr-audit-checkpoint-v1`, the checkpoint's signed payload); no `""`.
    pub digest: String,
}

/// A model another model was made from (spec §7.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseModel {
    /// The base model's own `model_hash` (`sha256:<hex>`, no `""`).
    pub model_hash: String,
    /// The issuer's label for the base model, which nothing checks (may be
    /// `""`).
    pub name: String,
    /// `fine-tune`, `adapter`, `merge`, `quantization`, `distillation` or
    /// `other`.
    pub relation: String,
}

/// Descriptive architecture facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Architecture {
    /// e.g. `spiking-neural-network`
    #[serde(rename = "type")]
    pub kind: String,
    /// e.g. `fully-connected`
    pub topology: String,
    /// e.g. `int8`
    pub precision: String,
}

/// One hashed component of the model (spec §7.3, §7.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateComponent {
    /// In general, a name of spec §7.2 (normally a file's path); in the
    /// profile, `afferent_H`, `recurrent_H` or `thresholds`.
    pub name: String,
    /// `sha256:<hex>` of the component's bytes.
    pub hash: String,
    /// Component size in bytes (at most 2^53 - 1).
    #[serde(deserialize_with = "safe_u64")]
    pub size_bytes: u64,
}

/// §2.5 — how it learned (spec §8): the training the model went through at
/// its issuer's hands, or of which its issuer holds records (§7.6).
///
/// Every optional member is omitted when `None`, and `null` is rejected
/// (spec §2 rule 3): absent says that the issuer does not state it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningProvenance {
    /// The digest of the training records in their format (§8.2), or `""`
    /// when the record commits to none (§8.4).
    pub training_input_digest: String,
    /// The Merkle root over the records (§8.3), or `""` when the record
    /// commits to none (§8.4).
    pub training_input_merkle_root: String,
    /// The number of records committed (at most 2^53 - 1); 0 when none are.
    #[serde(deserialize_with = "safe_u64")]
    pub training_input_count: u64,
    /// Training epochs (at most 2^53 - 1). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_safe_u64")]
    pub training_epochs: Option<u64>,
    /// RFC 3339 UTC, caller-supplied. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub training_started_at: Option<String>,
    /// RFC 3339 UTC, caller-supplied. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub training_ended_at: Option<String>,
    /// Environment in which training ran.
    pub training_environment: TrainingEnvironment,
    /// Declared provenance of the training data (a claim, not a proof).
    pub training_input_provenance: TrainingInputProvenance,
    /// How the records are defined and ordered (§8.2): `named-set-v1`,
    /// `khalmtrn-frame-v1` or the issuer's own. Present on a general record
    /// that commits records; absent in the `snn-compact-v1` profile and when
    /// nothing is committed. Optional; never `""`.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub training_input_format: Option<String>,
    /// `not-disclosed` or `not-held` when the record commits to no training
    /// records (§8.4). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub training_input_disclosure: Option<String>,
}

/// Environment in which training ran (spec §8.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingEnvironment {
    /// `sha256:<hex>` of a statement of the hardware's identity, or `""` when
    /// not attested.
    pub hardware_id: String,
    /// `sha256:<hex>` of a TEE's measurement, as its TEE family encodes it,
    /// or `""` when none.
    pub tee_measurement: String,
    /// `sha256:<hex>` of a description of the training software, or `""`.
    pub software_hash: String,
    /// The accelerator's software and its version as the issuer names it,
    /// for instance a GPU toolkit's. Optional; never `""` (task 10.11b,
    /// D11b-8; task 10.12a, D12a-1, in place of one vendor's `cuda_version`).
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub accelerator_software: Option<String>,
    /// The training software and its version as the issuer names it, or `""`
    /// (task 10.12a, D12a-2: formerly `engine_version`).
    pub training_software: String,
    /// The accelerator hardware as the issuer names it (vendor, model,
    /// count). Optional; never `""`.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub accelerator: Option<String>,
}

/// Declared provenance of the training data (spec §8.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingInputProvenance {
    /// e.g. `sensor_stream`, or `""` when not stated.
    pub source_type: String,
    /// Free-form human description, or `""`.
    pub source_description: String,
    /// One ISO 3166-1 alpha-2 code, when all the data resides in one country.
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub data_residency: Option<String>,
    /// The period spanning all of the data's collection. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub collection_period: Option<Period>,
    /// Two or more codes, ascending, when the data resides in several
    /// countries; `data_residency` is then absent. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_some")]
    pub data_residency_countries: Option<Vec<String>>,
}

/// A [start, end] time window (RFC 3339 UTC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Period {
    /// Start, inclusive.
    pub start: String,
    /// End, inclusive.
    pub end: String,
}

/// §2.6 — where it runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentContext {
    /// Deployment identifier (`urn:uuid:...`), caller-supplied.
    pub deployment_id: String,
    /// RFC 3339 UTC, caller-supplied.
    pub deployed_at: String,
    /// DID of the deployer.
    pub deployed_by: String,
    /// `sha256:<hex>` hardware identifier, or `""`.
    pub hardware_id: String,
    /// `sha256:<hex>` TEE measurement, or `""`.
    pub tee_measurement: String,
    /// `sha256:<hex>` software hash, or `""`.
    pub software_hash: String,
    /// The declared inference boundary.
    pub inference_boundary: InferenceBoundary,
    /// The policy pack governing this deployment.
    pub policy_pack_id: String,
}

/// The declarative sovereignty boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceBoundary {
    /// e.g. `air-gapped`
    #[serde(rename = "type")]
    pub kind: String,
    /// Whether model egress is allowed at all.
    pub egress_allowed: bool,
    /// Egress destinations allowed when `egress_allowed` is true.
    pub allowed_egress_destinations: Vec<String>,
}

/// §2.7 — what rules it satisfies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCompliance {
    /// The policy pack that was evaluated.
    pub policy_pack_id: String,
    /// RFC 3339 UTC, caller-supplied.
    pub evaluated_at: String,
    /// One entry per evaluated rule.
    pub results: Vec<PolicyResult>,
    /// `compliant`, `non-compliant`, or `indeterminate`.
    pub overall_status: String,
}

/// One rule evaluation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResult {
    /// Rule identifier, e.g. `example-data-residency`.
    pub rule_id: String,
    /// `pass` or `fail`.
    pub status: String,
    /// `sha256:<hex>` pointer to the evidence.
    pub evidence_hash: String,
}

/// §2.8 — what came before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lineage {
    /// The previous record's id; `None` for `initial` lineage. In JSON:
    /// omitted when `None`, and `null` is rejected (spec §2.3).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_string"
    )]
    pub previous_record_id: Option<String>,
    /// The previous record's hash; `None` for `initial` lineage. In JSON:
    /// omitted when `None`, and `null` is rejected (spec §2.3).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_string"
    )]
    pub previous_record_hash: Option<String>,
    /// Length of the lineage chain (1 for the initial record; at most
    /// 2^53 - 1).
    #[serde(deserialize_with = "safe_u64")]
    pub lineage_chain_length: u64,
    /// The chain's root record id.
    pub root_record_id: String,
    /// `initial`, `training-update`, `fine-tune`, `quantization`,
    /// `deployment`, or `policy-change`.
    pub lineage_type: String,
}

/// §2.9 — the cryptographic binding. Excluded from the signed payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureSection {
    /// `ES256`
    pub algorithm: String,
    /// `base64url:` + the unpadded base64url of the raw 64-byte `r || s`
    /// (86 characters) — the JOSE ES256 encoding, and the exact bytes of the
    /// COSE_Sign1 signature. Never DER.
    pub signature: String,
    /// `sha256:<hex>` of the canonical signed payload.
    pub signed_payload_hash: String,
    /// The signing key's id — equal to `issuer.key_id` (the RFC 9278 URN of
    /// its RFC 7638 thumbprint). It is the COSE protected header's `kid`, so
    /// the signature binds it.
    pub signing_key_id: String,
}
