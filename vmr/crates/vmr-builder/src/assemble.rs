//! The record assembly: bind the issuer to the signing key, check the
//! record, sign it.
// ============================================================================
//  assemble.rs — every step between a record's parts and its signature
//
//  Moved from vmr-provenance's builder.rs (task 10.13a, D13a-1, commit B1),
//  unchanged: the key binding (QA P3-07), the schema, consistency and
//  lineage checks a verifier makes (so no record is signed that a verifier
//  must reject at its own issued_at), the issuer-side time order (QA P5-08),
//  and the ES256 signature over the COSE Sig_structure of the canonical
//  payload. The engine profile's RecordBuilder and the general description
//  both sign through here.
//
//  Determinism: no clock, no randomness. RFC 6979 makes the signature a
//  function of the key and the payload.
// ============================================================================

use crate::error::Error;
use p256::ecdsa::SigningKey;
use vmr_record::hash::{format_hash, sha256};
use vmr_record::record::{
    DeploymentContext, DocumentationRef, Issuer, JwkPublicKey, LearningProvenance, Lineage, ModelIdentity, Record,
    PolicyCompliance, SignatureSection,
};
use vmr_record::timestamp::Timestamp;

/// Everything a record states, before its key binding and signature: each a
/// caller's input, none read from a clock or drawn at random.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordParts {
    /// The record's id (`urn:uuid:...`).
    pub record_id: String,
    /// The issuance timestamp (RFC 3339 UTC).
    pub issued_at: String,
    /// The issuer section. `public_key` must be the signing key's JWK;
    /// `key_id` may be empty, and is then derived from the key.
    pub issuer: Issuer,
    /// What the model is (spec §7).
    pub model_identity: ModelIdentity,
    /// How it was trained, as the issuer states it (spec §8).
    pub learning_provenance: LearningProvenance,
    /// Where it runs, stated by the party deploying it; absent otherwise.
    pub deployment_context: Option<DeploymentContext>,
    /// The issuer's declared policy evaluation.
    pub policy_compliance: PolicyCompliance,
    /// The lineage section.
    pub lineage: Lineage,
    /// The issuer's data governance documentation, by hash.
    pub data_governance: Option<DocumentationRef>,
    /// The issuer's human oversight documentation, by hash.
    pub human_oversight: Option<DocumentationRef>,
}

/// Bind `issuer` to the signing key (QA P3-07) and return the key's id. The
/// issuer's JWK must be the signing key's, and the key id is derived from
/// it - the RFC 7638 thumbprint URN. An empty `issuer.key_id` is filled in;
/// any other value must already be the derived one.
pub fn bind_key(issuer: &mut Issuer, key: &SigningKey) -> Result<String, Error> {
    let jwk = JwkPublicKey::from_verifying_key(key.verifying_key());
    if issuer.public_key != jwk {
        return Err(Error::InvalidInput(
            "issuer.public_key is not the signing key's public key (JWK)".into(),
        ));
    }
    let signing_key_id = jwk.key_id();
    if issuer.key_id.is_empty() {
        issuer.key_id = signing_key_id.clone();
    } else if issuer.key_id != signing_key_id {
        return Err(Error::InvalidInput(format!(
            "issuer.key_id {:?} is not the signing key's RFC 7638 thumbprint URN {signing_key_id}",
            issuer.key_id
        )));
    }
    Ok(signing_key_id)
}

/// Assemble the record and sign it. Before the key is used the record must
/// pass `validate_format`, `check_consistency` and
/// `check_lineage_consistency` (spec §2, §7, §6.5), and its time claims must
/// be in order (training ends no earlier than it starts and no later than
/// `issued_at`, data collection ends no earlier than it starts -
/// issuer-side only: spec v0.1 has no such rule; and the declared policy
/// evaluation is no later than `issued_at`, which the verifier checks too
/// since P6-6); a violation is `Error::InvalidInput` naming the field
/// (`/lineage/...: lineage: ...`, `/learning_provenance/...: time order:
/// ...`).
pub fn sign_record(parts: RecordParts, key: &SigningKey) -> Result<Record, Error> {
    let RecordParts {
        record_id,
        issued_at,
        mut issuer,
        model_identity,
        learning_provenance,
        deployment_context,
        policy_compliance,
        lineage,
        data_governance,
        human_oversight,
    } = parts;
    let signing_key_id = bind_key(&mut issuer, key)?;

    let mut record = Record {
        record_version: "0.1".into(),
        record_id,
        issued_at,
        issuer,
        model_identity,
        learning_provenance,
        deployment_context,
        policy_compliance,
        lineage,
        data_governance,
        human_oversight,
        signature: SignatureSection {
            algorithm: String::new(),
            signature: String::new(),
            signed_payload_hash: String::new(),
            signing_key_id: signing_key_id.clone(),
        },
    };

    // Never sign what a verifier must reject at issued_at (Phase 4 task
    // 4.3a): every value rule of the schema (ids, timestamps, DIDs, enums,
    // hashes, integer ranges), the model and training consistency of spec
    // §7 and §8 and the lineage consistency of spec §6.5 (the verifier's
    // lineage.consistency, the same function; Phase 5 review) are checked
    // before the key is used. The signature section is still empty here; its
    // rules are the signature's own. (Whether issued_at lies in the future is
    // the caller's to judge: the builder reads no clock. `vmr record emit`
    // refuses it, QA P5-04.)
    record
        .validate_format()
        .map_err(|v| Error::InvalidInput(v.to_string()))?;
    record
        .check_consistency()
        .map_err(|v| Error::InvalidInput(v.to_string()))?;
    record
        .check_lineage_consistency()
        .map_err(|v| Error::InvalidInput(v.to_string()))?;
    // And more than a verifier asks: time claims that contradict each other
    // are refused too (issuer-side hygiene, QA P5-08).
    check_time_order(&record).map_err(Error::InvalidInput)?;

    // Sign: the ES256 signature covers the COSE Sig_structure of the
    // canonical payload (the record minus its signature section), so the
    // JSON form and the COSE envelope carry identical signature bytes.
    let sig = vmr_record::sign::sign(key, &record.signature_tbs()?)?;
    record.signature = SignatureSection {
        algorithm: "ES256".into(),
        signature: SignatureSection::signature_field(&sig),
        signed_payload_hash: format_hash(&sha256(&record.signed_payload()?)),
        signing_key_id,
    };
    Ok(record)
}

/// The builder's own rule for a record's time claims (QA P5-08): they must
/// not contradict each other.
///
/// - training ends no earlier than it starts
///   (`training_ended_at >= training_started_at`);
/// - data collection ends no earlier than it starts
///   (`collection_period.end >= collection_period.start`);
/// - training ended no later than the record is issued
///   (`training_ended_at <= issued_at`);
/// - the declared policy evaluation is no later than the record is issued
///   (`policy_compliance.evaluated_at <= issued_at`, P6-6): the evaluation is
///   inside the signed payload, so a later one claims a result the signature
///   could not have covered. Unlike the three above, this relation IS a
///   verifier rule as well (`time.policy_not_after_issued`, spec 6.2).
///
/// This is **issuer-side hygiene, not a verification rule**: record format
/// v0.1 (`specs/record-format-v0.1.md` §6) has no such check, so a
/// verifier - `vmr-verify` included, unchanged - accepts a record another
/// builder signed with contradictory times. The builder refuses to sign one,
/// so that every issuer using it gets the check. Called after
/// `validate_format`, so every timestamp here is already a valid one. A
/// relation whose member is absent (an optional time the issuer does not
/// state, spec §2 rule 3; task 10.11b) is not checked.
fn check_time_order(p: &Record) -> Result<(), String> {
    let time = |pointer: &str, value: &str| {
        Timestamp::parse(value).map_err(|v| format!("{pointer}: {}", v.detail))
    };
    let l = &p.learning_provenance;
    let started =
        l.training_started_at.as_deref().map(|v| time("/learning_provenance/training_started_at", v)).transpose()?;
    let ended =
        l.training_ended_at.as_deref().map(|v| time("/learning_provenance/training_ended_at", v)).transpose()?;
    let issued = time("/issued_at", &p.issued_at)?;
    const PERIOD: &str = "/learning_provenance/training_input_provenance/collection_period";
    let period = match &l.training_input_provenance.collection_period {
        Some(period) => Some((time(&format!("{PERIOD}/start"), &period.start)?, time(&format!("{PERIOD}/end"), &period.end)?)),
        None => None,
    };
    if let (Some(started), Some(ended)) = (&started, &ended) {
        if ended < started {
            return Err(format!(
                "/learning_provenance/training_ended_at: time order: {ended} is before training_started_at \
                 {started} - training cannot end before it starts"
            ));
        }
    }
    if let Some((from, to)) = &period {
        if to < from {
            return Err(format!(
                "{PERIOD}/end: time order: {to} is before its start {from} - a collection period cannot \
                 end before it starts"
            ));
        }
    }
    if let Some(ended) = &ended {
        if *ended > issued {
            return Err(format!(
                "/learning_provenance/training_ended_at: time order: {ended} is after issued_at {issued} - \
                 a record cannot attest training that had not ended when it was issued"
            ));
        }
    }
    let evaluated = time("/policy_compliance/evaluated_at", &p.policy_compliance.evaluated_at)?;
    if evaluated > issued {
        return Err(format!(
            "/policy_compliance/evaluated_at: time order: {evaluated} is after issued_at {issued} - \
             an evaluation cannot post-date the signature that covers it"
        ));
    }
    Ok(())
}
