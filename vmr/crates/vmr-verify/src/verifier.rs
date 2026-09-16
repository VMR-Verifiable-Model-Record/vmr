//! The verifier: runs the checks of `specs/record-format-v0.1.md` §6.2 in
//! order and returns a report.
// ============================================================================
//  verifier.rs — Verifier, VerifyOptions, the fail-fast pipeline (4.1-4.6, 4.4)
//
//  A pipeline is a fixed sequence of check ids per input form. Checks run in
//  that order; the first failure ends the run and every later check of the
//  sequence is recorded as skipped, so each input has one canonical reason.
//  Verification never returns an error and never panics: garbage in, a
//  report with verdict `fail` out (plan §3.3, Law 9).
//
//  Trust (spec §6.3): the key a signature is verified with comes from the
//  trust store, looked up by `signature.signing_key_id` — never from the
//  record. The record's own `issuer.public_key` is only parsed, to check
//  that the record is self-consistent about its key (key.binding); no
//  ECDSA verification ever runs against it.
//
//  Inputs that fully determine a report (plan §5.1): the input bytes, the
//  trust store, the evaluation time, and (later tasks) the predecessors and
//  options. No clock, environment, locale, file system or network is read.
// ============================================================================

use crate::policy::{PolicyEvaluator, PolicyStatus, VerifiedRecord};
use crate::report::{
    verdict_of, CheckId, CheckResult, EvaluationState, InputForm, InputSummary, IssuerSummary,
    LineageReport, LineageStatus, LinkSummary, Outcome, RecordSummary, PolicyReport,
    TrustStoreSummary, VerificationReport, Verdict, REPORT_VERSION,
};
use crate::text::{bounded, escape_controls, quote, serde_detail};
use crate::trust_store::{AttestationLevel, TrustStore, TrustedKey};
use vmr_record::hash::{format_hash, sha256};
use vmr_record::timestamp::Timestamp;
use vmr_record::validate::ModelDescription;
use vmr_record::Record;

/// The largest record a verifier reads, in either form: 1 MiB
/// (spec §6.1).
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// The most predecessors a verifier walks (spec §6.1).
pub const MAX_PREDECESSORS: usize = 1024;

/// What a verification depends on besides the record and the trust store.
/// Build with [`VerifyOptions::new`] and the `with_…` / `require_…`
/// methods; later versions may add options without breaking callers.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct VerifyOptions<'a> {
    /// The evaluation time `T`: the moment the record is judged at. Always
    /// the caller's value — the verifier never reads a clock (spec §6.4).
    pub evaluation_time: Timestamp,
    /// The record's predecessors, as the bytes of their JSON or COSE
    /// forms, immediate predecessor first (spec §6.5). The verifier never
    /// fetches one.
    pub previous: &'a [&'a [u8]],
    /// Fail `lineage.chain` unless the supplied predecessors reach an
    /// initial record (otherwise a partial or unchecked lineage is
    /// reported, not failed).
    pub require_complete_lineage: bool,
    /// A policy evaluator to run on the record if — and only if — it
    /// verifies (spec §6.6). Its result never changes the verdict; it
    /// decides `accepted`.
    pub policy: Option<&'a dyn PolicyEvaluator>,
}

impl std::fmt::Debug for VerifyOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyOptions")
            .field("evaluation_time", &self.evaluation_time)
            .field("previous", &self.previous.len())
            .field("require_complete_lineage", &self.require_complete_lineage)
            .field("policy", &self.policy.map(|p| p.policy_pack_id().to_string()))
            .finish()
    }
}

impl<'a> VerifyOptions<'a> {
    /// Options for a verification at `evaluation_time`, with no predecessors
    /// and no complete-lineage requirement.
    pub fn new(evaluation_time: Timestamp) -> Self {
        VerifyOptions {
            evaluation_time,
            previous: &[],
            require_complete_lineage: false,
            policy: None,
        }
    }

    /// Evaluate the record with `evaluator` if it verifies.
    pub fn with_policy(mut self, evaluator: &'a dyn PolicyEvaluator) -> Self {
        self.policy = Some(evaluator);
        self
    }

    /// The record's predecessors, immediate predecessor first.
    pub fn with_previous(mut self, previous: &'a [&'a [u8]]) -> Self {
        self.previous = previous;
        self
    }

    /// Whether the lineage must be verified back to an initial record.
    pub fn require_complete_lineage(mut self, required: bool) -> Self {
        self.require_complete_lineage = required;
        self
    }
}

/// Verifies records against one trust store.
#[derive(Debug, Clone)]
pub struct Verifier {
    store: TrustStore,
}

/// The JSON form's check sequence (spec §6.2): 21 checks.
const JSON_SEQUENCE: &[CheckId] = &[
    CheckId::InputSize,
    CheckId::InputForm,
    CheckId::JsonSyntax,
    CheckId::JsonStructure,
    CheckId::FormatSchema,
    CheckId::FormatConsistency,
    CheckId::SignatureAlgorithm,
    CheckId::SignatureEncoding,
    CheckId::SignatureLowS,
    CheckId::SignaturePayloadHash,
    CheckId::KeyBinding,
    CheckId::TrustKeyKnown,
    CheckId::SignatureValid,
    CheckId::TrustIssuer,
    CheckId::TrustKeyNotRevoked,
    CheckId::TrustKeyValidity,
    CheckId::TrustAttestation,
    CheckId::TimeNotFuture,
    CheckId::TimePolicyNotAfterIssued,
    CheckId::LineageConsistency,
    CheckId::LineageChain,
];

/// The COSE form's check sequence (spec §6.2): 25 checks.
const COSE_SEQUENCE: &[CheckId] = &[
    CheckId::InputSize,
    CheckId::InputForm,
    CheckId::CoseStructure,
    CheckId::CoseProtectedHeader,
    CheckId::CoseUnprotectedHeader,
    CheckId::CoseSignatureEncoding,
    CheckId::CosePayload,
    CheckId::CoseCanonical,
    CheckId::FormatSchema,
    CheckId::FormatConsistency,
    CheckId::SignatureAlgorithm,
    CheckId::SignatureEncoding,
    CheckId::SignatureLowS,
    CheckId::SignaturePayloadHash,
    CheckId::KeyBinding,
    CheckId::TrustKeyKnown,
    CheckId::SignatureValid,
    CheckId::TrustIssuer,
    CheckId::TrustKeyNotRevoked,
    CheckId::TrustKeyValidity,
    CheckId::TrustAttestation,
    CheckId::TimeNotFuture,
    CheckId::TimePolicyNotAfterIssued,
    CheckId::LineageConsistency,
    CheckId::LineageChain,
];

/// An input of neither form: only these two checks apply.
const UNKNOWN_SEQUENCE: &[CheckId] = &[CheckId::InputSize, CheckId::InputForm];

/// The COSE decode checks 3c-8c, in order.
const COSE_DECODE_CHECKS: [CheckId; 6] = [
    CheckId::CoseStructure,
    CheckId::CoseProtectedHeader,
    CheckId::CoseUnprotectedHeader,
    CheckId::CoseSignatureEncoding,
    CheckId::CosePayload,
    CheckId::CoseCanonical,
];

/// The checks every record runs once decoded, in any form (spec §6.2,
/// checks 5 onward) — the in-memory form's whole sequence.
const RECORD_SEQUENCE: &[CheckId] = &[
    CheckId::FormatSchema,
    CheckId::FormatConsistency,
    CheckId::SignatureAlgorithm,
    CheckId::SignatureEncoding,
    CheckId::SignatureLowS,
    CheckId::SignaturePayloadHash,
    CheckId::KeyBinding,
    CheckId::TrustKeyKnown,
    CheckId::SignatureValid,
    CheckId::TrustIssuer,
    CheckId::TrustKeyNotRevoked,
    CheckId::TrustKeyValidity,
    CheckId::TrustAttestation,
    CheckId::TimeNotFuture,
    CheckId::TimePolicyNotAfterIssued,
    CheckId::LineageConsistency,
    CheckId::LineageChain,
];

/// What a run learns on its way, for the report.
#[derive(Default)]
struct Findings {
    record: Option<RecordSummary>,
    issuer: Option<IssuerSummary>,
    lineage: Option<LineageReport>,
    /// The predecessors whose links verified, decoded, in walk order: what a
    /// policy evaluator may read (P6-17). Never serialized.
    predecessors: Vec<Record>,
}

impl Verifier {
    /// A verifier that trusts exactly the keys of `store`.
    pub fn new(store: TrustStore) -> Self {
        Verifier { store }
    }

    /// The trust store this verifier trusts.
    pub fn trust_store(&self) -> &TrustStore {
        &self.store
    }

    /// Verify `input` in whichever form it is: JSON when its first byte that
    /// is not JSON whitespace is `{`, COSE when its first byte is `0x84`.
    /// Anything else fails `input.form` (form `unknown`).
    pub fn verify(&self, input: &[u8], opts: &VerifyOptions<'_>) -> VerificationReport {
        self.verify_detecting(input, opts).0
    }

    /// Verify `input` as the JSON form of a record (spec §2).
    pub fn verify_json(&self, input: &[u8], opts: &VerifyOptions<'_>) -> VerificationReport {
        self.verify_json_inner(input, opts).0
    }

    /// Verify `input` as the COSE form of a record (spec §4.4): exactly
    /// the canonical envelope, then the record's checks — with, at
    /// `signature.valid`, a standard COSE verification of the envelope as
    /// received next to the reconstructed-TBS check.
    pub fn verify_cose(&self, input: &[u8], opts: &VerifyOptions<'_>) -> VerificationReport {
        self.verify_cose_inner(input, opts).0
    }

    /// Verify a record already in memory (e.g. one just built): the checks
    /// from `format.schema` on, exactly as for a decoded record. The
    /// report's input is the record's compact JSON serialization.
    pub fn verify_record(&self, record: &Record, opts: &VerifyOptions<'_>) -> VerificationReport {
        let bytes = serde_json::to_vec(record).unwrap_or_default();
        let mut run = Run::new(RECORD_SEQUENCE);
        let mut found = Findings { record: Some(RecordSummary::of(record)), ..Findings::default() };
        let _ended = self.record_checks(&mut run, &mut found, record, None, opts);
        self.report(InputForm::InMemory, &bytes, opts, run, found, Some(record))
    }

    /// [`Verifier::verify`], also returning the decoded record.
    fn verify_detecting(&self, input: &[u8], opts: &VerifyOptions<'_>) -> (VerificationReport, Option<Record>) {
        if input.first() == Some(&0x84) {
            return self.verify_cose_inner(input, opts);
        }
        if input.iter().copied().find(|&b| !is_json_whitespace(b)) == Some(b'{') {
            return self.verify_json_inner(input, opts);
        }
        let mut run = Run::new(UNKNOWN_SEQUENCE);
        let _ended = (|| -> Result<(), Stop> {
            run.record(CheckId::InputSize, check_size(input))?;
            run.record(CheckId::InputForm, Err(unknown_form(input)))
        })();
        (self.report(InputForm::Unknown, input, opts, run, Findings::default(), None), None)
    }

    fn verify_json_inner(&self, input: &[u8], opts: &VerifyOptions<'_>) -> (VerificationReport, Option<Record>) {
        let mut run = Run::new(JSON_SEQUENCE);
        let mut found = Findings::default();
        let mut decoded = None;
        let _ended = (|| -> Result<(), Stop> {
            run.record(CheckId::InputSize, check_size(input))?;
            run.record(CheckId::InputForm, check_json_form(input))?;
            let text = run.record(CheckId::JsonSyntax, check_json_syntax(input))?;
            let record = run.record(CheckId::JsonStructure, check_json_structure(text))?;
            found.record = Some(RecordSummary::of(&record));
            let result = self.record_checks(&mut run, &mut found, &record, None, opts);
            decoded = Some(record);
            result
        })();
        let report = self.report(InputForm::Json, input, opts, run, found, decoded.as_ref());
        (report, decoded)
    }

    fn verify_cose_inner(&self, input: &[u8], opts: &VerifyOptions<'_>) -> (VerificationReport, Option<Record>) {
        let mut run = Run::new(COSE_SEQUENCE);
        let mut found = Findings::default();
        let mut decoded = None;
        let _ended = (|| -> Result<(), Stop> {
            run.record(CheckId::InputSize, check_size(input))?;
            run.record(CheckId::InputForm, check_cose_form(input))?;
            let record = cose_decode(&mut run, input)?;
            found.record = Some(RecordSummary::of(&record));
            let result = self.record_checks(&mut run, &mut found, &record, Some(input), opts);
            decoded = Some(record);
            result
        })();
        let report = self.report(InputForm::Cose, input, opts, run, found, decoded.as_ref());
        (report, decoded)
    }

    /// Checks 5-21: format, signature, key binding, trust, time, lineage.
    /// `envelope` is the COSE input as received, for the second signature
    /// check.
    fn record_checks(
        &self,
        run: &mut Run,
        found: &mut Findings,
        p: &Record,
        envelope: Option<&[u8]>,
        opts: &VerifyOptions<'_>,
    ) -> Result<(), Stop> {
        run.record(CheckId::FormatSchema, check_format_schema(p))?;
        run.record(CheckId::FormatConsistency, check_format_consistency(p))?;
        run.record(CheckId::SignatureAlgorithm, check_signature_algorithm(p))?;
        let sig = run.record(CheckId::SignatureEncoding, check_signature_encoding(p))?;
        run.record(CheckId::SignatureLowS, check_low_s(&sig))?;
        run.record(CheckId::SignaturePayloadHash, check_payload_hash(p))?;
        run.record(CheckId::KeyBinding, check_key_binding(p))?;
        let trusted = run.record(CheckId::TrustKeyKnown, self.check_key_known(p))?;
        run.record(CheckId::SignatureValid, check_signature_valid(p, &trusted, envelope))?;
        run.record(CheckId::TrustIssuer, check_trust_issuer(p, &trusted))?;
        // The trust store's name for the issuer enters the report only now
        // (QA P4-05): the trusted key really signed this record and speaks
        // for the issuer it names. Earlier, a forgery citing a trusted (and
        // public) key id would carry the genuine issuer's name in its failed
        // report. A failure from here on keeps it: "whose revoked key".
        found.issuer = Some(IssuerSummary::of(&trusted));
        run.record(CheckId::TrustKeyNotRevoked, check_not_revoked(&trusted))?;
        let issued_at = run.record(CheckId::TrustKeyValidity, check_key_validity(p, &trusted))?;
        run.record(CheckId::TrustAttestation, check_attestation(p, &trusted))?;
        run.record(CheckId::TimeNotFuture, check_not_future(issued_at, opts.evaluation_time))?;
        run.record(CheckId::TimePolicyNotAfterIssued, check_policy_not_after_issued(p, issued_at))?;

        let lineage = found.lineage.insert(LineageReport {
            lineage_type: p.lineage.lineage_type.clone(),
            declared_chain_length: p.lineage.lineage_chain_length,
            status: LineageStatus::Broken,
            verified_links: Vec::new(),
        });
        run.record(CheckId::LineageConsistency, check_lineage_consistency(p))?;
        let (outcome, detail) = self.check_lineage_chain(p, opts, lineage, &mut found.predecessors);
        run.record_outcome(CheckId::LineageChain, outcome, detail)
    }

    fn check_key_known(&self, p: &Record) -> Stage<TrustedKey<'_>> {
        match self.store.lookup(&p.signature.signing_key_id) {
            Some(k) => {
                let detail = format!(
                    "the trust store trusts key {} for issuer {}",
                    quote(k.key_id),
                    quote(k.issuer_id)
                );
                Ok((k, detail))
            }
            None => Err(format!(
                "signing key {} is not in the trust store",
                quote(&p.signature.signing_key_id)
            )),
        }
    }

    /// Check 21 (spec §6.5): walk the supplied predecessors from the
    /// record, each verified in full on its own (same store, same `T`, no
    /// predecessors of its own), each link checked against its successor.
    /// Sets `lineage.status` and `lineage.verified_links`, and keeps each
    /// predecessor whose link verified in `verified`, in the same order.
    fn check_lineage_chain(
        &self,
        head: &Record,
        opts: &VerifyOptions<'_>,
        lineage: &mut LineageReport,
        verified: &mut Vec<Record>,
    ) -> (Outcome, String) {
        let supplied = opts.previous.len();
        let declared = head.lineage.lineage_chain_length;
        let incomplete = |lineage: &mut LineageReport, status, detail: String| {
            lineage.status = status;
            if opts.require_complete_lineage {
                (Outcome::Fail, format!("a complete lineage is required: {detail}"))
            } else {
                (Outcome::NotEvaluated, detail)
            }
        };
        if supplied > MAX_PREDECESSORS {
            return (
                Outcome::Fail,
                format!("{supplied} predecessors supplied; a verifier walks at most {MAX_PREDECESSORS}"),
            );
        }
        if head.lineage.lineage_type == "initial" {
            if supplied == 0 {
                lineage.status = LineageStatus::Initial;
                return (Outcome::Pass, "an initial record: the chain is this record".into());
            }
            return (
                Outcome::Fail,
                format!("{supplied} predecessor(s) supplied for an initial record, which has none"),
            );
        }
        if supplied == 0 {
            return incomplete(
                lineage,
                LineageStatus::NotChecked,
                format!("{declared} records declared; no predecessor supplied, none verified"),
            );
        }

        let own = VerifyOptions::new(opts.evaluation_time);
        let mut successor = head.clone();
        for (i, bytes) in opts.previous.iter().enumerate() {
            let n = i + 1;
            let (report, decoded) = self.verify_detecting(bytes, &own);
            let predecessor = match (report.verdict, decoded) {
                (Verdict::Pass, Some(p)) => p,
                _ => {
                    let why = report
                        .failure
                        .map(|f| format!("{}: {}", f.check, f.detail))
                        .unwrap_or_default();
                    return (Outcome::Fail, format!("predecessor {n} does not verify on its own: {why}"));
                }
            };
            if let Err(rule) = check_link(&successor, &predecessor) {
                return (
                    Outcome::Fail,
                    format!("predecessor {n} ({}): {rule}", quote(&predecessor.record_id)),
                );
            }
            lineage.verified_links.push(LinkSummary {
                record_id: predecessor.record_id.clone(),
                signed_payload_hash: predecessor.signed_payload_hash().unwrap_or_default(),
                lineage_type: predecessor.lineage.lineage_type.clone(),
                lineage_chain_length: predecessor.lineage.lineage_chain_length,
                issued_at: predecessor.issued_at.clone(),
            });
            verified.push(predecessor.clone());
            if predecessor.lineage.lineage_type == "initial" {
                if n < supplied {
                    return (
                        Outcome::Fail,
                        format!(
                            "{} more predecessor(s) supplied after the initial record {}",
                            supplied - n,
                            quote(&predecessor.record_id)
                        ),
                    );
                }
                lineage.status = LineageStatus::Complete;
                return (
                    Outcome::Pass,
                    format!("complete: {n} link(s) verified back to the initial record"),
                );
            }
            successor = predecessor;
        }
        incomplete(
            lineage,
            LineageStatus::Partial,
            format!(
                "partial: {supplied} link(s) verified of {declared} records declared; \
                 the chain continues beyond the last supplied predecessor"
            ),
        )
    }

    fn report(
        &self,
        form: InputForm,
        input: &[u8],
        opts: &VerifyOptions<'_>,
        run: Run,
        found: Findings,
        decoded: Option<&Record>,
    ) -> VerificationReport {
        let checks = run.finish();
        let (verdict, failure) = verdict_of(&checks);
        let evaluation =
            evaluate_policy(opts, verdict, decoded, found.issuer.as_ref(), found.lineage.as_ref(), &found.predecessors);
        let accepted = verdict == Verdict::Pass
            && match &evaluation {
                EvaluationState::NotRequested => true,
                EvaluationState::Evaluated { status, .. } => *status == PolicyStatus::Compliant,
                EvaluationState::Skipped { .. } | EvaluationState::EvaluatorPanicked { .. } => false,
            };
        VerificationReport {
            report_version: REPORT_VERSION,
            verdict,
            failure,
            accepted,
            evaluation_time: opts.evaluation_time.to_string(),
            input: InputSummary {
                form,
                byte_length: input.len() as u64,
                sha256: format_hash(&sha256(input)),
            },
            trust_store: TrustStoreSummary {
                sha256: self.store.sha256().to_string(),
                issuer_count: self.store.issuer_count() as u64,
                key_count: self.store.key_count() as u64,
            },
            previous: opts.previous.iter().map(|b| format_hash(&sha256(b))).collect(),
            require_complete_lineage: opts.require_complete_lineage,
            record: found.record,
            issuer: found.issuer,
            checks,
            lineage: found.lineage,
            policy: PolicyReport {
                declared: decoded.map(|p| p.policy_compliance.clone()),
                evaluation,
            },
        }
    }
}

/// The policy evaluation (spec §6.6): only for a verified record, with a
/// panicking evaluator contained - the one panic containment in the
/// verifier (plan §5.8; vmr-ffi does the same for step hooks, QA F-16).
fn evaluate_policy(
    opts: &VerifyOptions<'_>,
    verdict: Verdict,
    decoded: Option<&Record>,
    issuer: Option<&IssuerSummary>,
    lineage: Option<&LineageReport>,
    predecessors: &[Record],
) -> EvaluationState {
    let Some(evaluator) = opts.policy else {
        return EvaluationState::NotRequested;
    };
    // A pass verdict means checks 20 and 21 ran, so the lineage is known.
    let (Verdict::Pass, Some(record), Some(issuer), Some(lineage)) = (verdict, decoded, issuer, lineage)
    else {
        return EvaluationState::Skipped {
            reason: "the verdict is fail: a policy is evaluated only on a verified record".into(),
        };
    };
    let pack = evaluator.policy_pack_id().to_string();
    let verified = VerifiedRecord::new(record, issuer, lineage, predecessors);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        evaluator.evaluate(&verified, opts.evaluation_time)
    }));
    match result {
        Ok(evaluation) => {
            let declared = &record.policy_compliance.policy_pack_id;
            let detail = (declared != &pack).then(|| {
                escape_controls(format!(
                    "the record declares policy pack {}; the evaluator applied {}",
                    quote(declared),
                    quote(&pack)
                ))
            });
            EvaluationState::Evaluated {
                policy_pack_id: pack,
                policy_pack_version: evaluation.pack_version,
                policy_pack_payload_hash: evaluation.pack_payload_hash,
                pack_signature: evaluation.pack_signature,
                authority_store: evaluation.authority_store.map(Box::new),
                status: evaluation.status,
                rules: evaluation.rules,
                detail,
            }
        }
        Err(_) => EvaluationState::EvaluatorPanicked { policy_pack_id: pack },
    }
}

// ---------------------------------------------------------------------------
//  The run: fail-fast, every check of the sequence accounted for
// ---------------------------------------------------------------------------

/// A check failed: the run ends.
struct Stop;

/// A check's outcome: `Ok((value, detail))` passes, `Err(detail)` fails.
type Stage<T> = Result<(T, String), String>;

struct Run {
    sequence: &'static [CheckId],
    checks: Vec<CheckResult>,
}

impl Run {
    fn new(sequence: &'static [CheckId]) -> Self {
        Run { sequence, checks: Vec::with_capacity(sequence.len()) }
    }

    /// Record `id`'s outcome; a failure ends the run. Every detail passes
    /// through [`escape_controls`] on its way into the report.
    fn record<T>(&mut self, id: CheckId, stage: Stage<T>) -> Result<T, Stop> {
        match stage {
            Ok((value, detail)) => {
                self.checks.push(CheckResult { id, outcome: Outcome::Pass, detail: escape_controls(detail) });
                Ok(value)
            }
            Err(detail) => {
                self.checks.push(CheckResult { id, outcome: Outcome::Fail, detail: escape_controls(detail) });
                Err(Stop)
            }
        }
    }

    /// Record an outcome that may be `NotEvaluated` (lineage.chain); only a
    /// failure ends the run.
    fn record_outcome(&mut self, id: CheckId, outcome: Outcome, detail: String) -> Result<(), Stop> {
        self.checks.push(CheckResult { id, outcome, detail: escape_controls(detail) });
        if outcome == Outcome::Fail {
            Err(Stop)
        } else {
            Ok(())
        }
    }

    /// The checks, with every check of the sequence that did not run
    /// recorded as skipped.
    fn finish(mut self) -> Vec<CheckResult> {
        let done = self.checks.len();
        for &id in self.sequence.iter().skip(done) {
            self.checks.push(CheckResult {
                id,
                outcome: Outcome::Skipped,
                detail: "not run: an earlier check failed".into(),
            });
        }
        self.checks
    }
}

// ---------------------------------------------------------------------------
//  Checks 1-2 and 3j-4j
// ---------------------------------------------------------------------------

fn check_size(input: &[u8]) -> Stage<()> {
    if input.len() > MAX_RECORD_BYTES {
        Err(format!(
            "{} bytes; a v0.1 record is at most {MAX_RECORD_BYTES} bytes (1 MiB)",
            input.len()
        ))
    } else {
        Ok(((), format!("{} bytes (at most {MAX_RECORD_BYTES})", input.len())))
    }
}

const UTF8_BOM: [u8; 3] = [0xef, 0xbb, 0xbf];

fn is_json_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn check_json_form(input: &[u8]) -> Stage<()> {
    if input.starts_with(&UTF8_BOM) {
        return Err("the input starts with a UTF-8 byte order mark (EF BB BF); \
                    a JSON record has none"
            .into());
    }
    match input.iter().copied().find(|&b| !is_json_whitespace(b)) {
        Some(b'{') => Ok(((), "a JSON object".into())),
        None if input.is_empty() => Err("empty input".into()),
        None => Err("the input is only whitespace".into()),
        Some(0x84) if input.first() == Some(&0x84) => Err(
            "the first byte is 0x84, a 4-element CBOR array: this is the COSE form, not JSON"
                .into(),
        ),
        Some(b) => Err(format!("the first byte that is not whitespace is 0x{b:02x}, not '{{'")),
    }
}

fn check_json_syntax(input: &[u8]) -> Stage<&str> {
    let text = std::str::from_utf8(input).map_err(|e| format!("not UTF-8: {e}"))?;
    // A pure syntax pass: every value is skipped (iteratively, so nesting
    // depth costs no stack), members are not interpreted.
    serde_json::from_str::<serde::de::IgnoredAny>(text)
        .map_err(|e| format!("not RFC 8259 JSON: {}", serde_detail(&e)))?;
    Ok((text, "UTF-8, RFC 8259 JSON, nothing after the value".into()))
}

fn check_json_structure(text: &str) -> Stage<Record> {
    // The text is valid JSON: whatever the typed parse rejects is structure,
    // whatever category serde_json files it under.
    match Record::from_json(text) {
        Ok(p) => Ok((p, "exactly the schema's members and JSON types".into())),
        Err(vmr_record::Error::Json(e)) => Err(serde_detail(&e)),
        Err(other) => Err(bounded(&other.to_string())),
    }
}

// ---------------------------------------------------------------------------
//  Checks 2 and 3c-8c for the COSE form
// ---------------------------------------------------------------------------

fn check_cose_form(input: &[u8]) -> Stage<()> {
    match input.first() {
        Some(0x84) => Ok(((), "an untagged 4-element CBOR array".into())),
        _ => Err(unknown_form(input)),
    }
}

/// Why `input` is in neither form (or not in the one asked for).
fn unknown_form(input: &[u8]) -> String {
    let first_json = input.iter().copied().find(|&b| !is_json_whitespace(b));
    match input.first() {
        None => "empty input".into(),
        Some(_) if input.starts_with(&UTF8_BOM) => {
            "the input starts with a UTF-8 byte order mark (EF BB BF)".into()
        }
        Some(0xd2) => "the input is a tagged COSE_Sign1 (CBOR tag 18, 0xD2); v0.1 envelopes \
                       are untagged, starting with 0x84"
            .into(),
        Some(b) if b >> 5 == 6 => {
            format!("the input starts with a CBOR tag (0x{b:02x}); v0.1 envelopes are untagged")
        }
        Some(_) if first_json == Some(b'{') => {
            "the input is a JSON object: this is the JSON form, not COSE".into()
        }
        Some(b) => format!(
            "the input starts with 0x{b:02x}: neither a JSON object nor an untagged COSE_Sign1 (0x84)"
        ),
    }
}

/// Run checks 3c-8c: every decode check before the one that fails passes
/// (cose::decode_record checks them in this order and stops at the first
/// failure).
fn cose_decode(run: &mut Run, input: &[u8]) -> Result<Record, Stop> {
    use vmr_record::cose::CoseDecodeError as E;
    let passed = [
        "one CBOR data item: a COSE_Sign1 array, nothing after it",
        "exactly the deterministic encoding of {1: -7 (ES256), 4: kid}; kid is UTF-8",
        "the empty map",
        "64 bytes r || s, r and s in 1..n-1",
        "the canonical signed payload of a record",
        "byte-identical to the canonical envelope of the record it carries",
    ];
    let e = match vmr_record::cose::decode_record(input) {
        Ok(p) => {
            for (id, detail) in COSE_DECODE_CHECKS.into_iter().zip(passed) {
                run.record(id, Ok(((), detail.to_string())))?;
            }
            return Ok(p);
        }
        Err(e) => e,
    };
    let failed_at = match &e {
        E::Tagged | E::Cbor(_) | E::NotSign1(_) => CheckId::CoseStructure,
        E::ProtectedHeader(_) => CheckId::CoseProtectedHeader,
        E::UnprotectedHeader => CheckId::CoseUnprotectedHeader,
        E::SignatureEncoding(_) => CheckId::CoseSignatureEncoding,
        E::NoPayload | E::Payload(_) | E::PayloadNotCanonical => CheckId::CosePayload,
        E::NotCanonical => CheckId::CoseCanonical,
    };
    let failure = match &e {
        E::Payload(vmr_record::Error::Json(j)) => {
            format!("the payload is not a record: {}", serde_detail(j))
        }
        other => bounded(&other.to_string()),
    };
    for (id, detail) in COSE_DECODE_CHECKS.into_iter().zip(passed) {
        if id == failed_at {
            break;
        }
        run.record(id, Ok(((), detail.to_string())))?;
    }
    run.record(failed_at, Err(failure))
}

// ---------------------------------------------------------------------------
//  Checks 5-11: the record alone
// ---------------------------------------------------------------------------

fn check_format_schema(p: &Record) -> Stage<()> {
    p.validate_format()
        .map(|()| ((), "every value rule of the schema holds (outside /signature)".into()))
        .map_err(|v| v.to_string())
}

fn check_format_consistency(p: &Record) -> Stage<()> {
    p.check_consistency()
        .map(|()| {
            let described = match p.model_description() {
                // The profile snn-compact-v1 (spec §7.4): the detail every
                // record had before task 10.11b, which the golden reports pin.
                ModelDescription::KhalmEngineProfile => {
                    "three components in order; sizes, parameter_count and model_hash agree".to_string()
                }
                // The general description (spec §7.3; task 10.11b, D11b-12).
                ModelDescription::General => {
                    let n = p.model_identity.learned_state_components.len();
                    let components = if n == 1 { "1 component".to_string() } else { format!("{n} components") };
                    format!(
                        "general model description: {components} in name order; learned_state_hash is their \
                         named-set digest"
                    )
                }
            };
            // Task 10.11e (D11e-6; spec §6.3, §7.7): only a record that names
            // other signed statements gets this, so every earlier detail stays.
            let detail = match p.model_identity.statement_references.as_ref().map(Vec::len) {
                None => described,
                Some(1) => format!("{described}; 1 statement reference: declared, not checked (its form only)"),
                Some(n) => format!("{described}; {n} statement references: declared, not checked (their form only)"),
            };
            ((), detail)
        })
        .map_err(|v| v.to_string())
}

fn check_signature_algorithm(p: &Record) -> Stage<()> {
    if p.signature.algorithm == "ES256" {
        Ok(((), "ES256".into()))
    } else {
        Err(format!(
            "signature.algorithm is {}; v0.1 records are ES256 only",
            quote(&p.signature.algorithm)
        ))
    }
}

fn check_signature_encoding(p: &Record) -> Stage<p256::ecdsa::Signature> {
    p.signature
        .parsed_signature()
        .map(|sig| (sig, "base64url: + the canonical base64url of a 64-byte r || s".into()))
        .map_err(|e| {
            format!(
                "signature.signature is not base64url: + 64 bytes r || s with r, s in 1..n-1 ({})",
                bounded(&e.to_string())
            )
        })
}

fn check_low_s(sig: &p256::ecdsa::Signature) -> Stage<()> {
    if vmr_record::sign::is_high_s(sig) {
        Err("s is in the upper half of the group order (high-s); only the low-s form is valid".into())
    } else {
        Ok(((), "s <= n/2".into()))
    }
}

fn check_payload_hash(p: &Record) -> Stage<()> {
    let recomputed = p
        .signed_payload_hash()
        .map_err(|e| format!("the signed payload cannot be computed: {}", bounded(&e.to_string())))?;
    if p.signature.signed_payload_hash == recomputed {
        Ok(((), format!("{recomputed} is the hash of the canonical signed payload")))
    } else {
        Err(format!(
            "signature.signed_payload_hash {} is not the canonical signed payload's hash {recomputed}",
            quote(&p.signature.signed_payload_hash)
        ))
    }
}

fn check_key_binding(p: &Record) -> Stage<()> {
    // Parsed only to see that it IS a P-256 key: this key is never used to
    // verify anything (spec §6.3).
    if let Err(e) = p.issuer.public_key.to_verifying_key() {
        return Err(format!("issuer.public_key is not a P-256 key: {}", bounded(&e.to_string())));
    }
    let derived = p.issuer.public_key.key_id();
    if p.issuer.key_id != derived {
        return Err(format!(
            "issuer.key_id {} is not the RFC 7638 thumbprint URN of issuer.public_key",
            quote(&p.issuer.key_id)
        ));
    }
    if p.signature.signing_key_id != p.issuer.key_id {
        return Err(format!(
            "signature.signing_key_id {} differs from issuer.key_id {}",
            quote(&p.signature.signing_key_id),
            quote(&p.issuer.key_id)
        ));
    }
    Ok(((), "issuer.key_id is the thumbprint of issuer.public_key and the signing key id".into()))
}

// ---------------------------------------------------------------------------
//  Checks 13-18: under the trusted key
// ---------------------------------------------------------------------------

/// `signature.valid` when the ES256 signature over the Sig_structure does
/// not verify under the trust store's key. Its causes, in words a reader can
/// act on: the signed content changed after signing (a tamper), or the
/// signature bytes are not this key's signature over it (damaged, or made
/// with another key - a forgery citing a trusted key id).
const SIGNATURE_MISMATCH: &str = "the signature does not match the record's signed content under \
     the trust store's key: the record was changed after it was signed, or its signature was \
     damaged or made with another key";

/// The same for the COSE envelope as received (checked after the
/// Sig_structure, so reached only if the two ever diverged).
const ENVELOPE_SIGNATURE_MISMATCH: &str = "the COSE_Sign1 envelope's signature does not match its \
     content under the trust store's key: the envelope was changed after it was signed, or its \
     signature was damaged or made with another key";

fn check_signature_valid(
    p: &Record,
    trusted: &TrustedKey<'_>,
    envelope: Option<&[u8]>,
) -> Stage<()> {
    if trusted.public_key != &p.issuer.public_key {
        return Err(format!(
            "the trust store's key {} is not the record's issuer.public_key",
            quote(trusted.key_id)
        ));
    }
    // ECDSA under the TRUSTED key (spec §6.3), over the Sig_structure the
    // verifier rebuilds from the record. A mismatch is said in plain words
    // - what it means and how it comes about - never with the crypto
    // library's own text ("signature error"): this is the line a tampered
    // record shows. The other integrity failures were each a check of their
    // own already (7-11) and cannot reach here; if one did, it is named.
    p.check_integrity(trusted.verifying_key).map_err(|e| match e {
        vmr_record::integrity::IntegrityError::BadSignature(_) => SIGNATURE_MISMATCH.to_string(),
        other => format!(
            "the integrity check under the trust store's key failed: {}",
            bounded(&other.to_string())
        ),
    })?;
    // For the COSE form, also a standard COSE_Sign1 verification of the
    // envelope as received: both must pass, so a divergence between the two
    // (impossible while cose.canonical holds) could not go unnoticed.
    if let Some(bytes) = envelope {
        let sign1 = vmr_record::cose::decode_sign1(bytes)
            .map_err(|e| format!("the envelope no longer decodes: {}", bounded(&e.to_string())))?;
        vmr_record::cose::verify_sign1(&sign1, trusted.verifying_key).map_err(|e| match e {
            vmr_record::Error::Signature(_) => ENVELOPE_SIGNATURE_MISMATCH.to_string(),
            other => format!(
                "the COSE_Sign1 envelope's signature cannot be checked under the trust store's key: {}",
                bounded(&other.to_string())
            ),
        })?;
    }
    // One detail for every form, so the JSON and COSE reports of a record
    // differ only in their input and decode checks.
    Ok((
        (),
        "ES256 over the Sig_structure verifies under the trust store's key \
         (a COSE envelope is also checked as received)"
            .into(),
    ))
}

fn check_trust_issuer(p: &Record, trusted: &TrustedKey<'_>) -> Stage<()> {
    if trusted.issuer_id == p.issuer.issuer_id {
        Ok(((), format!("the key speaks for {}", quote(trusted.issuer_id))))
    } else {
        Err(format!(
            "the trust store trusts this key for {}, not for {}",
            quote(trusted.issuer_id),
            quote(&p.issuer.issuer_id)
        ))
    }
}

fn check_not_revoked(trusted: &TrustedKey<'_>) -> Stage<()> {
    if trusted.revoked {
        Err(format!("the trust store marks key {} revoked", quote(trusted.key_id)))
    } else {
        Ok(((), "not revoked".into()))
    }
}

/// Passes with `issued_at`, for the time check.
fn check_key_validity(p: &Record, trusted: &TrustedKey<'_>) -> Stage<Timestamp> {
    let issued_at = Timestamp::parse(&p.issued_at).map_err(|v| format!("issued_at: {v}"))?;
    if issued_at < trusted.valid_from {
        return Err(format!(
            "issued_at {issued_at} is before the key's valid_from {}",
            trusted.valid_from
        ));
    }
    match trusted.valid_until {
        Some(until) if issued_at >= until => Err(format!(
            "issued_at {issued_at} is not before the key's valid_until {until}"
        )),
        Some(until) => Ok((issued_at, format!("{} <= {issued_at} < {until}", trusted.valid_from))),
        None => Ok((issued_at, format!("{} <= {issued_at} (no end)", trusted.valid_from))),
    }
}

fn check_attestation(p: &Record, trusted: &TrustedKey<'_>) -> Stage<()> {
    let declared = AttestationLevel::parse(&p.issuer.attestation_level).ok_or_else(|| {
        format!("issuer.attestation_level {} is not a level", quote(&p.issuer.attestation_level))
    })?;
    if declared <= trusted.attestation_level {
        Ok((
            (),
            format!(
                "declares {}; the trust store grants {}",
                declared.as_str(),
                trusted.attestation_level.as_str()
            ),
        ))
    } else {
        Err(format!(
            "the record declares attestation {}; the trust store grants this key at most {}",
            declared.as_str(),
            trusted.attestation_level.as_str()
        ))
    }
}

fn check_not_future(issued_at: Timestamp, evaluation_time: Timestamp) -> Stage<()> {
    if issued_at <= evaluation_time {
        Ok(((), format!("issued_at {issued_at} <= evaluation time {evaluation_time}")))
    } else {
        Err(format!("issued_at {issued_at} is after the evaluation time {evaluation_time}"))
    }
}

/// Check 19 (spec §6.2, P6-6): `policy_compliance.evaluated_at` is not after
/// `issued_at`. Both are the record's own claims inside the signed payload,
/// so this check reads no evaluation time: an evaluation later than the
/// issuance claims a result the signature over it could not have covered.
/// `issued_at` is already parsed (check 16 returned it); `evaluated_at` is
/// already a rule-7 timestamp (check 5 passed), so a parse failure here is
/// impossible and is reported as a failure rather than assumed away.
fn check_policy_not_after_issued(p: &Record, issued_at: Timestamp) -> Stage<()> {
    let declared = &p.policy_compliance.evaluated_at;
    let evaluated = Timestamp::parse(declared).map_err(|v| v.detail)?;
    if evaluated <= issued_at {
        Ok(((), format!("policy evaluated_at {evaluated} <= issued_at {issued_at}")))
    } else {
        Err(format!(
            "the declared policy evaluated_at {evaluated} is after issued_at {issued_at}: an \
             evaluation inside the signed payload cannot post-date the signature over it"
        ))
    }
}

// ---------------------------------------------------------------------------
//  Checks 20-21: lineage (spec §6.5)
// ---------------------------------------------------------------------------

/// Check 20: the rule is vmr-record's (`Record::check_lineage_consistency`,
/// which the builder also runs before it signs), so a verifier and an issuer
/// can never disagree about it. A failure's detail is the rule's own (its
/// member path aside); a pass says what was found.
fn check_lineage_consistency(p: &Record) -> Stage<()> {
    p.check_lineage_consistency().map_err(|v| v.detail)?;
    let l = &p.lineage;
    if l.lineage_type == "initial" {
        return Ok(((), "initial: no predecessor, chain length 1, its own root".into()));
    }
    Ok((
        (),
        format!(
            "{}: names its predecessor, chain length {}, a root other than itself",
            quote(&l.lineage_type),
            l.lineage_chain_length
        ),
    ))
}

/// The link rules between a successor and its verified predecessor
/// (spec §6.5); the error names the rule that fails.
fn check_link(successor: &Record, predecessor: &Record) -> Result<(), String> {
    let s = &successor.lineage;
    let p = &predecessor.lineage;
    if s.previous_record_id.as_deref() != Some(predecessor.record_id.as_str()) {
        return Err(format!(
            "its record_id is not the previous_record_id {} its successor names",
            s.previous_record_id.as_deref().map(quote).unwrap_or_default()
        ));
    }
    let recomputed = predecessor
        .signed_payload_hash()
        .map_err(|e| format!("its signed payload cannot be computed: {}", bounded(&e.to_string())))?;
    if s.previous_record_hash.as_deref() != Some(recomputed.as_str()) {
        return Err(format!(
            "its signed payload hash {recomputed} is not the previous_record_hash {} its \
             successor names",
            s.previous_record_hash.as_deref().map(quote).unwrap_or_default()
        ));
    }
    if s.root_record_id != p.root_record_id {
        return Err(format!(
            "its root_record_id {} differs from its successor's {}",
            quote(&p.root_record_id),
            quote(&s.root_record_id)
        ));
    }
    if p.lineage_chain_length.checked_add(1) != Some(s.lineage_chain_length) {
        return Err(format!(
            "its lineage_chain_length {} is not one less than its successor's {}",
            p.lineage_chain_length, s.lineage_chain_length
        ));
    }
    // Both issued_at values are profile timestamps (format.schema passed for
    // both); in the profile, lexical order is chronological order, but
    // compare them as instants anyway.
    match (Timestamp::parse(&predecessor.issued_at), Timestamp::parse(&successor.issued_at)) {
        (Ok(before), Ok(after)) if before <= after => Ok(()),
        (Ok(before), Ok(after)) => Err(format!(
            "it was issued at {before}, after its successor ({after})"
        )),
        _ => Err("issued_at is not a profile timestamp".into()),
    }
}
