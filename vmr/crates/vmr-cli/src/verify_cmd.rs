//! `vmr record verify` (TASKS 5.3).
// ============================================================================
//  verify_cmd.rs — read two files, take the time, ask vmr-verify, render
//
//  The call sequence of docs/dev/phase4.md §3.6: (1) the trust store →
//  TrustStore::from_json, an unusable store is the operator's error (exit
//  1); (2) the evaluation time: --at, else the current UTC second (the one
//  clock read, clock.rs); (3) the record and any predecessors, bounded
//  reads; (4) Verifier::verify, which detects the form, with the lineage
//  options and NO policy evaluator (none exists before Phase 6, C6); (5)
//  the §3.5 rendering or --json, and the report's exit code. The verifier
//  never returns an error: a malformed, truncated or forged record is a
//  report with verdict fail (exit 3), never a crash.
//
//  Step (4) changed with P6-13: with --policy-pack the verifier IS given a
//  policy evaluator, `policy_pack::PackEvaluator` over vmr-policy, and the
//  report then carries an evaluation next to the issuer's declaration.
//  Nothing else about the sequence moves. The pack is read and validated
//  BEFORE the record is verified, so an unusable pack is exit 1 without a
//  verification result being produced at all - a bad pack must not look like
//  a bad record. The evaluator is only ever called for a record that
//  passed (vmr-verify decides that, not this module), and it is handed
//  `opts.evaluation_time`: this verifier's own time, never the record's
//  declared `evaluated_at` (P6-6 is about the issuer's embedded evaluation).
//
//  6.16 (P6-14, P6-16) adds the pack's own authority signature to that
//  prelude. The authorities it is checked against come from --authority-store
//  when it is given (a trust store whose issuers are empty), else from the
//  trust store's policy_authorities: never both. The pack's signature is
//  decided before the record is read. A signature that does not verify, and
//  --require-signed-pack refusing an unsigned or untrusted pack, are exit 1
//  with no report, like any unusable pack. The evaluation time is taken
//  before the pack, because a trusted authority key's window is judged at it
//  (a pack carries no signed time).
//
//  The two stores are one root of trust split over two files, so the rule
//  that gives a key one role inside a store (A16-3) holds across them too
//  (QA16-01, A16-25): an authority store holding a key the trust store trusts
//  for an issuer is refused, after both stores load and before the pack is
//  read.
// ============================================================================

use crate::clock::{self, TimeSource};
use crate::cli::VerifyArgs;
use crate::error::{CliError, EXIT_OK, EXIT_POLICY_NOT_ACCEPTED, EXIT_VERIFICATION_FAILED};
use crate::files::{self, shown, ReadError};
use crate::output::Output;
use crate::policy_pack::{self, Authorities};
use crate::render;
use std::path::Path;
use vmr_verify::policy::PolicyEvaluator;
use vmr_verify::trust_store::MAX_TRUST_STORE_BYTES;
use vmr_verify::{TrustStore, VerificationReport, Verifier, VerifyOptions};

/// What a trust store is, for the hint of a refusal.
const TRUST_STORE_HINT: &str = concat!(
    "a trust store is the verifier operator's list of trusted issuers and keys; build one with `",
    crate::tool_name!(),
    " trust-store add` (format: specs/trust-store-format-v0.1.md)"
);

/// The stable id of refusing an authority store that lists issuers (A16-7,
/// A16-22).
pub const AUTHORITY_STORE_ISSUERS: &str = "authority_store.issuers";

/// The stable id of refusing an authority store that holds a key the trust
/// store trusts for an issuer (docs/dev/task-6.16.md A16-25).
pub const AUTHORITY_STORE_ISSUER_KEY: &str = "authority_store.issuer_key";

/// What an authority store is, for the hint of a refusal.
const AUTHORITY_STORE_HINT: &str = "an authority store is a trust store listing only the policy authorities whose keys may sign policy packs: \"issuers\": [] and a \"policy_authorities\" list (specs/trust-store-format-v0.1.md §4.2)";

/// Run `record verify`.
pub fn run(args: &VerifyArgs) -> Result<Output, CliError> {
    let store = load_trust_store(&args.trust_store)?;
    let authority_store = match &args.authority_store {
        Some(path) => {
            let authorities = load_authority_store(path)?;
            refuse_issuer_keys(&store, &authorities, path)?;
            Some(authorities)
        }
        None => None,
    };
    let (at, source) = clock::given_or_now(args.at, "--at")?;
    let pack = match &args.policy_pack {
        Some(path) => {
            let authorities = match &authority_store {
                Some(authority_store) => Authorities::AuthorityStore(authority_store),
                None => Authorities::TrustStore(&store),
            };
            Some(policy_pack::load(path)?.check_signature(
                authorities,
                at,
                args.require_signed_pack.then_some("--require-signed-pack"),
            )?)
        }
        None => None,
    };
    let record = files::read_document(&args.record, "record")?;
    let previous = args
        .previous
        .iter()
        .map(|p| files::read_document(p, "predecessor record"))
        .collect::<Result<Vec<_>, _>>()?;
    let refs: Vec<&[u8]> = previous.iter().map(Vec::as_slice).collect();
    let mut opts = VerifyOptions::new(at)
        .with_previous(&refs)
        .require_complete_lineage(args.require_lineage);
    if let Some(evaluator) = &pack {
        opts = opts.with_policy(evaluator as &dyn PolicyEvaluator);
    }

    let report = Verifier::new(store).verify(&record, &opts);
    let out = Output { stdout: rendered(&report, args.json, source)?, rich: None, code: exit_code(&report) };
    // The terminal screen (docs/dev/cli-polish.md CP-2); never for --json,
    // which is data.
    Ok(if args.json { out } else { out.with_rich(crate::screens::verification(&report, source)) })
}

/// The report as the user asked for it: the §3.5 summary, or the report's
/// own JSON followed by a newline.
fn rendered(report: &VerificationReport, json: bool, source: TimeSource) -> Result<String, CliError> {
    if json {
        let text = report
            .to_json()
            .map_err(|e| CliError::input(format!("cannot write the report as JSON: {e}")))?;
        Ok(format!("{text}\n"))
    } else {
        Ok(render::verification(report, source))
    }
}

/// The exit code of a verification: the report's own (0 accepted, 3 verdict
/// fail, 4 verified but not accepted). Anything else it could ever return is
/// treated as a failure.
fn exit_code(report: &VerificationReport) -> u8 {
    match report.exit_code() {
        0 => EXIT_OK,
        4 => EXIT_POLICY_NOT_ACCEPTED,
        _ => EXIT_VERIFICATION_FAILED,
    }
}

/// Read and validate a trust store. Every failure is the operator's (exit
/// 1), named by the loader's stable kind (`trust_store.*`,
/// specs/trust-store-format-v0.1.md §3) — never a verification result.
pub fn load_trust_store(path: &Path) -> Result<TrustStore, CliError> {
    load_store(path, "trust store", TRUST_STORE_HINT)
}

/// Read and validate an authority store (`--authority-store`, P6-16): a store
/// of the trust-store format whose `issuers` is empty
/// (specs/trust-store-format-v0.1.md §4.2). Every failure is the operator's
/// (exit 1). A store that lists issuers is one of them: its issuers would be
/// trusted for nothing a reader could see. That refusal's stable id is
/// [`AUTHORITY_STORE_ISSUERS`] (docs/dev/task-6.16.md A16-22).
pub fn load_authority_store(path: &Path) -> Result<TrustStore, CliError> {
    let store = load_store(path, "authority store", AUTHORITY_STORE_HINT)?;
    if store.issuer_count() > 0 {
        return Err(CliError::input(format!(
            "authority store {} cannot be used: {AUTHORITY_STORE_ISSUERS}: it trusts {}, and an authority store \
             lists only policy_authorities, with \"issuers\": []",
            shown(path),
            render::plural(store.issuer_count() as u64, "issuer", "issuers")
        ))
        .with_hint(
            "keep the issuers records are verified against in --trust-store; an authority store lists only \
             the policy authorities whose keys may sign packs (specs/trust-store-format-v0.1.md §4.2)",
        ));
    }
    Ok(store)
}

/// Refuse an authority store that holds a key `store` trusts for an issuer
/// (A16-25). With it one key would speak for records and for the packs they
/// are judged by, which A16-3 refuses inside one store
/// (`trust_store.duplicate_key`). Keys are compared as the loader compares
/// them there, by `key_id`, which it has checked is the thumbprint of the key.
/// The first such key in the authority store's canonical order is named.
fn refuse_issuer_keys(store: &TrustStore, authorities: &TrustStore, path: &Path) -> Result<(), CliError> {
    let document = authorities.to_document();
    let Some(issuer_key) =
        document.policy_authorities.iter().flat_map(|authority| &authority.keys).find_map(|key| store.lookup(&key.key_id))
    else {
        return Ok(());
    };
    // The key id passed the loader's thumbprint check and the issuer id its
    // DID syntax (ASCII, no controls): both are safe to print whole.
    Err(CliError::input(format!(
        "authority store {} cannot be used: {AUTHORITY_STORE_ISSUER_KEY}: it trusts {} for a policy authority, and the \
         trust store trusts the same key for issuer {}: one key may not vouch both for records and for the policy \
         packs they are judged by",
        shown(path),
        issuer_key.key_id,
        issuer_key.issuer_id
    ))
    .with_hint(
        "an organisation that issues records and signs policy packs holds one key for each role: its issuer key \
         in --trust-store, and another key for its packs in --authority-store (specs/trust-store-format-v0.1.md §4.2)",
    ))
}

/// Read and validate a file of the trust-store format, called `what` in every
/// refusal ("trust store", "authority store"), with `hint` for a store the
/// loader refuses.
fn load_store(path: &Path, what: &str, hint: &'static str) -> Result<TrustStore, CliError> {
    let unusable = |why: String| {
        CliError::input(format!("{what} {} cannot be used: {why}", shown(path))).with_hint(hint)
    };
    let bytes = match files::read_bounded(path, MAX_TRUST_STORE_BYTES as u64) {
        Ok(bytes) => bytes,
        Err(ReadError::TooLarge(size)) => {
            return Err(unusable(format!(
                "trust_store.size: the file is {size} bytes; the limit is {MAX_TRUST_STORE_BYTES} (16 MiB)"
            )))
        }
        Err(ReadError::Io(e)) => return Err(CliError::input(format!("cannot read {what} {}: {e}", shown(path)))),
    };
    TrustStore::from_json(&bytes).map_err(|e| match files::byte_order_mark(&bytes) {
        // Still refused (a trust store is UTF-8 JSON), but saying why: the
        // loader's "expected value (line 1, column 1)" points at invisible
        // bytes (QA P5-07).
        Some(bom) => CliError::input(format!(
            "{what} {} cannot be used: {e}: {bom}, which a {what} may not have",
            shown(path)
        ))
        .with_hint(files::SAVE_WITHOUT_BOM),
        None => unusable(e.to_string()),
    })
}
