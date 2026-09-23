//! `vmr pack sign` and `vmr pack check` — an authority signs its own policy
//! pack, and reads back what it signed.
// ============================================================================
//  pack_cmd.rs — making a pack signature, and reading a pack on its own
//
//  The policy-pack format says any authority may publish and sign a pack, and
//  the verifier checks a pack signature in full. Until these two commands
//  there was no way to MAKE one with this tool, so the claim held of the
//  format and not of the tooling: an author had to compute the payload and
//  sign it with their own code. `pack sign` closes that gap, and it is part
//  of the free Community edition, as emitting and verifying a record are.
//
//  This module is orchestration, like the rest of the CLI. It decides nothing
//  cryptographic: `vmr_policy::sign_pack` makes the section over the format's
//  §4 payload, and `PackEvaluator::check_signature` — the same code path
//  `record verify --policy-pack` takes — decides a signature against the
//  policy authorities an operator trusts.
//
//  Nothing here privileges an authority. Any P-256 key signs any pack; the
//  tool holds no built-in authority, no default store and no baseline pack.
//  Whether a key may speak for the authority a pack names is the decision of
//  whoever checks it, and it lives in their trust store (P6-14, P6-16;
//  specs/trust-store-format-v0.1.md §4.2).
//
//  Two refusals of its own, both the author's error (exit 1):
//
//    * a pack that already carries a `signature` section, without --replace:
//      signing it again would silently discard another party's signature,
//      and a signing command may not do that quietly;
//    * an --output that exists, without --force: the same convention every
//      other command that writes a file uses (`files::write_public_new`).
//
//  `pack sign` reads the pack with `policy_pack::load_pack`, not
//  `policy_pack::load`: the latter refuses a pack whose stated
//  `signed_payload_hash` is not its own (QA Q6-05), which is exactly the
//  pack an author asks --replace to re-sign. `pack check` reads it with
//  `policy_pack::load`, so it refuses such a pack as `record verify` does.
// ============================================================================

use crate::cli::{PackCheckArgs, PackSignArgs};
use crate::clock::{self, TimeSource};
use crate::error::CliError;
use crate::files::{self, shown};
use crate::keys;
use crate::output::Output;
use crate::policy_pack::{self, Authorities};
use crate::render::{plural, shown_disclaimer, shown_value};
use crate::verify_cmd::{load_authority_store, load_trust_store};
use serde::Serialize;
use vmr_policy::{LoadedPack, Severity};
use vmr_verify::policy::{AuthorityStoreSummary, PackSignatureState};

/// The stable id of refusing to sign a pack that already carries a signature
/// without `--replace`. It is this command's own refusal, not a refusal of
/// the format: the format has nothing to say about re-signing.
pub const ALREADY_SIGNED: &str = "pack_sign.already_signed";

// ---------------------------------------------------------------------------
//  pack sign
// ---------------------------------------------------------------------------

/// Run `pack sign`.
pub fn sign(args: &PackSignArgs) -> Result<Output, CliError> {
    // A device or a directory, or either input file, is refused before
    // anything is read (QA P5-02, P5-11).
    files::check_output(
        &args.output,
        "signed policy pack",
        "--output",
        &[(&args.pack, "--pack"), (&args.key, "--key")],
    )?;
    let pack = policy_pack::load_pack(&args.pack)?;
    if let Some(section) = &pack.pack().signature {
        if !args.replace {
            // The key id passed the pack schema's pattern (a thumbprint URN),
            // so it is safe to print whole.
            return Err(CliError::input(format!(
                "policy pack {} is already signed: {ALREADY_SIGNED}: its signature section names {} as its \
                 signer, and nothing was written",
                shown(&args.pack),
                section.signing_key_id
            ))
            .with_hint(
                "sign it again with --replace, which drops the old section (the new signature covers the same \
                 payload, so the pack's payload hash does not change), or sign a copy without one",
            ));
        }
    }
    let key = keys::read_signing_key(&args.key)?;
    let section = vmr_policy::sign_pack(pack.document(), &key)
        .map_err(|e| CliError::input(format!("policy pack {} was not signed: {e}", shown(&args.pack))))?;

    // The document as received, with the section added: every other member
    // keeps its VALUE, and `signature` is the only one this command writes.
    //
    // Its LAYOUT does move: serde_json's `Value` holds an object's members in
    // sorted order (a BTreeMap, this workspace not using `preserve_order`), so
    // the file comes back sorted whatever order it was written in. Nothing
    // that is checked depends on it - the signed payload is the JCS form, and
    // so is the payload hash - and a pack already in sorted order, which is
    // what this command writes, comes back unchanged. docs/CLI.md §3.8 says
    // so, rather than letting an author discover it in a diff.
    let mut document = pack.document().clone();
    let object = document.as_object_mut().ok_or_else(|| {
        CliError::input(format!("policy pack {} is not a JSON object", shown(&args.pack)))
    })?;
    object.insert(
        "signature".to_string(),
        serde_json::to_value(&section)
            .map_err(|e| CliError::input(format!("cannot write the signature section: {e}")))?,
    );
    let text = serde_json::to_string_pretty(&document)
        .map_err(|e| CliError::input(format!("cannot write the signed policy pack as JSON: {e}")))?;
    let bytes = format!("{text}\n").into_bytes();
    // Read back with the loader before it is written: a pack this tool writes
    // is one this tool loads, and its signature verifies under the key that
    // just made it. A failure here is a fault of this tool, never the
    // author's input, and `CliError::internal` says so (still exit 1: the
    // CLI has no code of its own for it).
    let written = vmr_policy::load_pack_bytes(&bytes)
        .map_err(|e| CliError::internal(format!("the signed policy pack would not load again: {e}")))?;
    written
        .verify_signature(key.verifying_key())
        .map_err(|e| CliError::internal(format!("the signature just made does not verify: {e}")))?;
    files::write_public_new(&args.output, &bytes, args.force, "signed policy pack")?;

    let authority = &pack.pack().authority;
    // The signature --replace dropped, when it dropped one: an author signing
    // someone else's pack is told whose signature is no longer on it (L2).
    // The authority's name stays what the PACK says it is, here as in
    // `pack check`: signing a pack establishes nothing about its author (L1).
    let replaced = match &pack.pack().signature {
        Some(old) if args.replace => Some(old.signing_key_id.clone()),
        _ => None,
    };
    let mut out = format!(
        "Signed policy pack: {} {}\n  \
         Authority:    {} ({}) — the pack's own claim\n  \
         Signing key:  {}\n  \
         Payload hash: {}\n  \
         Signed pack:  {} ({})\n",
        shown_value(&pack.pack_id),
        shown_value(&pack.pack_version),
        shown_value(&authority.authority_id),
        shown_value(&authority.authority_name),
        section.signing_key_id,
        section.signed_payload_hash,
        shown(&args.output),
        if replaced.is_some() {
            "the pack as given, its signature section replaced"
        } else {
            "the pack as given, with its signature section added"
        }
    );
    if let Some(old) = &replaced {
        out.push_str(&format!("  Replaced:     the signature of {old}\n"));
    }
    let screen = crate::screens::pack_signed(&crate::screens::PackSigned {
        pack_id: &shown_value(&pack.pack_id),
        pack_version: &shown_value(&pack.pack_version),
        authority_id: &shown_value(&authority.authority_id),
        authority_name: &shown_value(&authority.authority_name),
        signing_key_id: &section.signing_key_id,
        payload_hash: &section.signed_payload_hash,
        output: &shown(&args.output),
        replaced: replaced.as_deref(),
    });
    Ok(Output::ok(out).with_rich(screen))
}

// ---------------------------------------------------------------------------
//  pack check
// ---------------------------------------------------------------------------

/// What `pack check` found, as `--json` writes it. A pack author reads this
/// to confirm what they just signed, so it states the pack's own claims and,
/// separately, what a store decided about its signature.
#[derive(Debug, Serialize)]
struct PackReport<'a> {
    /// The pack FORMAT version the pack declares.
    version: &'a str,
    /// The pack's identifier.
    pack_id: &'a str,
    /// The pack's own semantic version.
    pack_version: &'a str,
    /// The regime it encodes.
    jurisdiction: &'a str,
    /// What the pack is, in the authority's words.
    description: &'a str,
    /// What the pack is not, in the authority's words.
    disclaimer: &'a str,
    /// Who the pack says authored it: a claim until a store says otherwise.
    authority: ReportAuthority<'a>,
    /// The bytes an authority signs, hashed (format §4).
    payload_hash: &'a str,
    /// The signature's state, in the words `record verify` uses.
    signature: &'a PackSignatureState,
    /// The store that CHECKED the signature, and the time it was judged at.
    /// `null` whenever nothing was checked - no store was given, the pack is
    /// unsigned, or no authority in the store holds the key it names - so a
    /// consumer reading `checked != null` as "the signature was checked" is
    /// right (I1). A store that decided nothing is in `consulted` instead.
    checked: Option<Checked<'a>>,
    /// The store that was read and the time it would have judged at, when it
    /// decided nothing: the pack is unsigned, or names a key that store does
    /// not hold. `null` when a store checked the signature, and when none was
    /// given.
    consulted: Option<Checked<'a>>,
    /// Every rule, in the pack's order.
    rules: Vec<ReportRule<'a>>,
}

/// The authority a pack names.
#[derive(Debug, Serialize)]
struct ReportAuthority<'a> {
    /// The authority's identifier.
    authority_id: &'a str,
    /// The authority's name, as the pack states it.
    authority_name: &'a str,
}

/// The store the signature was checked against, and when.
#[derive(Debug, Serialize)]
struct Checked<'a> {
    /// The authority store, as the verifier's report names one.
    authority_store: Option<&'a AuthorityStoreSummary>,
    /// The time the key's window was judged at.
    at: String,
    /// Where that time came from: `--at`, or this machine's clock.
    time_source: &'static str,
}

/// One rule of the pack.
#[derive(Debug, Serialize)]
struct ReportRule<'a> {
    /// The rule's identifier, unique in its pack.
    rule_id: &'a str,
    /// The rule's kind.
    #[serde(rename = "type")]
    rule_type: &'static str,
    /// How a failure weighs: `mandatory`, `recommended` or `informational`.
    severity: &'static str,
    /// What the rule asks.
    description: &'a str,
    /// The clause it encodes.
    reference: &'a str,
}

/// Run `pack check`.
pub fn check(args: &PackCheckArgs) -> Result<Output, CliError> {
    let evaluator = policy_pack::load(&args.pack)?;
    // With --require-signed the states no authority vouched for - unsigned,
    // and signed by a key no trusted authority holds - are refused (exit 1)
    // instead of reported, so that `pack check ... && deploy` gates on a
    // signature the operator trusts (M1).
    let require_signed = args.require_signed.then_some("--require-signed");
    // The authorities come from the operator's own file, whichever they keep
    // them in: an authority store of its own, or the policy_authorities of
    // the trust store they verify records with - the two `record verify`
    // reads, routed the same way (M2). Clap refuses both at once.
    // What to call that store in the output: an operator reads which of their
    // own files decided this, and the two are not interchangeable.
    let store_label = if args.authority_store.is_some() { "authority store" } else { "trust store" };
    let (checked, evaluator) = match (&args.authority_store, &args.trust_store) {
        (None, None) => (None, evaluator),
        (Some(path), _) => {
            let store = load_authority_store(path)?;
            let (at, source) = clock::given_or_now(args.at, "--at")?;
            // The same decision `record verify` makes, in the same code, with
            // the same refusals: a signature that does not verify, or a key
            // that may not speak for the pack's authority, is exit 1.
            let evaluator =
                evaluator.check_signature(Authorities::AuthorityStore(&store), at, require_signed)?;
            (Some((at, source)), evaluator)
        }
        (None, Some(path)) => {
            let store = load_trust_store(path)?;
            let (at, source) = clock::given_or_now(args.at, "--at")?;
            let evaluator = evaluator.check_signature(Authorities::TrustStore(&store), at, require_signed)?;
            (Some((at, source)), evaluator)
        }
    };
    let pack = evaluator.loaded();
    let state = evaluator.signature_state();
    // A store decided the signature only when it ended `valid`: every other
    // outcome for a key the store holds is a refusal (exit 1), and a store
    // that does not hold the key checked nothing (I1).
    let decided = matches!(state, PackSignatureState::Valid { .. });
    let store_read = checked.map(|(at, source)| Checked {
        authority_store: evaluator.authority_store(),
        at: at.to_string(),
        time_source: match source {
            TimeSource::Argument(flag) => flag,
            TimeSource::Clock => "clock",
        },
    });
    let (checked_by, consulted) = if decided { (store_read, None) } else { (None, store_read) };
    let report = PackReport {
        version: &pack.version,
        pack_id: &pack.pack_id,
        pack_version: &pack.pack_version,
        jurisdiction: &pack.jurisdiction,
        description: &pack.description,
        disclaimer: &pack.disclaimer,
        authority: ReportAuthority {
            authority_id: &pack.authority.authority_id,
            authority_name: &pack.authority.authority_name,
        },
        payload_hash: pack.payload_hash(),
        signature: state,
        checked: checked_by,
        consulted,
        rules: pack
            .rules
            .iter()
            .map(|rule| {
                let common = rule.common();
                ReportRule {
                    rule_id: common.rule_id,
                    rule_type: rule.rule_type(),
                    severity: common.severity.id(),
                    description: common.description,
                    reference: common.reference,
                }
            })
            .collect(),
    };
    if args.json {
        let json = serde_json::to_string_pretty(&report)
            .map_err(|e| CliError::input(format!("cannot write the pack report as JSON: {e}")))?;
        return Ok(Output::ok(format!("{json}\n")));
    }
    let when = checked.map(|(at, source)| format!("{at} {}", source.label()));
    let signature = signature_line(state, when.as_deref(), store_label);
    let out = text(pack, &signature, &shown(&args.pack));
    let screen = crate::screens::pack_checked(&crate::screens::PackChecked {
        pack_id: &shown_value(&pack.pack_id),
        pack_version: &shown_value(&pack.pack_version),
        authority_id: &shown_value(&pack.authority.authority_id),
        authority_name: &shown_value(&pack.authority.authority_name),
        jurisdiction: &shown_value(&pack.jurisdiction),
        description: &shown_value(&pack.description),
        disclaimer: &shown_disclaimer(&pack.disclaimer),
        payload_hash: pack.payload_hash(),
        file: &shown(&args.pack),
        signature: state,
        store: store_label,
        checked: when.map(|w| format!("checked at {w}")),
        rules: pack
            .rules
            .iter()
            .map(|rule| {
                let common = rule.common();
                crate::screens::PackRule {
                    rule_id: shown_value(common.rule_id),
                    rule_type: rule.rule_type(),
                    severity: common.severity.id(),
                    description: shown_value(common.description),
                }
            })
            .collect(),
    });
    Ok(Output::ok(out).with_rich(screen))
}

/// The plain text of `pack check`.
fn text(pack: &LoadedPack, signature: &str, file: &str) -> String {
    let mandatory = pack.rules.iter().filter(|r| r.common().severity == Severity::Mandatory).count() as u64;
    let mut out = format!(
        "Policy pack: {} {}\n  \
         File:         {file}\n  \
         Authority:    {} ({}) — the pack's own claim\n  \
         Jurisdiction: {}\n  \
         Description:  {}\n  \
         Disclaimer:   {}\n  \
         Payload hash: {}\n  \
         Signature:    {signature}\n  \
         Rules:        {}, {mandatory} mandatory\n",
        shown_value(&pack.pack_id),
        shown_value(&pack.pack_version),
        shown_value(&pack.authority.authority_id),
        shown_value(&pack.authority.authority_name),
        shown_value(&pack.jurisdiction),
        shown_value(&pack.description),
        shown_disclaimer(&pack.disclaimer),
        pack.payload_hash(),
        plural(pack.rules.len() as u64, "rule", "rules"),
    );
    for rule in &pack.rules {
        let common = rule.common();
        out.push_str(&format!(
            "    {} ({}, {})\n      {}\n",
            shown_value(common.rule_id),
            rule.rule_type(),
            common.severity.id(),
            shown_value(common.description)
        ));
    }
    out
}

/// One line saying what is known about the pack's signature, and by whose
/// decision. "Signed" is never allowed to read as "checked": without a store
/// this command checks nothing, and it says so. `store` is what to call the
/// store that decided - the operator's authority store, or the trust store
/// they verify records with - so the line names the file they gave.
fn signature_line(state: &PackSignatureState, checked: Option<&str>, store: &str) -> String {
    match state {
        PackSignatureState::Unsigned => {
            "unsigned — this pack carries no authority signature (pin it by its payload hash)".to_string()
        }
        PackSignatureState::NotChecked { signing_key_id } => match checked {
            None => format!(
                "not checked — it names {signing_key_id} as its signer; pass --authority-store, or \
                 --trust-store, to check that signature against the policy authorities you trust"
            ),
            Some(_) => format!(
                "not checked — it names {signing_key_id} as its signer, and no policy authority in the \
                 {store} holds that key"
            ),
        },
        PackSignatureState::Valid { signing_key_id, authority_id, authority_name } => format!(
            "valid — signed by {signing_key_id}, which the {store} trusts for {} ({}), at {}",
            shown_value(authority_id),
            shown_value(authority_name),
            checked.unwrap_or_default()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_valid() -> PackSignatureState {
        PackSignatureState::Valid {
            signing_key_id: "urn:ietf:params:oauth:jwk-thumbprint:sha-256:AAAA".into(),
            authority_id: "an-authority.example".into(),
            authority_name: "An authority, per this operator".into(),
        }
    }

    #[test]
    fn an_unchecked_signature_never_reads_as_a_checked_one() {
        // The honesty this command exists for: a pack states its own signer,
        // and only a store the operator provisioned turns that into "valid".
        let named = PackSignatureState::NotChecked { signing_key_id: "urn:x:1".into() };
        let without = signature_line(&named, None, "authority store");
        assert!(without.starts_with("not checked — "), "{without}");
        assert!(without.contains("--authority-store"), "{without}");
        assert!(without.contains("--trust-store"), "{without}");
        let with = signature_line(&named, Some("2026-09-11T00:00:00Z (current time)"), "trust store");
        assert!(with.starts_with("not checked — "), "{with}");
        assert!(!with.contains("--authority-store"), "{with}");
        assert!(with.contains("no policy authority in the trust store holds that key"), "{with}");
        let unsigned = signature_line(&PackSignatureState::Unsigned, None, "authority store");
        assert!(unsigned.starts_with("unsigned — "), "{unsigned}");
    }

    #[test]
    fn a_valid_signature_names_the_key_the_authority_and_the_time_it_was_judged_at() {
        let line = signature_line(&state_valid(), Some("2026-09-11T00:00:00Z (--at)"), "authority store");
        assert!(line.starts_with("valid — signed by urn:ietf:"), "{line}");
        assert!(line.contains("an-authority.example"), "{line}");
        assert!(line.ends_with("at 2026-09-11T00:00:00Z (--at)"), "{line}");
    }
}
