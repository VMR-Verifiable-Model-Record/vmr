//! `vmr trust-store add` and `vmr trust-store add-authority` (Phase 5 task
//! 5.6b, docs/dev/phase5.md C8; the authority counterpart with `pack sign`).
// ============================================================================
//  trust_store_cmd.rs — the verifier operator's explicit trust decision
//
//  Decision D1 (Phase 4): a trust store is provisioned beforehand, out of
//  band, by the operator of the VERIFIER — like a browser's root
//  certificates or SSH's known_hosts. This command is that act, with every
//  decision explicit (no defaults): the DID the key speaks for, the name to
//  show for it, the highest attestation level, the first second it may sign
//  (and, optionally, the end). It reads only a public key file (§3.2) —
//  never a record — so no key is ever trusted because a record carries
//  it. The new store is validated with TrustStore::new before a byte is
//  written, and written atomically (a temporary file, then a rename), in
//  canonical order.
//
//  `add-authority` is the same act for the other key a verifier trusts: the
//  one an authority signs its policy packs with (`vmr pack sign`). Without
//  it a verifier who wanted to trust a new authority had to hand-author the
//  store's JSON, which is how a standard quietly becomes one vendor's: the
//  side that signs had a command and the side that decides whom to believe
//  did not. It writes `policy_authorities` only, never `issuers` - one key
//  speaks for records or for packs, never both (trust-store format §4.2) -
//  and the file it writes may be a full trust store or an authority store of
//  its own ("issuers": []).
// ============================================================================

use crate::cli::{AttestationArg, TrustStoreAddArgs, TrustStoreAddAuthorityArgs};
use crate::error::CliError;
use crate::files::{self, shown};
use crate::keys;
use crate::output::Output;
use crate::render::{plural, shown_value};
use crate::verify_cmd::load_trust_store;
use vmr_verify::trust_store::{
    AttestationLevel, AuthorityDocument, IssuerDocument, KeyDocument, TrustStoreDocument,
    TRUST_STORE_VERSION,
};
use vmr_verify::TrustStore;

/// Run `trust-store add`.
pub fn add(args: &TrustStoreAddArgs) -> Result<Output, CliError> {
    // The store is read and replaced: a device name would be read from (the
    // console) and written to, so it is refused first (QA P5-02), and so is
    // the public key file itself (QA P5-11).
    files::check_output(&args.trust_store, "trust store", "--trust-store", &[(&args.public_key, "--public-key")])?;
    let key = keys::read_public_key_file(&args.public_key)?;
    let (mut document, created) = read_or_new(&args.trust_store)?;

    let unchanged = |why: String| {
        CliError::input(format!("{why}; trust store {} was not changed", shown(&args.trust_store)))
    };
    if let Some(holder) = document.issuers.iter().find(|i| i.keys.iter().any(|k| k.key_id == key.key_id)) {
        return Err(unchanged(format!(
            "key {} is already in the trust store, trusted for {}",
            key.key_id,
            shown_value(&holder.issuer_id)
        )));
    }
    let entry = KeyDocument {
        key_id: key.key_id.clone(),
        public_key: key.public_key,
        attestation_level: level(args.attestation_level),
        valid_from: args.valid_from.to_string(),
        valid_until: args.valid_until.map(|t| t.to_string()),
        revoked: false,
    };
    match document.issuers.iter_mut().find(|i| i.issuer_id == args.issuer_id) {
        Some(issuer) if issuer.issuer_name != args.issuer_name => {
            return Err(unchanged(format!(
                "issuer {} is already in the trust store as \"{}\", not \"{}\"",
                shown_value(&issuer.issuer_id),
                shown_value(&issuer.issuer_name),
                shown_value(&args.issuer_name)
            )))
        }
        Some(issuer) => issuer.keys.push(entry),
        None => document.issuers.push(IssuerDocument {
            issuer_id: args.issuer_id.clone(),
            issuer_name: args.issuer_name.clone(),
            keys: vec![entry],
        }),
    }

    // Every rule of the format, checked before anything is written.
    let store = TrustStore::new(document)
        .map_err(|e| unchanged(format!("the trust store would not be valid: {e}")))?;
    let text = serde_json::to_string_pretty(&store.to_document())
        .map_err(|e| CliError::input(format!("cannot write the trust store as JSON: {e}")))?;
    files::replace_file(&args.trust_store, format!("{text}\n").as_bytes(), "trust store")?;

    let window = match args.valid_until {
        Some(until) => format!("from {} until {until} (exclusive)", args.valid_from),
        None => format!("from {} (no end)", args.valid_from),
    };
    let store_shown = shown(&args.trust_store);
    let decision = crate::screens::TrustDecision {
        key_id: &key.key_id,
        issuer_id: &args.issuer_id,
        issuer_name: &args.issuer_name,
        level: level(args.attestation_level).as_str(),
        window: &window,
        store: &store_shown,
        created,
        issuers: store.issuer_count() as u64,
        keys: store.key_count() as u64,
        sha256: store.sha256().to_string(),
    };
    Ok(Output::ok(format!(
        "Trusted key {}\n  \
         for issuer:   {} ({})\n  \
         attestation:  up to {}\n  \
         may sign:     {window}\n  \
         Trust store:  {} {}: {}, {}, {}\n",
        key.key_id,
        shown_value(&args.issuer_id),
        shown_value(&args.issuer_name),
        level(args.attestation_level).as_str(),
        store_shown,
        if created { "created" } else { "updated" },
        plural(store.issuer_count() as u64, "issuer", "issuers"),
        plural(store.key_count() as u64, "key", "keys"),
        store.sha256()
    ))
    .with_rich(crate::screens::trusted(&decision)))
}

/// Run `trust-store add-authority`.
pub fn add_authority(args: &TrustStoreAddAuthorityArgs) -> Result<Output, CliError> {
    files::check_output(&args.trust_store, "trust store", "--trust-store", &[(&args.public_key, "--public-key")])?;
    let key = keys::read_public_key_file(&args.public_key)?;
    let (mut document, created) = read_or_new(&args.trust_store)?;

    let unchanged = |why: String| {
        CliError::input(format!("{why}; trust store {} was not changed", shown(&args.trust_store)))
    };
    // A key already trusted for an authority is not trusted for a second one,
    // and one trusted for an issuer is refused by the loader below
    // (`trust_store.duplicate_key`), as `add` is refused the other way round.
    if let Some(holder) =
        document.policy_authorities.iter().find(|a| a.keys.iter().any(|k| k.key_id == key.key_id))
    {
        return Err(unchanged(format!(
            "key {} is already in the trust store, trusted for the policy authority {}",
            key.key_id,
            shown_value(&holder.authority_id)
        )));
    }
    let entry = KeyDocument {
        key_id: key.key_id.clone(),
        public_key: key.public_key,
        attestation_level: level(args.attestation_level),
        valid_from: args.valid_from.to_string(),
        valid_until: args.valid_until.map(|t| t.to_string()),
        revoked: false,
    };
    match document.policy_authorities.iter_mut().find(|a| a.authority_id == args.authority_id) {
        Some(authority) if authority.authority_name != args.authority_name => {
            return Err(unchanged(format!(
                "policy authority {} is already in the trust store as \"{}\", not \"{}\"",
                shown_value(&authority.authority_id),
                shown_value(&authority.authority_name),
                shown_value(&args.authority_name)
            )))
        }
        Some(authority) => authority.keys.push(entry),
        None => document.policy_authorities.push(AuthorityDocument {
            authority_id: args.authority_id.clone(),
            authority_name: args.authority_name.clone(),
            keys: vec![entry],
        }),
    }

    // Every rule of the format, checked before anything is written.
    let store = TrustStore::new(document)
        .map_err(|e| unchanged(format!("the trust store would not be valid: {e}")))?;
    let text = serde_json::to_string_pretty(&store.to_document())
        .map_err(|e| CliError::input(format!("cannot write the trust store as JSON: {e}")))?;
    files::replace_file(&args.trust_store, format!("{text}\n").as_bytes(), "trust store")?;

    let window = match args.valid_until {
        Some(until) => format!("from {} until {until} (exclusive)", args.valid_from),
        None => format!("from {} (no end)", args.valid_from),
    };
    let store_shown = shown(&args.trust_store);
    let decision = crate::screens::AuthorityDecision {
        key_id: &key.key_id,
        authority_id: &args.authority_id,
        authority_name: &args.authority_name,
        window: &window,
        store: &store_shown,
        created,
        authorities: store.authority_count() as u64,
        keys: store.authority_key_count() as u64,
        sha256: store.sha256().to_string(),
    };
    Ok(Output::ok(format!(
        "Trusted key {}\n  \
         for authority: {} ({})\n  \
         may sign:      policy packs {window}\n  \
         Trust store:   {} {}: {}, {}, {}\n",
        key.key_id,
        shown_value(&args.authority_id),
        shown_value(&args.authority_name),
        store_shown,
        if created { "created" } else { "updated" },
        plural(store.authority_count() as u64, "policy authority", "policy authorities"),
        plural(store.authority_key_count() as u64, "key", "keys"),
        store.sha256()
    ))
    .with_rich(crate::screens::authority_trusted(&decision)))
}

/// The store to add to: the one at `path`, or a new empty one when there is
/// no file there yet. The second member says which.
fn read_or_new(path: &std::path::Path) -> Result<(TrustStoreDocument, bool), CliError> {
    match std::fs::metadata(path) {
        Ok(_) => Ok((load_trust_store(path)?.to_document(), false)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((
            TrustStoreDocument {
                trust_store_version: TRUST_STORE_VERSION.into(),
                issuers: Vec::new(),
                policy_authorities: Vec::new(),
            },
            true,
        )),
        Err(e) => Err(CliError::input(format!("cannot read trust store {}: {e}", shown(path)))),
    }
}

fn level(arg: AttestationArg) -> AttestationLevel {
    match arg {
        AttestationArg::SelfAttested => AttestationLevel::SelfAttested,
        AttestationArg::Software => AttestationLevel::Software,
        AttestationArg::Hardware => AttestationLevel::Hardware,
    }
}
