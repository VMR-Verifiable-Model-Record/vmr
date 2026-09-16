//! `vmr key generate` and `vmr key export` (TASKS 5.5, 5.6) — signing keys
//! as PKCS#8 PEM files, and their public half.
// ============================================================================
//  keys.rs — making a signing key, reading one back, exporting its public key
//
//  Randomness (docs/dev/phase5.md C3): a real key comes from the operating
//  system's CSPRNG (rand_core's OsRng over getrandom: BCryptGenRandom /
//  ProcessPrng on Windows, getrandom(2) on Linux). This is the CLI's only
//  source of randomness. Keys derived from fixed strings exist only in
//  tests. Law 1 is about weights, spikes and emitted codes; a key is none of
//  them, and record bytes remain a pure function of their inputs, the key
//  included (RFC 6979 deterministic signatures).
//
//  Secrecy (C7): the PEM is written once to a new file (owner-only on Unix)
//  and never printed or logged; its text lives in Zeroizing buffers that
//  are wiped when dropped, and no error message quotes a key file. MVP
//  limits, stated in docs/CLI.md: no passphrase, no hardware key store.
//
//  The public key file (§3.2): exactly the `key_id` and `public_key`
//  members of a trust-store key entry, so it drops into a trust store as it
//  stands.
// ============================================================================

use crate::cli::{KeyExportArgs, KeyGenerateArgs};
use crate::error::CliError;
use crate::files::{self, shown, ReadError};
use crate::names::TOOL;
use crate::output::Output;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::zeroize::Zeroizing;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use vmr_record::record::JwkPublicKey;

/// The largest key file read: 64 KiB (a P-256 PKCS#8 PEM is ~240 bytes).
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// A public key file (`vmr key export`): the two members a trust-store key
/// entry carries under the same names (specs/trust-store-format-v0.1.md §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyFile {
    /// The RFC 7638 thumbprint URN of `public_key`.
    pub key_id: String,
    /// The key as a JWK, exactly as in a record and a trust store.
    pub public_key: JwkPublicKey,
}

impl PublicKeyFile {
    /// The public key file of `key`.
    pub fn of(key: &VerifyingKey) -> Self {
        let jwk = JwkPublicKey::from_verifying_key(key);
        PublicKeyFile { key_id: jwk.key_id(), public_key: jwk }
    }
}

/// Run `key generate`.
pub fn generate(args: &KeyGenerateArgs) -> Result<Output, CliError> {
    // A device or a directory is refused before a key exists (QA P5-02).
    files::check_output(&args.output, "private key", "--output", &[])?;
    let key = SigningKey::random(&mut OsRng);
    // Zeroizing<String>: the PEM text is wiped when this binding drops.
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| CliError::input("cannot encode the new key as PKCS#8"))?;
    files::write_private_new(&args.output, pem.as_bytes(), args.force, "private key")?;
    let key_id = vmr_record::jwk::key_id(key.verifying_key());
    let mut out = format!(
        "Generated signing key: {key_id}\n  \
         Private key:  {} (PKCS#8 PEM, P-256, not encrypted: keep it secret; {TOOL} never prints it)\n",
        shown(&args.output)
    );
    let note = files::private_key_permissions_note(&args.output);
    if let Some(line) = &note {
        out.push_str(&format!("  Permissions:  {line}\n"));
    }
    let screen = crate::screens::key_generated(&key_id, &shown(&args.output), note.as_deref());
    Ok(Output::ok(out).with_rich(screen))
}

/// Run `key export`: the public key file to stdout, or to `--output`.
pub fn export(args: &KeyExportArgs) -> Result<Output, CliError> {
    if let Some(path) = &args.output {
        files::check_output(path, "public key file", "--output", &[(&args.key, "--key")])?;
    }
    let key = read_signing_key(&args.key)?;
    let file = PublicKeyFile::of(key.verifying_key());
    let json = serde_json::to_string_pretty(&file)
        .map_err(|e| CliError::input(format!("cannot write the public key as JSON: {e}")))?;
    match &args.output {
        None => Ok(Output::ok(format!("{json}\n"))),
        Some(path) => {
            files::write_public_new(path, format!("{json}\n").as_bytes(), args.force, "public key file")?;
            Ok(Output::ok(format!(
                "Exported public key: {}\n  Public key file: {} (the public key only: no private key material)\n",
                file.key_id,
                shown(path)
            ))
            .with_rich(crate::screens::key_exported(&file.key_id, &shown(path))))
        }
    }
}

/// Read a public key file (`vmr key export` output) and check it: closed
/// objects (neither written as the array of its values: QA QT-01), a P-256
/// point, and a `key_id` that IS the key's RFC 7638
/// thumbprint URN (so an edited id cannot pass one key off as another). A
/// record, which also carries a public key, is not a public key file.
pub fn read_public_key_file(path: &Path) -> Result<PublicKeyFile, CliError> {
    let bytes = files::read_bounded(path, MAX_KEY_FILE_BYTES).map_err(|e| match e {
        ReadError::TooLarge(size) => CliError::input(format!(
            "public key file {} is {size} bytes; a public key file is at most 64 KiB, and it was not read",
            shown(path)
        )),
        ReadError::Io(e) => CliError::input(format!("cannot read public key file {}: {e}", shown(path))),
    })?;
    parse_public_key_file(&bytes).map_err(|why| match files::byte_order_mark(&bytes) {
        // Refused, but named (QA P5-07).
        Some(bom) => CliError::input(format!(
            "{} is not a usable public key file: {bom}, which a public key file may not have (it is UTF-8 JSON)",
            shown(path)
        ))
        .with_hint(files::SAVE_WITHOUT_BOM),
        None => CliError::input(format!("{} is not a usable public key file: {why}", shown(path)))
            .with_hint(concat!("pass the file `", crate::tool_name!(), " key export` wrote: {\"key_id\": …, \"public_key\": {…}}")),
    })
}

/// Parse and check a public key file's bytes; the error says why it is not
/// one (bounded, terminal-safe).
///
/// `pub` only for `fuzz/`'s `public_key` target and its stable seed test
/// (task 10.13, release-basics-fuzz): not a stable API, and no Community
/// caller outside this crate uses it.
#[doc(hidden)]
pub fn parse_public_key_file(bytes: &[u8]) -> Result<PublicKeyFile, String> {
    let file: PublicKeyFile = vmr_record::strict_json::from_slice(bytes)
        .map_err(|e| format!("not a public key file: {}", crate::render::bounded(&e.to_string())))?;
    file.public_key
        .to_verifying_key()
        .map_err(|e| format!("its public_key is not a P-256 key ({})", crate::render::bounded(&e.to_string())))?;
    let derived = file.public_key.key_id();
    if file.key_id != derived {
        return Err(format!(
            "its key_id {} is not the RFC 7638 thumbprint of its public_key ({derived}): the file was altered",
            crate::render::bounded(&file.key_id)
        ));
    }
    Ok(file)
}

/// Read a P-256 private key from a PKCS#8 PEM file. Errors say what the
/// file is instead, never what it contains.
pub fn read_signing_key(path: &Path) -> Result<SigningKey, CliError> {
    let bytes = Zeroizing::new(files::read_bounded(path, MAX_KEY_FILE_BYTES).map_err(|e| match e {
        ReadError::TooLarge(size) => CliError::input(format!(
            "private key {} is {size} bytes; a key file is at most 64 KiB, and it was not read",
            shown(path)
        )),
        ReadError::Io(e) => CliError::input(format!("cannot read private key {}: {e}", shown(path))),
    })?);
    signing_key_from_pem(&bytes).map_err(|what| {
        CliError::input(format!("{} is {what}", shown(path)))
            .with_hint(concat!("pass the file `", crate::tool_name!(), " key generate` wrote (a PKCS#8 \"PRIVATE KEY\" PEM of a P-256 key)"))
    })
}

/// A P-256 private key from PKCS#8 PEM bytes; the error says what the bytes
/// are instead — never what they contain.
fn signing_key_from_pem(bytes: &[u8]) -> Result<SigningKey, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "not a PKCS#8 PEM private key (not text)")?;
    SigningKey::from_pkcs8_pem(text).map_err(|_| {
        if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
            "an encrypted PKCS#8 key; this version reads only keys that are not encrypted"
        } else if text.contains("-----BEGIN EC PRIVATE KEY-----") {
            "a SEC1 \"EC PRIVATE KEY\"; convert it with `openssl pkcs8 -topk8 -nocrypt`"
        } else if text.contains("PUBLIC KEY-----") {
            "a public key; this needs the private key"
        } else {
            "not a PKCS#8 PEM private key of a P-256 key"
        }
    })
}

#[cfg(test)]
mod robustness {
    use super::*;
    use crate::mutate::{mutate, terminal_safe, Lcg};

    fn test_key() -> SigningKey {
        // Derived, test-only.
        vmr_record::sign::signing_key_from_secret(&vmr_record::hash::sha256(b"vmr-cli keys robustness (test-only)"))
            .unwrap()
    }

    #[test]
    fn mutated_key_files_never_panic() {
        let key = test_key();
        let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let seed = pem.as_bytes().to_vec();
        let mut rng = Lcg::new(0x5EED_5006);
        let mut current = seed.clone();
        for i in 0..1500 {
            if i % 8 == 0 {
                current = seed.clone();
            }
            current = mutate(&mut rng, &current);
            // Any outcome but a panic; an error is one of a few fixed
            // sentences, so it cannot carry key material by construction.
            let _outcome = signing_key_from_pem(&current);
        }
        assert_eq!(signing_key_from_pem(&seed).unwrap().to_bytes(), key.to_bytes());
    }

    #[test]
    fn mutated_public_key_files_never_panic_and_reasons_are_terminal_safe() {
        let seed = serde_json::to_vec_pretty(&PublicKeyFile::of(test_key().verifying_key())).unwrap();
        let mut rng = Lcg::new(0x5EED_5007);
        let mut current = seed.clone();
        for i in 0..1500 {
            if i % 8 == 0 {
                current = seed.clone();
            }
            current = mutate(&mut rng, &current);
            if let Err(why) = parse_public_key_file(&current) {
                assert!(terminal_safe(&why), "{why}");
            }
        }
        assert!(parse_public_key_file(&seed).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_object_written_as_the_array_of_its_values_is_refused() {
        // QA QT-01: serde's derive reads a struct from the array of its
        // values in declaration order. A public key file is closed objects
        // (docs/CLI.md §4.2): its public_key, and the file itself, written as
        // arrays read as the file, and are refused.
        let key = vmr_record::sign::signing_key_from_secret(&vmr_record::hash::sha256(b"vmr-cli keys QT-01 (test-only)"))
            .unwrap();
        let file = PublicKeyFile::of(key.verifying_key());
        let jwk = &file.public_key;
        let key_as_array = serde_json::json!([jwk.kty, jwk.crv, jwk.x, jwk.y]);
        let key_as_object = serde_json::to_value(jwk).unwrap();
        for (what, doc) in [
            ("its public_key", serde_json::json!({ "key_id": file.key_id, "public_key": key_as_array })),
            ("the file", serde_json::json!([file.key_id, key_as_object])),
        ] {
            let bytes = serde_json::to_vec(&doc).unwrap();
            assert_eq!(serde_json::from_slice::<PublicKeyFile>(&bytes).unwrap(), file, "{what}: serde_json reads it as the file");
            let why = parse_public_key_file(&bytes).expect_err(what);
            assert!(why.contains("invalid type: sequence, expected "), "{what}: {why}");
        }
        assert_eq!(parse_public_key_file(&serde_json::to_vec(&file).unwrap()).unwrap(), file);
    }
}
