// tests/cli_keygen.rs — TASKS 5.5: `vmr key generate` (TASKS name
// test_cli_keygen.cpp; docs/dev/phase5.md C3, C7).
//
// A real signing key comes from the operating system's CSPRNG — never from
// a fixed string (that pattern is test-only in this repository). It is
// written once as an unencrypted PKCS#8 PEM, never over an existing file
// unless asked, and never printed.

mod common;
use common::*;
use p256::pkcs8::DecodePrivateKey;
use vmr_record::record::JwkPublicKey;

/// The key id `key generate` printed.
fn printed_key_id(run: &Run) -> String {
    let line = run.stdout.lines().find(|l| l.starts_with("Generated signing key: ")).unwrap_or_else(|| {
        panic!("no key id line:\n{}", run.transcript())
    });
    line.trim_start_matches("Generated signing key: ").to_string()
}

fn read_key(path: &std::path::Path) -> p256::ecdsa::SigningKey {
    let pem = std::fs::read_to_string(path).unwrap();
    p256::ecdsa::SigningKey::from_pkcs8_pem(&pem).expect("a PKCS#8 PEM P-256 private key")
}

#[test]
fn keygen_help_states_the_format_and_its_limits() {
    let run = vmr(&["key", "generate", "--help"]);
    run.expect_code(0);
    for text in ["--output", "--force", "PKCS#8", "not encrypted", "operating system"] {
        assert!(run.stdout.contains(text), "{text} missing:\n{}", run.transcript());
    }
}

#[test]
fn generate_writes_a_pkcs8_pem_p256_key_and_prints_its_key_id() {
    let s = Scratch::new("keygen-basic");
    let run = vmr(&["key", "generate", "--output", &s.arg("factory.key")]);
    run.expect_code(0);
    let pem = std::fs::read_to_string(s.path("factory.key")).unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{pem}");
    assert!(pem.ends_with("-----END PRIVATE KEY-----\n"), "{pem}");
    assert!(!pem.contains('\r'), "LF line endings");
    let key = read_key(&s.path("factory.key"));
    let key_id = JwkPublicKey::from_verifying_key(key.verifying_key()).key_id();
    assert_eq!(printed_key_id(&run), key_id, "the printed id is the key's RFC 7638 thumbprint URN");
    assert!(key_id.starts_with("urn:ietf:params:oauth:jwk-thumbprint:sha-256:"));
    // The file as given: a Windows path keeps its single backslashes.
    assert!(run.stdout.contains(&format!("  Private key:  '{}' (PKCS#8 PEM", s.arg("factory.key"))), "{}", run.transcript());
    assert!(run.stderr.is_empty(), "{}", run.transcript());
}

#[test]
fn every_run_makes_a_different_key() {
    // The OS CSPRNG, not a derivation: three runs, three keys.
    let s = Scratch::new("keygen-unique");
    let mut ids = std::collections::BTreeSet::new();
    let mut pems = std::collections::BTreeSet::new();
    for i in 0..3 {
        let name = format!("k{i}.key");
        let run = vmr(&["key", "generate", "--output", &s.arg(&name)]);
        run.expect_code(0);
        ids.insert(printed_key_id(&run));
        pems.insert(std::fs::read_to_string(s.path(&name)).unwrap());
    }
    assert_eq!(ids.len(), 3, "{ids:?}");
    assert_eq!(pems.len(), 3);
}

#[test]
fn an_existing_file_is_never_overwritten_without_force() {
    let s = Scratch::new("keygen-overwrite");
    let path = s.write("factory.key", "keep me");
    let run = vmr(&["key", "generate", "--output", &path]);
    run.expect_code(1);
    assert!(run.stderr.contains("already exists"), "{}", run.transcript());
    assert!(run.stderr.contains("--force"), "{}", run.transcript());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep me", "the file is untouched");
    assert!(run.stdout.is_empty(), "{}", run.transcript());

    let run = vmr(&["key", "generate", "--output", &path, "--force"]);
    run.expect_code(0);
    let key = read_key(&s.path("factory.key"));
    assert_eq!(printed_key_id(&run), JwkPublicKey::from_verifying_key(key.verifying_key()).key_id());
}

#[test]
fn no_secret_material_is_ever_printed() {
    let s = Scratch::new("keygen-secret");
    let run = vmr(&["key", "generate", "--output", &s.arg("factory.key")]);
    run.expect_code(0);
    let pem = std::fs::read_to_string(s.path("factory.key")).unwrap();
    let secret = read_key(&s.path("factory.key")).to_bytes();
    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    let mut forbidden = vec![hex.clone(), hex.to_uppercase(), vmr_record::encoding::b64url_encode(&secret)];
    // Every base64 line of the PEM body.
    forbidden.extend(pem.lines().filter(|l| !l.starts_with("-----")).map(str::to_string));
    let printed = format!("{}{}", run.stdout, run.stderr);
    for f in &forbidden {
        assert!(!printed.contains(f.as_str()), "secret material printed:\n{}", run.transcript());
    }
    assert!(!printed.contains("PRIVATE KEY-----"), "{}", run.transcript());
}

#[test]
fn an_unwritable_destination_is_an_input_error() {
    let s = Scratch::new("keygen-missing-dir");
    let run = vmr(&["key", "generate", "--output", &s.arg("no/such/dir/factory.key")]);
    run.expect_code(1);
    assert!(run.stderr.starts_with("vmr: error: cannot create private key"), "{}", run.transcript());
    let run = vmr(&["key", "generate"]);
    run.expect_code(1);
    assert!(run.stderr.contains("--output <FILE>"), "{}", run.transcript());
}

/// The line `key generate` prints about the key file's permissions.
fn permissions_line(run: &Run) -> Option<&str> {
    run.stdout.lines().find(|l| l.trim_start().starts_with("Permissions:"))
}

#[cfg(windows)]
#[test]
fn on_windows_the_output_says_the_key_inherits_its_folders_permissions_and_how_to_restrict_it() {
    // QA P5-06: vmr cannot set a DACL here (no unsafe code, no new crate),
    // and a key made in a folder under a drive root inherits "Authenticated
    // Users: (M)" - silently. One line now says so, with a command that
    // leaves the file to its owner alone. No key material in it.
    let s = Scratch::new("keygen-acl");
    let key = s.arg("factory.key");
    let run = vmr(&["key", "generate", "--output", &key]);
    run.expect_code(0);
    let line = permissions_line(&run).unwrap_or_else(|| panic!("no Permissions line:\n{}", run.transcript()));
    assert!(line.contains("inherits its folder's permissions"), "{line}");
    assert!(line.contains(&format!("icacls \"{key}\" /inheritance:r /grant:r *S-1-3-4:F")), "{line}");
    assert!(!line.contains("PRIVATE KEY"), "{line}");
}

#[cfg(unix)]
#[test]
fn on_unix_there_is_no_permissions_line_the_file_is_0600() {
    let s = Scratch::new("keygen-no-acl-line");
    let run = vmr(&["key", "generate", "--output", &s.arg("factory.key")]);
    run.expect_code(0);
    assert_eq!(permissions_line(&run), None, "{}", run.transcript());
    assert!(!run.stdout.contains("icacls"), "{}", run.transcript());
}

#[cfg(unix)]
#[test]
fn the_private_key_file_is_readable_by_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let s = Scratch::new("keygen-mode");
    vmr(&["key", "generate", "--output", &s.arg("factory.key")]).expect_code(0);
    let mode = std::fs::metadata(s.path("factory.key")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "{mode:o}");
}
