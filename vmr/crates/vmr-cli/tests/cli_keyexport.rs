// tests/cli_keyexport.rs — TASKS 5.6: `vmr key export` (TASKS name
// test_cli_keyexport.cpp; docs/dev/phase5.md §3.2, C7).
//
// The public half of a key, in the form a trust store takes: exactly the
// `key_id` and `public_key` members of a trust-store key entry. The tests
// check that the id is the key's RFC 7638 thumbprint URN, that the file
// drops into a trust store verbatim and that store then verifies a
// record the key signed — and that no private material ever leaves.

mod common;
use common::*;
use p256::pkcs8::DecodePrivateKey;
use serde_json::Value;
use vmr_record::record::JwkPublicKey;
use vmr_verify::trust_store::{AttestationLevel, IssuerDocument, KeyDocument, TrustStoreDocument};

/// Generate a key with the CLI into `s`; return (its path, its printed id).
fn generated_key(s: &Scratch, name: &str) -> (String, String) {
    let path = s.arg(name);
    let run = vmr(&["key", "generate", "--output", &path]);
    run.expect_code(0);
    let id = run.stdout.lines().next().unwrap().trim_start_matches("Generated signing key: ").to_string();
    (path, id)
}

fn read_key(path: &str) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_pkcs8_pem(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn export_help_says_only_the_public_key_leaves() {
    let run = vmr(&["key", "export", "--help"]);
    run.expect_code(0);
    for text in ["--key", "--output", "--force", "public key", "never", "trust store"] {
        assert!(run.stdout.contains(text), "{text} missing:\n{}", run.transcript());
    }
}

#[test]
fn export_prints_exactly_the_key_id_and_the_jwk() {
    let s = Scratch::new("export-stdout");
    let (key, id) = generated_key(&s, "factory.key");
    let run = vmr(&["key", "export", "--key", &key]);
    run.expect_code(0);
    let json: Value = serde_json::from_str(&run.stdout).expect("stdout is the JSON file");
    let members: Vec<&String> = json.as_object().unwrap().keys().collect();
    assert_eq!(members, ["key_id", "public_key"], "exactly the two trust-store members");
    let jwk = JwkPublicKey::from_verifying_key(read_key(&key).verifying_key());
    assert_eq!(json["key_id"], id.as_str(), "the id `key generate` printed");
    assert_eq!(json["key_id"], jwk.key_id().as_str(), "the RFC 7638 thumbprint URN of the key");
    let exported: JwkPublicKey = serde_json::from_value(json["public_key"].clone()).unwrap();
    assert_eq!(exported, jwk);
    assert!(run.stderr.is_empty(), "{}", run.transcript());
}

#[test]
fn export_to_a_file_never_overwrites_without_force() {
    let s = Scratch::new("export-file");
    let (key, id) = generated_key(&s, "factory.key");
    let out = s.arg("factory.pub.json");
    let run = vmr(&["key", "export", "--key", &key, "--output", &out]);
    run.expect_code(0);
    assert!(run.stdout.contains(&id), "{}", run.transcript());
    let written: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(written["key_id"], id.as_str());

    std::fs::write(&out, "keep me").unwrap();
    let run = vmr(&["key", "export", "--key", &key, "--output", &out]);
    run.expect_code(1);
    assert!(run.stderr.contains("already exists"), "{}", run.transcript());
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "keep me");
    vmr(&["key", "export", "--key", &key, "--output", &out, "--force"]).expect_code(0);
    let written: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(written["key_id"], id.as_str());
}

#[test]
fn the_export_drops_into_a_trust_store_that_then_verifies_the_keys_records() {
    // The round trip Phase 4 promised (plan §3.6): key export -> a
    // trust-store key entry whose key id matches the key -> a store under
    // which a record that key signed verifies, through the CLI.
    let s = Scratch::new("export-roundtrip");
    let (key, id) = generated_key(&s, "factory.key");
    let run = vmr(&["key", "export", "--key", &key]);
    run.expect_code(0);
    let export: Value = serde_json::from_str(&run.stdout).unwrap();
    let doc = TrustStoreDocument {
        trust_store_version: "0.1".into(),
        issuers: vec![IssuerDocument {
            issuer_id: "did:web:factory-operator.ph".into(),
            issuer_name: "New Clark City Fab Operator".into(),
            keys: vec![KeyDocument {
                key_id: serde_json::from_value(export["key_id"].clone()).unwrap(),
                public_key: serde_json::from_value(export["public_key"].clone()).unwrap(),
                attestation_level: AttestationLevel::Software,
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: None,
                revoked: false,
            }],
        }],
        policy_authorities: Vec::new(),
    };
    let store = vmr_verify::TrustStore::new(doc.clone()).expect("the exported members form a valid entry");
    let trusted = store.lookup(&id).expect("looked up by the exported key id");
    assert_eq!(trusted.key_id, id);
    let store_path = s.write("trust-store.json", serde_json::to_string_pretty(&doc).unwrap());

    // A record that key signed (the vector's content, the new key).
    let signing = read_key(&key);
    let mut p = vector();
    let jwk = JwkPublicKey::from_verifying_key(signing.verifying_key());
    p.issuer.key_id = jwk.key_id();
    p.signature.signing_key_id = jwk.key_id();
    p.issuer.public_key = jwk;
    let sig = vmr_record::sign::sign(&signing, &p.signature_tbs().unwrap()).unwrap();
    p.signature.signature = vmr_record::record::SignatureSection::signature_field(&sig);
    p.signature.signed_payload_hash = p.signed_payload_hash().unwrap();
    let record = s.write("record.vmr", p.to_cose().unwrap());
    let run = vmr(&["record", "verify", "--record", &record, "--trust-store", &store_path, "--at", T]);
    run.expect_code(0);
    assert!(run.stdout.contains(&format!("  Key:           {id} (software)")), "{}", run.transcript());
}

#[test]
fn no_private_material_leaves() {
    let s = Scratch::new("export-secret");
    let (key, _) = generated_key(&s, "factory.key");
    let out = s.arg("factory.pub.json");
    let to_stdout = vmr(&["key", "export", "--key", &key]);
    let to_file = vmr(&["key", "export", "--key", &key, "--output", &out]);
    let pem = std::fs::read_to_string(&key).unwrap();
    let secret = read_key(&key).to_bytes();
    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    let mut forbidden = vec![hex.clone(), hex.to_uppercase(), vmr_record::encoding::b64url_encode(&secret)];
    forbidden.extend(pem.lines().filter(|l| !l.starts_with("-----")).map(str::to_string));
    let everything = format!(
        "{}{}{}{}{}",
        to_stdout.stdout,
        to_stdout.stderr,
        to_file.stdout,
        to_file.stderr,
        std::fs::read_to_string(&out).unwrap()
    );
    for f in &forbidden {
        assert!(!everything.contains(f.as_str()), "private material left the key file");
    }
    assert!(!everything.contains("\"d\""), "no private JWK member");
    assert!(!everything.contains("PRIVATE KEY"), "no PEM");
}

#[test]
fn a_file_that_is_not_a_p256_pkcs8_private_key_is_an_input_error() {
    let s = Scratch::new("export-bad-keys");
    let (key, _) = generated_key(&s, "good.key");
    let pem = std::fs::read_to_string(&key).unwrap();
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("\n");
    let cases: Vec<(&str, String, &str)> = vec![
        ("empty.key", String::new(), "not a PKCS#8 PEM private key"),
        ("text.key", "hello".into(), "not a PKCS#8 PEM private key"),
        ("public.pem", format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"), "a public key"),
        ("sec1.pem", format!("-----BEGIN EC PRIVATE KEY-----\n{body}\n-----END EC PRIVATE KEY-----\n"), "SEC1"),
        (
            "encrypted.pem",
            format!("-----BEGIN ENCRYPTED PRIVATE KEY-----\n{body}\n-----END ENCRYPTED PRIVATE KEY-----\n"),
            "encrypted",
        ),
        ("truncated.key", pem[..pem.len() / 2].to_string(), "not a PKCS#8 PEM private key"),
        // The DER SEQUENCE tag (0x30, base64 "M…") replaced: the structure
        // no longer decodes. (Changing the key octets instead would only make
        // a different, valid key.)
        ("corrupt.key", pem.replacen("-----\nM", "-----\nA", 1), "not a PKCS#8 PEM private key"),
    ];
    for (name, content, fragment) in &cases {
        let path = s.write(name, content);
        let run = vmr(&["key", "export", "--key", &path]);
        run.expect_code(1);
        assert!(run.stdout.is_empty(), "{name}:\n{}", run.transcript());
        assert!(run.stderr.contains(fragment), "{name}: expected `{fragment}`:\n{}", run.transcript());
        assert!(!run.stderr.contains(&body[..20]), "{name}: the key file's content was echoed");
    }
    let huge = s.write("huge.key", vec![b'A'; 64 * 1024 + 1]);
    let run = vmr(&["key", "export", "--key", &huge]);
    run.expect_code(1);
    assert!(run.stderr.contains("64 KiB"), "{}", run.transcript());
    let run = vmr(&["key", "export", "--key", &s.arg("missing.key")]);
    run.expect_code(1);
    assert!(run.stderr.contains("cannot read private key"), "{}", run.transcript());
}
