// tests/cli_trust_store.rs — `vmr trust-store add` (Phase 5 task 5.6b,
// docs/dev/phase5.md C8).
//
// Decision D1 (Phase 4): the trust store is provisioned beforehand, out of
// band, by the VERIFIER's operator. `trust-store add` is that act, made
// explicit: which DID a key speaks for, the name to show, the highest
// attestation level, from when it may sign. It reads only a public key
// file — never a record: a key is never trusted because a record
// carries it — and it never writes a store the loader would reject.

mod common;
use common::*;
use p256::pkcs8::DecodePrivateKey;
use vmr_record::record::JwkPublicKey;
use vmr_verify::trust_store::AttestationLevel;
use vmr_verify::TrustStore;

const ISSUER: &str = "did:web:factory-operator.ph";
const NAME: &str = "New Clark City Fab Operator";

/// Generate a key and export its public key file with the CLI; return
/// (private key path, public key file path, key id).
fn exported_key(s: &Scratch, stem: &str) -> (String, String, String) {
    let key = s.arg(&format!("{stem}.key"));
    let run = vmr(&["key", "generate", "--output", &key]);
    run.expect_code(0);
    let id = run.stdout.lines().next().unwrap().trim_start_matches("Generated signing key: ").to_string();
    let public = s.arg(&format!("{stem}.pub.json"));
    vmr(&["key", "export", "--key", &key, "--output", &public]).expect_code(0);
    (key, public, id)
}

fn add<'a>(store: &'a str, public: &'a str, issuer: &'a str, name: &'a str) -> Vec<&'a str> {
    vec![
        "trust-store", "add", "--trust-store", store, "--public-key", public, "--issuer-id", issuer,
        "--issuer-name", name, "--attestation-level", "software", "--valid-from", "2026-01-01T00:00:00Z",
    ]
}

fn load(path: &str) -> TrustStore {
    TrustStore::from_json(&std::fs::read(path).unwrap()).expect("the written store loads")
}

#[test]
fn trust_store_add_help_lists_every_decision() {
    let run = vmr(&["trust-store", "add", "--help"]);
    run.expect_code(0);
    for text in [
        "--trust-store", "--public-key", "--issuer-id", "--issuer-name", "--attestation-level",
        "--valid-from", "--valid-until", "never", "record",
    ] {
        assert!(run.stdout.contains(text), "{text} missing:\n{}", run.transcript());
    }
}

#[test]
fn add_keeps_the_policy_authorities_of_a_store_and_never_shares_their_keys() {
    // docs/TASKS.md 6.16: `trust-store add` rewrites the store in canonical
    // order and keeps the policy authorities it trusts; a key already trusted
    // for an authority is not trusted for an issuer too (one key, one list).
    let s = Scratch::new("ts-keeps-authorities");
    let (_, public, id) = exported_key(&s, "factory");
    let authority_key = JwkPublicKey::from_verifying_key(key("vmr-cli tests: a policy authority key").verifying_key());
    let doc = serde_json::json!({
        "trust_store_version": "0.1",
        "issuers": [],
        "policy_authorities": [{
            "authority_id": "khalm-reference-packs",
            "authority_name": "KHALM reference packs",
            "keys": [{
                "key_id": authority_key.key_id(), "public_key": authority_key, "attestation_level": "software",
                "valid_from": "2026-01-01T00:00:00Z", "revoked": false
            }]
        }]
    });
    let store = s.write("trust-store.json", serde_json::to_vec_pretty(&doc).unwrap());
    vmr(&add(&store, &public, ISSUER, NAME)).expect_code(0);
    let loaded = load(&store);
    assert_eq!((loaded.issuer_count(), loaded.authority_count(), loaded.authority_key_count()), (1, 1, 1));
    assert!(loaded.lookup(&id).is_some());
    let kept = loaded.lookup_authority(&authority_key.key_id()).expect("the authority is kept");
    assert_eq!((kept.authority_id, kept.authority_name), ("khalm-reference-packs", "KHALM reference packs"));

    let before = std::fs::read(&store).unwrap();
    let authority_public = s.write(
        "authority.pub.json",
        serde_json::to_vec_pretty(&serde_json::json!({"key_id": authority_key.key_id(), "public_key": authority_key}))
            .unwrap(),
    );
    let run = vmr(&add(&store, &authority_public, "did:web:other.example", "Other"));
    run.expect_code(1);
    assert!(run.stderr.contains("trust_store.duplicate_key"), "{}", run.transcript());
    assert_eq!(std::fs::read(&store).unwrap(), before, "the store was not changed");
}

#[test]
fn add_creates_a_store_that_verifies_the_keys_records() {
    let s = Scratch::new("ts-create");
    let (key, public, id) = exported_key(&s, "factory");
    let store = s.arg("trust-store.json");
    let run = vmr(&add(&store, &public, ISSUER, NAME));
    run.expect_code(0);
    let loaded = load(&store);
    assert_eq!((loaded.issuer_count(), loaded.key_count()), (1, 1));
    let k = loaded.lookup(&id).expect("the key is trusted");
    assert_eq!((k.issuer_id, k.issuer_name, k.key_id), (ISSUER, NAME, id.as_str()));
    assert_eq!(k.attestation_level, AttestationLevel::Software);
    assert_eq!(k.valid_from.to_string(), "2026-01-01T00:00:00Z");
    assert_eq!(k.valid_until, None);
    assert!(!k.revoked);
    assert!(run.stdout.contains(&id), "{}", run.transcript());
    assert!(run.stdout.contains("created"), "{}", run.transcript());
    assert!(run.stdout.contains(loaded.sha256()), "the store's identity is printed:\n{}", run.transcript());

    // The store verifies a record that key signed.
    let signing = p256::ecdsa::SigningKey::from_pkcs8_pem(&std::fs::read_to_string(&key).unwrap()).unwrap();
    let mut p = vector();
    let jwk = JwkPublicKey::from_verifying_key(signing.verifying_key());
    p.issuer.key_id = jwk.key_id();
    p.signature.signing_key_id = jwk.key_id();
    p.issuer.public_key = jwk;
    let sig = vmr_record::sign::sign(&signing, &p.signature_tbs().unwrap()).unwrap();
    p.signature.signature = vmr_record::record::SignatureSection::signature_field(&sig);
    p.signature.signed_payload_hash = p.signed_payload_hash().unwrap();
    let record = s.write("record.json", p.to_json().unwrap());
    let run = vmr(&["record", "verify", "--record", &record, "--trust-store", &store, "--at", T]);
    run.expect_code(0);
    assert!(run.stdout.contains(&format!("{ISSUER} ({NAME}, per trust store)")), "{}", run.transcript());
}

#[test]
fn a_second_key_and_a_second_issuer_are_added_in_canonical_order() {
    let s = Scratch::new("ts-grow");
    let (_, pub_a, id_a) = exported_key(&s, "a");
    let (_, pub_b, id_b) = exported_key(&s, "b");
    let (_, pub_c, id_c) = exported_key(&s, "c");
    let store = s.arg("trust-store.json");
    vmr(&add(&store, &pub_a, ISSUER, NAME)).expect_code(0);
    let first = load(&store).sha256().to_string();
    // Key rotation: a second key for the same issuer.
    let run = vmr(&add(&store, &pub_b, ISSUER, NAME));
    run.expect_code(0);
    assert!(run.stdout.contains("updated"), "{}", run.transcript());
    // Another issuer, with an end to its key's window.
    let mut args = add(&store, &pub_c, "did:web:other.example", "Other Example");
    args.extend(["--valid-until", "2027-01-01T00:00:00Z"]);
    vmr(&args).expect_code(0);
    let loaded = load(&store);
    assert_eq!((loaded.issuer_count(), loaded.key_count()), (2, 3));
    assert_eq!(loaded.lookup(&id_a).unwrap().issuer_id, ISSUER);
    assert_eq!(loaded.lookup(&id_b).unwrap().issuer_id, ISSUER);
    let c = loaded.lookup(&id_c).unwrap();
    assert_eq!(c.issuer_id, "did:web:other.example");
    assert_eq!(c.valid_until.map(|t| t.to_string()).as_deref(), Some("2027-01-01T00:00:00Z"));
    assert_ne!(loaded.sha256(), first);
    // The file is written in canonical order (issuers by id, keys by id).
    let text = std::fs::read_to_string(&store).unwrap();
    let canonical = serde_json::to_string_pretty(&loaded.to_document()).unwrap() + "\n";
    assert_eq!(text, canonical);
}

#[test]
fn the_same_key_twice_or_a_contradicting_name_is_refused_and_nothing_changes() {
    let s = Scratch::new("ts-refuse");
    let (_, public, id) = exported_key(&s, "factory");
    let (_, other, _) = exported_key(&s, "other");
    let store = s.arg("trust-store.json");
    vmr(&add(&store, &public, ISSUER, NAME)).expect_code(0);
    let before = std::fs::read(&store).unwrap();
    for (args, fragment) in [
        (add(&store, &public, ISSUER, NAME), "already in the trust store"),
        (add(&store, &public, "did:web:other.example", "Other"), "already in the trust store"),
        (add(&store, &other, ISSUER, "Someone Else"), "already in the trust store as"),
    ] {
        let run = vmr(&args);
        run.expect_code(1);
        assert!(run.stderr.contains(fragment), "expected `{fragment}`:\n{}", run.transcript());
        assert_eq!(std::fs::read(&store).unwrap(), before, "the store is unchanged");
    }
    assert!(load(&store).lookup(&id).is_some());
}

#[test]
fn every_trust_decision_is_explicit() {
    let s = Scratch::new("ts-explicit");
    let (_, public, _) = exported_key(&s, "factory");
    let store = s.arg("trust-store.json");
    let full = add(&store, &public, ISSUER, NAME);
    for flag in ["--issuer-id", "--issuer-name", "--attestation-level", "--valid-from", "--public-key", "--trust-store"] {
        let pos = full.iter().position(|a| *a == flag).unwrap();
        let mut args = full.clone();
        args.drain(pos..pos + 2);
        let run = vmr(&args);
        run.expect_code(1);
        assert!(run.stderr.contains(flag), "{flag}:\n{}", run.transcript());
        assert!(!s.path("trust-store.json").exists(), "nothing written without {flag}");
    }
}

#[test]
fn invalid_values_are_refused_before_anything_is_written() {
    let s = Scratch::new("ts-invalid");
    let (_, public, _) = exported_key(&s, "factory");
    let store = s.arg("trust-store.json");
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (add(&store, &public, "factory-operator.ph", NAME), "trust_store.issuer_id"),
        (add(&store, &public, "did:web:fäctory.ph", NAME), "trust_store.issuer_id"),
        (
            {
                let mut a = add(&store, &public, ISSUER, NAME);
                a.extend(["--valid-until", "2025-01-01T00:00:00Z"]);
                a
            },
            "trust_store.validity_window",
        ),
        (
            {
                let mut a = add(&store, &public, ISSUER, NAME);
                let at = a.iter().position(|x| *x == "--valid-from").unwrap() + 1;
                a[at] = "2026-13-01T00:00:00Z";
                a
            },
            "for '--valid-from <T>'",
        ),
        (
            {
                let mut a = add(&store, &public, ISSUER, NAME);
                let at = a.iter().position(|x| *x == "--attestation-level").unwrap() + 1;
                a[at] = "root";
                a
            },
            "for '--attestation-level <LEVEL>'",
        ),
    ];
    for (args, fragment) in &cases {
        let run = vmr(args);
        run.expect_code(1);
        assert!(run.stderr.contains(fragment), "{args:?}: expected `{fragment}`:\n{}", run.transcript());
        assert!(!s.path("trust-store.json").exists(), "{args:?}: nothing written");
    }
}

#[test]
fn a_record_or_an_altered_key_file_is_never_a_source_of_trust() {
    let s = Scratch::new("ts-no-record");
    let store = s.arg("trust-store.json");
    // A record carries a public key; it is still not a key file.
    let record = s.write("record.json", vector().to_json().unwrap());
    let run = vmr(&add(&store, &record, ISSUER, NAME));
    run.expect_code(1);
    assert!(run.stderr.contains("not a public key file"), "{}", run.transcript());
    assert!(!s.path("trust-store.json").exists());

    // A key file whose id was edited to claim another key.
    let (_, public, _) = exported_key(&s, "factory");
    let mut json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&public).unwrap()).unwrap();
    json["key_id"] = serde_json::json!(vector().issuer.key_id);
    let altered = s.write("altered.pub.json", serde_json::to_string_pretty(&json).unwrap());
    let run = vmr(&add(&store, &altered, ISSUER, NAME));
    run.expect_code(1);
    assert!(run.stderr.contains("is not the RFC 7638 thumbprint"), "{}", run.transcript());
    // An off-curve key.
    json = serde_json::from_str(&std::fs::read_to_string(&public).unwrap()).unwrap();
    json["public_key"]["y"] = json["public_key"]["x"].clone();
    let off_curve = s.write("offcurve.pub.json", serde_json::to_string_pretty(&json).unwrap());
    let run = vmr(&add(&store, &off_curve, ISSUER, NAME));
    run.expect_code(1);
    assert!(run.stderr.contains("not a P-256 key"), "{}", run.transcript());
    assert!(!s.path("trust-store.json").exists());
}

#[test]
fn a_store_saved_with_a_byte_order_mark_is_refused_saying_so() {
    // QA P5-07: Windows PowerShell 5.1's `Set-Content -Encoding UTF8` and
    // `Out-File` write a byte order mark (a stock Out-File, UTF-16). The
    // store stays refused - the format is UTF-8 JSON - but the message now
    // names the invisible first bytes and how to save without them.
    let s = Scratch::new("ts-bom");
    let (key, public, _) = exported_key(&s, "factory");
    let store = s.arg("trust-store.json");
    vmr(&add(&store, &public, ISSUER, NAME)).expect_code(0);
    let text = std::fs::read(&store).unwrap();
    let utf16: Vec<u8> = [0xff, 0xfe]
        .into_iter()
        .chain(String::from_utf8(text.clone()).unwrap().encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    let record = s.write("record.json", vector().to_json().unwrap());
    let (_, other, _) = exported_key(&s, "other");
    for (name, bytes, what) in [
        ("bom.json", [&[0xef, 0xbb, 0xbf][..], &text].concat(), "starts with a UTF-8 byte order mark (EF BB BF)"),
        ("utf16.json", utf16, "is UTF-16 text"),
    ] {
        let path = s.write(name, &bytes);
        // verify: exit 1, the loader's kind, then the reason and the fix.
        let run = vmr(&["record", "verify", "--record", &record, "--trust-store", &path, "--at", T]);
        run.expect_code(1);
        for fragment in ["trust_store.syntax", what, "save it as UTF-8 without a byte order mark", "WriteAllText"] {
            assert!(run.stderr.contains(fragment), "{name}: `{fragment}` missing:\n{}", run.transcript());
        }
        // trust-store add: the same, and the file is left as it was.
        let run = vmr(&add(&path, &other, ISSUER, NAME));
        run.expect_code(1);
        assert!(run.stderr.contains(what), "{name}:\n{}", run.transcript());
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{name}: untouched");
    }
    let _ = key;
}

#[test]
fn a_public_key_file_with_a_byte_order_mark_is_refused_saying_so() {
    let s = Scratch::new("ts-bom-public");
    let (_, public, _) = exported_key(&s, "factory");
    let bom = s.write("bom.pub.json", [&[0xef, 0xbb, 0xbf][..], &std::fs::read(&public).unwrap()].concat());
    let run = vmr(&add(&s.arg("trust-store.json"), &bom, ISSUER, NAME));
    run.expect_code(1);
    assert!(run.stderr.contains("starts with a UTF-8 byte order mark (EF BB BF)"), "{}", run.transcript());
    assert!(run.stderr.contains("save it as UTF-8 without a byte order mark"), "{}", run.transcript());
    assert!(!s.path("trust-store.json").exists());
}

#[test]
fn an_unusable_existing_store_is_refused_and_left_alone() {
    let s = Scratch::new("ts-bad-existing");
    let (_, public, _) = exported_key(&s, "factory");
    for (name, content, kind) in [
        ("garbage.json", "not json", "trust_store.syntax"),
        ("v2.json", r#"{"trust_store_version":"0.2","issuers":[]}"#, "trust_store.version"),
    ] {
        let store = s.write(name, content);
        let run = vmr(&add(&store, &public, ISSUER, NAME));
        run.expect_code(1);
        assert!(run.stderr.contains(kind), "{name}:\n{}", run.transcript());
        assert_eq!(std::fs::read_to_string(&store).unwrap(), content, "{name} untouched");
    }
    // A store whose member name would clear the screen: refused, reported
    // with the name escaped - nothing raw reaches the terminal.
    let hostile = serde_json::json!({
        "trust_store_version": "0.1",
        "issuers": [],
        "\u{1b}[2J\u{202e}\u{200b}\u{1b}[32m\u{2713} trusted": 1
    })
    .to_string();
    let store = s.write("hostile.json", &hostile);
    let run = vmr(&add(&store, &public, ISSUER, NAME));
    run.expect_code(1);
    assert!(run.stderr.contains("trust_store.structure"), "{}", run.transcript());
    let raw: Vec<char> = run
        .stderr
        .chars()
        .filter(|&c| c != '\\' && c != '\n' && vmr_verify::display_safe(&c.to_string()) != c.to_string())
        .collect();
    assert!(raw.is_empty(), "raw {raw:?} on stderr:\n{}", run.transcript());
    assert!(run.stderr.contains("\\u{001b}[2J\\u{202e}\\u{200b}"), "{}", run.transcript());
    assert_eq!(std::fs::read_to_string(&store).unwrap(), hostile, "untouched");
}
