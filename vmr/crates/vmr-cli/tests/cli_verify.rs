// tests/cli_verify.rs — TASKS 5.3: `vmr record verify` (TASKS name
// test_cli_verify.cpp; docs/dev/phase5.md §5, C2, C10, C13).
//
// The CLI adds no trust logic: it reads the two files, takes the evaluation
// time, calls vmr-verify and renders the report. So the tests check three
// things: (1) the verdict and first failing check of every committed
// verification vector come out of the binary unchanged — exit 0 or 3 and the
// check id on the headline; (2) `--json` is the in-process report byte for
// byte; (3) everything around the verifier — files, time, the trust store —
// fails cleanly with exit 1, never a panic, and nothing a record says can
// repaint the terminal.

mod common;
use common::*;
use serde_json::Value;

/// The verifier's rendering of a pass starts with this.
const VALID: &str = "✓ Record valid — signed by a key the trust store trusts for this issuer";
/// ... and of a failure with this.
const NOT_VALID: &str = "✗ Record NOT valid — ";

fn verify_args<'a>(record: &'a str, store: &'a str, at: &'a str) -> Vec<&'a str> {
    vec!["record", "verify", "--record", record, "--trust-store", store, "--at", at]
}

#[test]
fn verify_help_documents_every_option_and_the_exit_codes() {
    let run = vmr(&["record", "verify", "--help"]);
    run.expect_code(0);
    for flag in ["--record", "--trust-store", "--at", "--previous", "--require-lineage", "--json"] {
        assert!(run.stdout.contains(flag), "{flag} missing:\n{}", run.transcript());
    }
    assert!(run.stdout.contains("Exit codes:"), "{}", run.transcript());
    assert!(run.stdout.contains("offline"), "{}", run.transcript());
}

#[test]
fn the_committed_vector_verifies_and_names_the_trust_stores_issuer() {
    let s = Scratch::new("verify-vector");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let run = vmr(&verify_args(&record, &store, T));
    run.expect_code(0);
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(lines[0], VALID, "{}", run.transcript());
    let expect = [
        "  Issuer:        did:web:factory-operator.ph (New Clark City Fab Operator, per trust store)",
        "  Key:           urn:ietf:params:oauth:jwk-thumbprint:sha-256:HyoPYysSFOQ5d6x64H8_pHddcHp7E91G5SZbdiaeWJg (software)",
        "  Record:        urn:uuid:2b6a0c48-9f21-4f3a-8c51-1d0b4a7e9c00, issued 2026-09-10T00:00:00Z",
        "  Policy status: \"compliant\", declared by the issuer, not evaluated (example-policy-pack-v1)",
        "  Lineage chain: 1 record (initial)",
        "  Checked at:    2026-09-11T00:00:00Z (--at)",
    ];
    for line in expect {
        assert!(lines.contains(&line), "missing `{line}`:\n{}", run.transcript());
    }
    let vector = vector();
    assert!(run.stdout.contains(&vector.model_identity.learned_state_hash), "{}", run.transcript());
    assert!(run.stdout.contains(&vector.learning_provenance.training_input_digest), "{}", run.transcript());
    let store_id = vmr_verify::TrustStore::from_json(&vector_store("ts-basic")).unwrap().sha256().to_string();
    assert!(run.stdout.contains(&format!("  Trust store:   {store_id}")), "{}", run.transcript());
    assert!(run.stderr.is_empty(), "{}", run.transcript());
}

#[test]
fn the_general_vector_verifies_through_the_binary() {
    // Task 10.11b (spec §7.3, §8.4): a record in the general description
    // verifies through `vmr record verify` as any other does, and the output
    // says that it commits no training records instead of showing "".
    let s = Scratch::new("verify-general");
    let general = general_vector();
    let record = s.write("record.json", general.to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let run = vmr(&verify_args(&record, &store, T));
    run.expect_code(0);
    assert_eq!(run.stdout.lines().next(), Some(VALID), "{}", run.transcript());
    assert!(run.stdout.contains(&format!("  Components:    {}", general.model_identity.learned_state_hash)), "{}", run.transcript());
    assert!(
        run.stdout.contains("  Training data: none committed (not disclosed, or not held by the issuer)"),
        "{}",
        run.transcript()
    );
    let mut json_args = verify_args(&record, &store, T);
    json_args.push("--json");
    let json = vmr(&json_args);
    json.expect_code(0);
    let report: Value = serde_json::from_str(&json.stdout).unwrap();
    let consistency = report["checks"].as_array().unwrap().iter().find(|c| c["id"] == "format.consistency").unwrap();
    assert_eq!(
        consistency["detail"],
        "general model description: 4 components in name order; learned_state_hash is their named-set digest"
    );
}

#[test]
fn verify_names_the_model_by_model_hash_and_the_components_by_their_digest() {
    // QA QC-02 (the reviewer's decision): a model's identity is model_hash
    // (spec §7.3, §7.4; what an enforcer binds since task 8.10), and `record
    // verify` shows it with model_format, as `record inspect` does. A general
    // record's learned_state_hash is the digest of the components its issuer
    // chose, shown as "Components"; the profile keeps "Model state". A record
    // of four files whose components are its two shards has two different
    // values, each under its own label, on a pass and among a failure's claims.
    let mut p = general_vector();
    p.model_identity.learned_state_components.retain(|c| c.name.ends_with(".safetensors"));
    assert_eq!(p.model_identity.learned_state_components.len(), 2);
    let mut digest = vmr_record::named_set::NamedSetDigest::new();
    for c in &p.model_identity.learned_state_components {
        digest.push(&c.name, &vmr_record::hash::parse_hash(&c.hash).unwrap()).unwrap();
    }
    p.model_identity.learned_state_hash = vmr_record::hash::format_hash(&digest.finish());
    sign_as(&mut p, KEY_A);
    let m = p.model_identity.clone();
    assert_ne!(m.model_hash, m.learned_state_hash);

    let s = Scratch::new("verify-model-hash");
    let record = s.write("record.json", p.to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let run = vmr(&verify_args(&record, &store, T));
    run.expect_code(0);
    let lines: Vec<&str> = run.stdout.lines().collect();
    let model = format!("  Model:         {} ({})", m.model_hash, m.model_format);
    let components = format!("  Components:    {}", m.learned_state_hash);
    assert!(lines.contains(&model.as_str()), "missing `{model}`:\n{}", run.transcript());
    assert!(lines.contains(&components.as_str()), "missing `{components}`:\n{}", run.transcript());
    assert!(!run.stdout.contains("Model state"), "{}", run.transcript());

    // Refused by a store that trusts no one: the same values, as claims.
    let empty = s.write("empty.json", vector_store("ts-empty"));
    let failed = vmr(&verify_args(&record, &empty, T));
    failed.expect_code(3);
    let claim = |label: &str, value: &str| {
        failed.stdout.lines().any(|l| l.trim_start().starts_with(&format!("{label}:")) && l.trim_end().ends_with(value))
    };
    assert!(claim("Model", &format!("{} ({})", m.model_hash, m.model_format)), "{}", failed.transcript());
    assert!(claim("Components", &m.learned_state_hash), "{}", failed.transcript());
}

#[test]
fn the_policy_line_never_reads_as_an_evaluation() {
    // C6: the record's policy_compliance is the issuer's declaration.
    // Whatever it declares, the output says so, and says it was not
    // evaluated; the report records no evaluation.
    let s = Scratch::new("verify-policy");
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    for status in ["compliant", "non-compliant", "indeterminate"] {
        let mut p = vector();
        p.policy_compliance.overall_status = status.into();
        sign_as(&mut p, KEY_A);
        let record = s.write("record.json", p.to_json().unwrap());
        let run = vmr(&verify_args(&record, &store, T));
        run.expect_code(0); // a declaration is content, not a verdict
        let policy: Vec<&str> = run.stdout.lines().filter(|l| l.contains("Policy")).collect();
        assert_eq!(policy.len(), 1, "{}", run.transcript());
        assert_eq!(
            policy[0],
            format!("  Policy status: \"{status}\", declared by the issuer, not evaluated (example-policy-pack-v1)")
        );
        let mut args = verify_args(&record, &store, T);
        args.push("--json");
        let json: Value = serde_json::from_str(&vmr(&args).stdout).unwrap();
        assert_eq!(json["policy"]["evaluation"]["state"], "not_requested");
        assert_eq!(json["policy"]["declared"]["overall_status"], status);
    }
}

#[test]
fn the_cose_form_verifies_with_the_same_result() {
    let s = Scratch::new("verify-cose");
    let record = s.write("record.vmr", vector().to_cose().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let run = vmr(&verify_args(&record, &store, T));
    run.expect_code(0);
    assert_eq!(headline(&run), VALID, "{}", run.transcript());
}

#[test]
fn json_output_is_the_verifiers_report_byte_for_byte() {
    let s = Scratch::new("verify-json");
    let store_bytes = vector_store("ts-basic");
    let store = s.write("trust-store.json", &store_bytes);
    let mut forged = vector();
    reissue_with(&mut forged, KEY_FORGER);
    for (name, bytes) in [
        ("pass.json", vector().to_json().unwrap().into_bytes()),
        ("pass.vmr", vector().to_cose().unwrap()),
        ("forged.json", forged.to_json().unwrap().into_bytes()),
        ("garbage.bin", b"\x00\x01garbage".to_vec()),
    ] {
        let record = s.write(name, &bytes);
        let mut args = verify_args(&record, &store, T);
        args.push("--json");
        let run = vmr(&args);
        let expected = in_process_report(&bytes, &store_bytes, T, &[], false);
        run.expect_code(expected.exit_code());
        assert_eq!(run.stdout, format!("{}\n", expected.to_json().unwrap()), "{name}");
        assert!(run.stderr.is_empty(), "{}", run.transcript());
    }
}

#[test]
fn every_verification_vector_gives_its_verdict_and_check_through_the_cli() {
    // The committed cross-implementation contract (specs/test-vectors/verify/):
    // 79 cases, every check id, JSON and COSE, chains with --previous and
    // --require-lineage. The binary must reproduce each verdict and first
    // failing check, and its --json must be the in-process report.
    let s = Scratch::new("verify-vectors");
    let doc: Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join("specs/test-vectors/verify/cases.json")).unwrap(),
    )
    .unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 79, "{} cases", cases.len());
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let input = vector_input_bytes(&case["input"]);
        let record = s.write(&format!("{id}.record"), &input);
        let store_name = case["trust_store"].as_str().unwrap();
        let store = s.write(&format!("{store_name}.json"), vector_store(store_name));
        let at = case["evaluation_time"].as_str().unwrap();
        let previous: Vec<Vec<u8>> =
            case["previous"].as_array().unwrap().iter().map(vector_input_bytes).collect();
        let previous_args: Vec<String> = previous
            .iter()
            .enumerate()
            .map(|(i, bytes)| s.write(&format!("{id}.previous-{i}"), bytes))
            .collect();
        let require = case["require_complete_lineage"].as_bool().unwrap();

        let mut args = verify_args(&record, &store, at);
        for p in &previous_args {
            args.extend(["--previous", p.as_str()]);
        }
        if require {
            args.push("--require-lineage");
        }
        let run = vmr(&args);
        let expected = &case["expected"];
        if expected["verdict"] == "pass" {
            run.expect_code(0);
            assert_eq!(headline(&run), VALID, "{id}:\n{}", run.transcript());
        } else {
            run.expect_code(3);
            let check = expected["check"].as_str().unwrap();
            assert!(
                headline(&run).starts_with(&format!("{NOT_VALID}{check}: ")),
                "{id}: expected first failing check {check}:\n{}",
                run.transcript()
            );
        }

        args.push("--json");
        let json = vmr(&args);
        let report = in_process_report(&input, &vector_store(store_name), at, &previous, require);
        assert_eq!(json.stdout, format!("{}\n", report.to_json().unwrap()), "{id}: --json");
        if let Some(lineage) = expected.get("lineage") {
            let printed: Value = serde_json::from_str(&json.stdout).unwrap();
            assert_eq!(&printed["lineage"]["status"], lineage, "{id}");
        }
    }
}

#[test]
fn lineage_outcomes_are_rendered_as_what_was_verified() {
    let s = Scratch::new("verify-lineage");
    let doc: Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join("specs/test-vectors/verify/cases.json")).unwrap(),
    )
    .unwrap();
    let case = |id: &str| doc["cases"].as_array().unwrap().iter().find(|c| c["id"] == id).unwrap().clone();
    let store = s.write("trust-store.json", vector_store("ts-basic"));

    let complete = case("pass-chain-3-complete");
    let head = s.write("head.json", vector_input_bytes(&complete["input"]));
    let mut args = verify_args(&head, &store, T);
    let prev: Vec<String> = complete["previous"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, p)| s.write(&format!("prev-{i}.json"), vector_input_bytes(p)))
        .collect();
    for p in &prev {
        args.extend(["--previous", p.as_str()]);
    }
    let run = vmr(&args);
    run.expect_code(0);
    assert!(
        run.stdout.contains("  Lineage chain: 3 records, verified back to the initial record"),
        "{}",
        run.transcript()
    );

    // A non-initial record alone: it verifies, and says its lineage was
    // not verified; requiring the lineage makes that a failure.
    let lone = case("pass-chain-not-checked");
    let head = s.write("lone.json", vector_input_bytes(&lone["input"]));
    let run = vmr(&verify_args(&head, &store, T));
    run.expect_code(0);
    let line = run.stdout.lines().find(|l| l.starts_with("  Lineage chain:")).unwrap();
    assert!(line.contains("declared") && line.contains("not verified"), "{}", run.transcript());
    let mut args = verify_args(&head, &store, T);
    args.push("--require-lineage");
    let run = vmr(&args);
    run.expect_code(3);
    assert!(headline(&run).starts_with(&format!("{NOT_VALID}lineage.chain: ")), "{}", run.transcript());
}

#[test]
fn a_tampered_byte_fails_signature_valid_with_exit_3() {
    // The demo's tamper: one claim changed inside the COSE envelope, same
    // length, so the envelope still decodes — only the signature can tell.
    let s = Scratch::new("verify-tamper");
    let mut bytes = vector().to_cose().unwrap();
    let needle = b"\"data_residency\":\"PH\"";
    let at = bytes.windows(needle.len()).position(|w| w == needle).expect("the claim is in the payload");
    bytes[at + needle.len() - 3] = b'S';
    bytes[at + needle.len() - 2] = b'G';
    let record = s.write("tampered.vmr", &bytes);
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let run = vmr(&verify_args(&record, &store, T));
    run.expect_code(3);
    assert!(headline(&run).starts_with(&format!("{NOT_VALID}signature.valid: ")), "{}", run.transcript());
    // What the demo audience reads: plain words, no crypto-library text.
    assert!(headline(&run).contains("the record was changed after it was signed"), "{}", run.transcript());
    assert!(!run.stdout.contains("signature error"), "{}", run.transcript());
    assert!(run.stdout.contains("Claims (not verified):"), "{}", run.transcript());
}

#[test]
fn a_forged_record_fails_trust_key_known_with_exit_3() {
    // QA PROBE 6: the forger embeds their own key everywhere and re-signs.
    // Integrity holds; trust does not.
    let s = Scratch::new("verify-forged");
    let mut p = vector();
    p.deployment_context.as_mut().unwrap().inference_boundary.egress_allowed = true;
    reissue_with(&mut p, KEY_FORGER);
    let record = s.write("forged.json", p.to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let run = vmr(&verify_args(&record, &store, T));
    run.expect_code(3);
    assert!(headline(&run).starts_with(&format!("{NOT_VALID}trust.key_known: ")), "{}", run.transcript());
    assert!(headline(&run).contains("is not in the trust store"), "{}", run.transcript());
    // The claims are shown only as claims.
    assert!(run.stdout.contains("did:web:factory-operator.ph"), "{}", run.transcript());
    assert!(!run.stdout.contains("per trust store"), "{}", run.transcript());
}

#[test]
fn an_empty_trust_store_trusts_nothing_and_another_issuers_key_speaks_for_no_one_else() {
    let s = Scratch::new("verify-stores");
    let record = s.write("record.json", vector().to_json().unwrap());
    let empty = s.write("empty.json", r#"{"trust_store_version":"0.1","issuers":[]}"#);
    let run = vmr(&verify_args(&record, &empty, T));
    run.expect_code(3);
    assert!(headline(&run).starts_with(&format!("{NOT_VALID}trust.key_known: ")), "{}", run.transcript());

    let other = s.write("other.json", vector_store("ts-key-for-other-issuer"));
    let run = vmr(&verify_args(&record, &other, T));
    run.expect_code(3);
    assert!(headline(&run).starts_with(&format!("{NOT_VALID}trust.issuer: ")), "{}", run.transcript());
}

#[test]
fn malformed_and_truncated_records_fail_cleanly_with_exit_3() {
    let s = Scratch::new("verify-malformed");
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let json = vector().to_json().unwrap().into_bytes();
    let cose = vector().to_cose().unwrap();
    let mut inputs: Vec<(String, Vec<u8>, &str)> = vec![
        ("empty".into(), vec![], "input.form"),
        ("whitespace".into(), b"  \n\t ".to_vec(), "input.form"),
        ("brace".into(), b"{".to_vec(), "json.syntax"),
        ("garbage".into(), b"\xff\xfe\x00garbage".to_vec(), "input.form"),
        ("bom".into(), [&[0xef, 0xbb, 0xbf][..], &json].concat(), "input.form"),
        ("not-utf8".into(), [&b"{\"record_version\":\""[..], &[0xc3, 0x28], b"\"}"].concat(), "json.syntax"),
        ("tagged-cose".into(), [&[0xd2][..], &cose].concat(), "input.form"),
        ("empty-object".into(), b"{}".to_vec(), "json.structure"),
        ("oversized".into(), [&json[..], &vec![b' '; 1024 * 1024]].concat(), "input.size"),
    ];
    for cut in [1, 2, 10, 100, cose.len() / 2, cose.len() - 1] {
        inputs.push((format!("cose-cut-{cut}"), cose[..cut].to_vec(), "cose.structure"));
    }
    for cut in [1, 50, json.len() / 2, json.len() - 1] {
        inputs.push((format!("json-cut-{cut}"), json[..cut].to_vec(), "json.syntax"));
    }
    for (name, bytes, check) in &inputs {
        let record = s.write(name, bytes);
        let run = vmr(&verify_args(&record, &store, T));
        run.expect_code(3);
        assert!(
            headline(&run).starts_with(&format!("{NOT_VALID}{check}: ")),
            "{name}: expected {check}:\n{}",
            run.transcript()
        );
        assert!(run.stderr.is_empty(), "{name}:\n{}", run.transcript());
    }
}

#[test]
fn an_unusable_trust_store_is_an_input_error_with_exit_1() {
    // Every committed trust-store loader vector: a store the loader rejects
    // is the operator's error (exit 1, the loader's kind named), never a
    // verification result; a store it accepts lets verification run.
    let s = Scratch::new("verify-bad-stores");
    let record = s.write("record.json", vector().to_json().unwrap());
    let doc: Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join("specs/test-vectors/trust-store/cases.json")).unwrap(),
    )
    .unwrap();
    for case in doc["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let store = s.write(&format!("{id}.json"), vector_input_bytes(&case["input"]));
        let run = vmr(&verify_args(&record, &store, T));
        if case["expected"]["result"] == "ok" {
            assert!(run.code == 0 || run.code == 3, "{id}:\n{}", run.transcript());
        } else {
            run.expect_code(1);
            let kind = case["expected"]["kind"].as_str().unwrap();
            assert!(run.stderr.contains(kind), "{id}: expected {kind}:\n{}", run.transcript());
            assert!(run.stderr.starts_with("vmr: error: "), "{id}:\n{}", run.transcript());
            assert!(run.stdout.is_empty(), "{id}:\n{}", run.transcript());
        }
    }
}

/// The characters `display_safe` escapes (the backslash aside, which it
/// doubles), the newline aside (it ends every line vmr prints): nothing a
/// terminal acts on or hides may reach it raw.
fn raw_unsafe(text: &str) -> Vec<char> {
    text.chars()
        .filter(|&c| c != '\\' && c != '\n' && vmr_verify::display_safe(&c.to_string()) != c.to_string())
        .collect()
}

#[test]
fn a_hostile_trust_store_never_reaches_the_terminal_raw() {
    // A trust store is untrusted input when it reaches the wrong person, and
    // an unusable one is reported on stderr, quoting what it got wrong. With
    // member names and an enum value that clear the screen and paint a fake
    // verdict (the store file holds ESC as the JSON escape \u001b, the bidi
    // override and the zero-width space raw), stderr must show them escaped:
    // the tool exits 1 and nothing on the terminal may say otherwise.
    let s = Scratch::new("verify-hostile-store");
    let record = s.write("record.json", vector().to_json().unwrap());
    let good: Value = serde_json::from_slice(&vector_store("ts-basic")).unwrap();
    // (A name is quoted with at most 64 characters: the probes come first.)
    let fake = "\u{1b}[2J\u{202e}\u{200b}\u{1b}[H\u{1b}[32m\u{2713} Record valid \u{2014} signed by a key the trust store trusts\u{1b}[0m";
    let mut member = good.clone();
    member[fake] = 1.into();
    let mut issuer_member = good.clone();
    issuer_member["issuers"][0][fake] = 1.into();
    let mut level = good.clone();
    level["issuers"][0]["keys"][0]["attestation_level"] = fake.into();
    for (name, doc) in [("unknown-member", member), ("unknown-issuer-member", issuer_member), ("bad-enum", level)] {
        let store = s.write(&format!("{name}.json"), serde_json::to_string(&doc).unwrap());
        assert!(std::fs::read_to_string(&store).unwrap().contains("\\u001b[2J"), "{name}: ESC travels escaped");
        let run = vmr(&verify_args(&record, &store, T));
        run.expect_code(1);
        assert!(run.stderr.starts_with("vmr: error: "), "{name}:\n{}", run.transcript());
        assert!(run.stderr.contains("trust_store.structure"), "{name}:\n{}", run.transcript());
        assert!(run.stdout.is_empty(), "{name}:\n{}", run.transcript());
        let raw = raw_unsafe(&run.stderr);
        assert!(raw.is_empty(), "{name}: raw {raw:?} on stderr:\n{}", run.transcript());
        for escaped in ["\\u{001b}[2J", "\\u{202e}", "\\u{200b}"] {
            assert!(run.stderr.contains(escaped), "{name}: {escaped} missing:\n{}", run.transcript());
        }
    }
}

#[test]
fn a_trust_store_member_name_of_100_000_characters_gives_a_bounded_message() {
    let s = Scratch::new("verify-huge-member");
    let record = s.write("record.json", vector().to_json().unwrap());
    let mut doc: Value = serde_json::from_slice(&vector_store("ts-basic")).unwrap();
    doc["x".repeat(100_000).as_str()] = 1.into();
    let store = s.write("trust-store.json", serde_json::to_string(&doc).unwrap());
    let run = vmr(&verify_args(&record, &store, T));
    run.expect_code(1);
    assert!(run.stderr.contains("trust_store.structure: unknown field `"), "{}", run.transcript());
    assert!(run.stderr.len() < 2000, "{} bytes on stderr", run.stderr.len());
    assert!(!run.stderr.contains(&"x".repeat(65)), "at most 64 characters of the name:\n{}", run.transcript());
}

#[test]
fn missing_files_and_bad_arguments_are_input_errors_with_exit_1() {
    let s = Scratch::new("verify-args");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let missing = s.arg("no-such-file.json");
    let extended = |flag: &'static str| {
        let mut a = verify_args(&record, &store, T);
        a.extend([flag, missing.as_str()]);
        a
    };
    let missing_previous = extended("--previous");
    let missing_pack = extended("--policy-pack");
    // (arguments, a fragment stderr must contain)
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (verify_args(&missing, &store, T), "cannot read record"),
        (verify_args(&record, &missing, T), "cannot read trust store"),
        (verify_args(&record, &store, "yesterday"), "invalid value 'yesterday' for '--at <T>'"),
        (verify_args(&record, &store, "2026-09-11T00:00:00+00:00"), "for '--at <T>'"),
        (verify_args(&record, &store, "2026-02-30T00:00:00Z"), "the date is not in the calendar"),
        (vec!["record", "verify", "--record", &record], "--trust-store <FILE>"),
        (vec!["record", "verify", "--trust-store", &store], "--record <FILE>"),
        (missing_previous, "cannot read predecessor record"),
        // `--policy-pack` exists since P6-13 (it reverses C6, which refused
        // a flag nothing could honour), and it names a FILE like every
        // other input: an unreadable one is the operator's error, not a
        // verification result. What the flag DOES is tests/cli_verify_policy.rs.
        (missing_pack, "cannot read policy pack"),
    ];
    for (args, fragment) in &cases {
        let run = vmr(args);
        run.expect_code(1);
        assert!(run.stdout.is_empty(), "{args:?}:\n{}", run.transcript());
        assert!(run.stderr.contains(fragment), "{args:?}: expected `{fragment}`:\n{}", run.transcript());
    }
}

#[test]
fn a_file_larger_than_16_mib_is_not_read() {
    let s = Scratch::new("verify-huge");
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let record = s.write("huge.json", vec![b' '; 16 * 1024 * 1024 + 1]);
    let run = vmr(&verify_args(&record, &store, T));
    run.expect_code(1);
    assert!(run.stderr.contains("16 MiB"), "{}", run.transcript());
}

#[test]
fn control_characters_in_a_record_never_reach_the_terminal() {
    // An issuer_name carrying ANSI escapes and a bidi override: shown as a
    // claim on failure, it must arrive escaped (display_safe), or it could
    // repaint the screen with a fake "valid" line.
    let s = Scratch::new("verify-escapes");
    let mut p = vector();
    p.issuer.issuer_name = "Evil\u{1b}[2K\r\u{1b}[32m✓ Record valid\u{202e}".into();
    reissue_with(&mut p, KEY_FORGER);
    let record = s.write("evil.json", p.to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let run = vmr(&verify_args(&record, &store, T));
    run.expect_code(3);
    for bad in ['\u{1b}', '\r', '\u{202e}'] {
        assert!(!run.stdout.contains(bad), "raw {bad:?} reached stdout:\n{}", run.transcript());
    }
    assert!(run.stdout.contains("\\u{001b}"), "{}", run.transcript());
    assert_eq!(run.stdout.lines().filter(|l| l.starts_with('✓')).count(), 0);
}

#[test]
fn control_and_bidi_characters_in_component_names_never_reach_the_terminal() {
    // QA QB-08: spec §7.2 compares names exactly and refuses no control or
    // bidi character in one, so a record can carry such names, and a bad
    // name is quoted in a failure's detail. verify's output, in its human and
    // its --json form, shows each escaped.
    use vmr_record::hash::{format_hash, sha256};
    use vmr_record::record::StateComponent;
    let s = Scratch::new("verify-component-names");
    let store = s.write("trust-store.json", vector_store("ts-basic"));

    // A consistent record whose component names hold U+0001 and U+202E.
    let files = [("\u{1}config.json", "{}"), ("weights\u{202e}lmth.bin", "0000")];
    let digest = vmr_record::named_set::named_set_digest(&files.map(|(name, text)| (name, sha256(text.as_bytes())))).unwrap();
    let mut named = general_vector();
    named.model_identity.learned_state_components = files
        .iter()
        .map(|(name, text)| StateComponent {
            name: name.to_string(),
            hash: format_hash(&sha256(text.as_bytes())),
            size_bytes: text.len() as u64,
        })
        .collect();
    named.model_identity.learned_state_hash = format_hash(&digest);
    named.model_identity.model_hash = format_hash(&digest);
    sign_as(&mut named, KEY_A);
    // The same with a name the rules refuse, so format.consistency quotes it.
    let mut refused = named.clone();
    refused.model_identity.learned_state_components[0].name = "\u{1}\u{1b}[2J\u{202e}/../config.json".into();

    for (label, p, code) in [("named", &named, 0), ("refused", &refused, 3)] {
        let record = s.write(&format!("{label}.json"), p.to_json().unwrap());
        for json in [false, true] {
            let mut args = verify_args(&record, &store, T);
            if json {
                args.push("--json");
            }
            let run = vmr(&args);
            run.expect_code(code);
            let raw = raw_unsafe(&run.stdout);
            assert!(raw.is_empty(), "{label} (--json: {json}): raw {raw:?} on stdout:\n{}", run.transcript());
        }
    }
}

#[test]
fn a_one_mib_record_gives_a_short_terminal_safe_rendering() {
    // QA P5-05: claims were escaped but not cut - a 1 MB record whose
    // issuer_name is 250 000 tag characters (invisible, each escaped as
    // \u{e0041}) printed 2.25 MB on a failure. Every value a rendering shows
    // is cut first, escaped second, and marked with its whole length; --json
    // stays the complete report.
    let s = Scratch::new("verify-huge-claims");
    let name: String = std::iter::repeat_n('\u{e0041}', 250_000).collect();
    let mut p = vector();
    p.issuer.issuer_name = name.clone();
    reissue_with(&mut p, KEY_FORGER);
    let bytes = p.to_json().unwrap().into_bytes();
    assert!(bytes.len() > 1_000_000 && bytes.len() <= 1024 * 1024, "{} bytes", bytes.len());
    let record = s.write("big.json", &bytes);
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let run = vmr(&verify_args(&record, &store, T));
    run.expect_code(3);
    assert!(run.stdout.len() < 8 * 1024, "{} bytes on stdout", run.stdout.len());
    let raw = raw_unsafe(&run.stdout);
    assert!(raw.is_empty(), "raw {:?} on stdout", &raw[..raw.len().min(4)]);
    let issuer = run.stdout.lines().find(|l| l.trim_start().starts_with("Issuer:")).unwrap();
    assert!(issuer.contains("\\u{e0041}…[250000 characters in all]"), "{issuer}");
    // --json: the whole claim, as the report holds it.
    let mut args = verify_args(&record, &store, T);
    args.push("--json");
    let run = vmr(&args);
    run.expect_code(3);
    let parsed: Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(parsed["record"]["issuer_name"], name.as_str(), "--json is complete");
}

#[test]
fn json_output_carries_no_character_a_terminal_acts_on() {
    // --json prints the report byte for byte, and the report's JSON writes
    // every character display_safe escapes as a JSON \u escape (serde_json
    // alone leaves DEL, C1 controls, bidi controls and invisible characters
    // raw): a record's claims reach the terminal inert and parse back
    // unchanged.
    let s = Scratch::new("verify-json-escapes");
    let name = "Evil\u{7f}\u{9b}32m\u{202e}\u{200b}\u{2028}\u{e0041}\u{ffff} \u{e9}";
    let mut p = vector();
    p.issuer.issuer_name = name.into();
    reissue_with(&mut p, KEY_FORGER);
    let bytes = p.to_json().unwrap().into_bytes();
    let record = s.write("evil.json", &bytes);
    let store_bytes = vector_store("ts-basic");
    let store = s.write("trust-store.json", &store_bytes);
    let mut args = verify_args(&record, &store, T);
    args.push("--json");
    let run = vmr(&args);
    run.expect_code(3);
    let raw = raw_unsafe(&run.stdout);
    assert!(raw.is_empty(), "raw {raw:?} on stdout:\n{}", run.transcript());
    let expected = in_process_report(&bytes, &store_bytes, T, &[], false);
    assert_eq!(run.stdout, format!("{}\n", expected.to_json().unwrap()), "still the report byte for byte");
    let parsed: Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(parsed["record"]["issuer_name"], name, "and the claim parses back unchanged");
}

#[test]
fn the_evaluation_time_is_an_input() {
    let s = Scratch::new("verify-time");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    // issued_at is 2026-09-10T00:00:00Z: a second earlier, it is from the future.
    let run = vmr(&verify_args(&record, &store, "2026-09-09T23:59:59Z"));
    run.expect_code(3);
    assert!(headline(&run).starts_with(&format!("{NOT_VALID}time.not_future: ")), "{}", run.transcript());
    let run = vmr(&verify_args(&record, &store, "2026-09-10T00:00:00Z"));
    run.expect_code(0);
}

#[test]
fn without_at_the_current_time_is_used_and_shown() {
    // C2: the one clock read, visible in the output. (Assumes the test
    // machine's clock is past the vector's issued_at, 2026-09-10.)
    let s = Scratch::new("verify-now");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let run = vmr(&["record", "verify", "--record", &record, "--trust-store", &store]);
    run.expect_code(0);
    let line = run.stdout.lines().find(|l| l.starts_with("  Checked at:")).unwrap();
    assert!(line.ends_with(" (current time)"), "{line}");
    let t = line.trim_start_matches("  Checked at:").trim().trim_end_matches(" (current time)");
    let t = vmr_record::timestamp::Timestamp::parse(t).expect("a profile timestamp");
    assert!(t >= vmr_record::timestamp::Timestamp::parse("2026-09-10T00:00:00Z").unwrap());
}

#[test]
fn verify_needs_nothing_but_the_record_and_the_trust_store() {
    // The second terminal: a cleared environment, a non-UTC time zone, and a
    // working directory holding exactly the two files, named relatively.
    let s = Scratch::new("verify-isolated");
    let dir = s.subdir("verifier");
    std::fs::write(dir.join("model.vmr"), vector().to_cose().unwrap()).unwrap();
    std::fs::write(dir.join("trust-store.json"), vector_store("ts-basic")).unwrap();
    let run = vmr_isolated(
        &dir,
        &[("TZ", "Pacific/Kiritimati")],
        &verify_args("model.vmr", "trust-store.json", T),
    );
    run.expect_code(0);
    assert_eq!(headline(&run), VALID, "{}", run.transcript());
    let mut names: Vec<String> =
        std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, ["model.vmr", "trust-store.json"], "verify wrote nothing");
}
