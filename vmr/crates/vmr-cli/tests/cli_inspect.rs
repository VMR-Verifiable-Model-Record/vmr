// tests/cli_inspect.rs — TASKS 5.4: `vmr record inspect` (TASKS name
// test_cli_inspect.cpp; docs/dev/phase5.md §2, C10).
//
// Inspect prints what a record SAYS. It checks nothing, so its output
// must be impossible to mistake for verification: an UNVERIFIED banner
// first, claims labelled as claims, the policy as a declaration — and a
// forged record inspects exactly like a genuine one.

mod common;
use common::*;

const BANNER: &str =
    "UNVERIFIED — the record's own claims; nothing here was checked against a trust store.";

#[test]
fn inspect_help_says_it_does_not_verify() {
    let run = vmr(&["record", "inspect", "--help"]);
    run.expect_code(0);
    assert!(run.stdout.contains("--record"), "{}", run.transcript());
    assert!(run.stdout.contains("does not verify"), "{}", run.transcript());
    assert!(run.stdout.contains("Exit codes:"), "{}", run.transcript());
}

#[test]
fn a_general_record_is_inspected_in_its_own_words() {
    // Task 10.11b (spec §7.3, §8.4): a record in the general description
    // shows its model hash and its components' named-set digest, counts
    // records, not frames, and says its training records are not held
    // instead of showing "" as a digest. QA QB-07: it names no accelerator
    // software it does not state, and says "times not stated" and "source
    // not stated". Task 10.12a: its environment line names no engine.
    let s = Scratch::new("inspect-general");
    let p = general_vector();
    let file = s.write("record.json", p.to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &file]);
    run.expect_code(0);
    assert_eq!(headline(&run), BANNER, "{}", run.transcript());
    for expected in [
        p.model_identity.model_hash.as_str(),
        "safetensors, 64 parameters, as the issuer states",
        "the components' named-set digest",
        "config.json",
        "model-00002-of-00002.safetensors",
        "tokenizer.json",
        "none committed: not held by the issuer (0 records, epochs not stated, times not stated)",
        "source not stated, residency not stated, collection period not stated",
    ] {
        assert!(run.stdout.contains(expected), "missing {expected}:\n{}", run.transcript());
    }
    let merkle = run.stdout.lines().find(|l| l.trim_start().starts_with("Merkle root:")).unwrap();
    assert!(merkle.trim_end().ends_with("none"), "{merkle}");
    for absent in ["frames", "CUDA", "accelerator software", "not stated to not stated"] {
        assert!(!run.stdout.contains(absent), "{absent} shown:\n{}", run.transcript());
    }
    let environment = run.stdout.lines().find(|l| l.trim_start().starts_with("Environment:")).unwrap();
    assert!(environment.contains("training software none") && !environment.contains("engine"), "{environment}");
}

#[test]
fn control_and_bidi_characters_in_component_names_are_escaped() {
    // QA QB-08: spec §7.2 refuses no control or bidi character in a name, so
    // a record can carry one; inspect shows each escaped, like every claim.
    let s = Scratch::new("inspect-component-names");
    let mut p = general_vector();
    p.model_identity.learned_state_components[0].name = "\u{1}config\u{202e}.json".into();
    let file = s.write("names.json", p.to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &file]);
    run.expect_code(0);
    for bad in ['\u{1}', '\u{202e}'] {
        assert!(!run.stdout.contains(bad), "raw {bad:?} reached stdout:\n{}", run.transcript());
    }
    let line = run.stdout.lines().find(|l| l.trim_start().starts_with("Components:")).unwrap();
    assert!(line.contains("\\u{0001}") && line.contains("\\u{202e}"), "{line}");
}

#[test]
fn a_record_that_states_no_parameter_count_reads_not_stated() {
    // QA QB-09: parameter_count is optional in the general description (spec
    // §7.3). Inspect checks nothing, so a profile record without it reads the
    // same way; verify refuses that one at format.consistency (§7.4).
    let s = Scratch::new("inspect-parameters");
    let mut general = general_vector();
    general.model_identity.parameter_count = None;
    sign_as(&mut general, KEY_A);
    let mut profile = vector();
    profile.model_identity.parameter_count = None;
    sign_as(&mut profile, KEY_A);
    for (name, p, expected) in [
        ("general.json", general, "(safetensors, parameters not stated)"),
        ("profile.json", profile, "(snn-compact-v1, parameters not stated)"),
    ] {
        let file = s.write(name, p.to_json().unwrap());
        let run = vmr(&["record", "inspect", "--record", &file]);
        run.expect_code(0);
        assert!(run.stdout.contains(expected), "missing {expected}:\n{}", run.transcript());
    }
}

#[test]
fn inspect_prints_the_claims_under_an_unverified_banner() {
    let s = Scratch::new("inspect-vector");
    let p = vector();
    let file = s.write("record.json", p.to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &file]);
    run.expect_code(0);
    assert_eq!(headline(&run), BANNER, "{}", run.transcript());
    assert!(run.stdout.contains("vmr record verify"), "{}", run.transcript());
    for expected in [
        p.record_id.as_str(),
        p.issued_at.as_str(),
        p.issuer.issuer_id.as_str(),
        p.issuer.issuer_name.as_str(),
        p.issuer.key_id.as_str(),
        p.model_identity.learned_state_hash.as_str(),
        p.learning_provenance.training_input_digest.as_str(),
        p.learning_provenance.training_input_merkle_root.as_str(),
        p.deployment_context.as_ref().unwrap().deployment_id.as_str(),
        p.lineage.root_record_id.as_str(),
        p.signature.signed_payload_hash.as_str(),
        "afferent_H",
        "recurrent_H",
        "thresholds",
        "24704 parameters",
        "residency PH",
    ] {
        assert!(run.stdout.contains(expected), "missing {expected}:\n{}", run.transcript());
    }
    let policy = run.stdout.lines().find(|l| l.trim_start().starts_with("Policy:")).unwrap();
    assert!(policy.contains("\"compliant\"") && policy.contains("declared by the issuer, not evaluated"), "{policy}");
    assert!(!run.stdout.contains('✓'), "inspect never shows a check mark:\n{}", run.transcript());
    assert!(run.stderr.is_empty(), "{}", run.transcript());
    // QA QB-07: a profile record states its accelerator software, its
    // training times and its source, so these three lines read them all;
    // task 10.12a names the environment's members generally.
    let line = |label: &str| {
        run.stdout
            .lines()
            .map(str::trim_start)
            .find(|l| l.starts_with(label))
            .unwrap_or_else(|| panic!("no {label} line:\n{}", run.transcript()))
            .to_string()
    };
    let none = |v: &str| if v.is_empty() { "none".to_string() } else { v.to_string() };
    let l = &p.learning_provenance;
    let env = &l.training_environment;
    let environment = format!(
        "training software {}, accelerator software {}, hardware {}, TEE {}, software {}",
        none(&env.training_software),
        none(env.accelerator_software.as_deref().expect("the vector states accelerator_software")),
        none(&env.hardware_id),
        none(&env.tee_measurement),
        none(&env.software_hash)
    );
    assert_eq!(line("Environment:"), format!("{:<16}{environment}", "Environment:"));
    let (started, ended) = (l.training_started_at.as_deref().unwrap(), l.training_ended_at.as_deref().unwrap());
    assert!(line("Training input:").ends_with(&format!(", {started} to {ended})")), "{}", line("Training input:"));
    let source = &l.training_input_provenance.source_type;
    assert!(!source.is_empty());
    assert!(line("Training data:").starts_with(&format!("{:<16}{source}, residency PH, ", "Training data:")), "{}", line("Training data:"));
}

#[test]
fn inspect_reads_both_forms_the_same_way() {
    let s = Scratch::new("inspect-forms");
    let p = vector();
    let json = s.write("record.json", p.to_json().unwrap());
    let cose = s.write("record.vmr", p.to_cose().unwrap());
    let a = vmr(&["record", "inspect", "--record", &json]);
    let b = vmr(&["record", "inspect", "--record", &cose]);
    a.expect_code(0);
    b.expect_code(0);
    assert!(a.stdout.contains("(JSON form, "), "{}", a.transcript());
    assert!(b.stdout.contains("(COSE_Sign1 form, "), "{}", b.transcript());
    // Everything but the file line is the same record.
    let body = |r: &Run| r.stdout.lines().filter(|l| !l.trim_start().starts_with("File:")).collect::<Vec<_>>().join("\n");
    assert_eq!(body(&a), body(&b));
}

#[test]
fn a_forged_record_inspects_like_any_other_because_inspect_checks_nothing() {
    let s = Scratch::new("inspect-forged");
    let mut p = vector();
    reissue_with(&mut p, KEY_FORGER);
    let file = s.write("forged.json", p.to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &file]);
    run.expect_code(0);
    assert_eq!(headline(&run), BANNER, "{}", run.transcript());
    assert!(run.stdout.contains("did:web:factory-operator.ph"), "{}", run.transcript());
}

#[test]
fn the_documentation_members_are_shown_only_when_declared_and_never_as_checked() {
    // Task 10.11a (D11-3): inspect shows the two optional documentation
    // members only when the record carries them, labelled as declared and
    // not checked, and escaped like every claim. Inspect applies no value
    // rule, so a member can hold anything.
    let s = Scratch::new("inspect-documentation");
    let plain = s.write("plain.json", vector().to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &plain]);
    run.expect_code(0);
    for label in ["Governance doc:", "Oversight doc:"] {
        assert!(!run.stdout.contains(label), "{label} shown for a record without the member:\n{}", run.transcript());
    }

    let mut p = vector();
    let hash = vmr_record::hash::format_hash(&vmr_record::hash::sha256(b"inspect: a data governance document"));
    p.data_governance = Some(vmr_record::record::DocumentationRef { documentation_hash: hash.clone() });
    p.human_oversight = Some(vmr_record::record::DocumentationRef { documentation_hash: "\u{1b}[2J\u{202e}".into() });
    sign_as(&mut p, KEY_A);
    let file = s.write("documented.json", p.to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &file]);
    run.expect_code(0);
    let find = |label: &str| {
        run.stdout
            .lines()
            .find(|l| l.trim_start().starts_with(label))
            .unwrap_or_else(|| panic!("no {label} line:\n{}", run.transcript()))
            .to_string()
    };
    let governance = find("Governance doc:");
    assert!(governance.contains(&hash), "{governance}");
    assert!(governance.contains("data governance documentation, by hash: declared, not checked"), "{governance}");
    let oversight = find("Oversight doc:");
    assert!(oversight.contains("\\u{001b}"), "{oversight}");
    assert!(oversight.contains("human oversight documentation, by hash: declared, not checked"), "{oversight}");
    for bad in ['\u{1b}', '\u{202e}'] {
        assert!(!run.stdout.contains(bad), "raw {bad:?} reached stdout:\n{}", run.transcript());
    }
}

#[test]
fn statement_references_are_shown_only_when_declared_and_never_as_checked() {
    // Task 10.11e (D11e-6): inspect shows a record's references to other
    // signed statements only when it carries them, each labelled as declared
    // and not checked, and escaped like every claim. Inspect applies no value
    // rule, so an entry can hold anything.
    use vmr_record::record::StatementReference;
    let s = Scratch::new("inspect-statement-references");
    let plain = s.write("plain.json", general_vector().to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &plain]);
    run.expect_code(0);
    assert!(!run.stdout.contains("Statement ref:"), "shown for a record without references:\n{}", run.transcript());

    let mut p = general_vector();
    let digest = vmr_record::hash::format_hash(&vmr_record::hash::sha256(b"inspect: an in-toto statement"));
    p.model_identity.statement_references = Some(vec![
        StatementReference { format: "oms-v1".into(), digest: digest.clone() },
        StatementReference { format: "\u{1b}[2J\u{202e}".into(), digest: "x".into() },
    ]);
    sign_as(&mut p, KEY_A);
    let file = s.write("referenced.json", p.to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &file]);
    run.expect_code(0);
    let lines: Vec<&str> = run.stdout.lines().filter(|l| l.contains("a signed statement about the model")).collect();
    assert_eq!(lines.len(), 2, "{}", run.transcript());
    assert!(lines[0].trim_start().starts_with("Statement ref:"), "{}", lines[0]);
    assert!(lines[0].contains("oms-v1") && lines[0].contains(&digest), "{}", lines[0]);
    for line in &lines {
        assert!(line.contains("by digest: declared, not checked"), "{line}");
    }
    assert!(lines[1].contains("\\u{001b}"), "{}", lines[1]);
    for bad in ['\u{1b}', '\u{202e}'] {
        assert!(!run.stdout.contains(bad), "raw {bad:?} reached stdout:\n{}", run.transcript());
    }
}

#[test]
fn control_characters_in_claims_are_escaped() {
    let s = Scratch::new("inspect-escapes");
    let mut p = vector();
    p.issuer.issuer_name = "Evil\u{1b}[2J\u{202e}".into();
    p.learning_provenance.training_input_provenance.source_description = "line\rbreak\u{9b}31m".into();
    sign_as(&mut p, KEY_A);
    let file = s.write("evil.json", p.to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &file]);
    run.expect_code(0);
    for bad in ['\u{1b}', '\r', '\u{202e}', '\u{9b}'] {
        assert!(!run.stdout.contains(bad), "raw {bad:?} reached stdout:\n{}", run.transcript());
    }
    assert!(run.stdout.contains("\\u{001b}"), "{}", run.transcript());
}

#[test]
fn a_one_mib_record_inspects_to_a_short_listing() {
    // QA P5-05: `inspect` printed every claim whole - 1 MB for a 1 MB name.
    // Each value is cut to 200 characters, escaped after the cut, and marked
    // with its length; a list longer than the three state components a v0.1
    // record has is shown in part, with the count of the rest.
    let s = Scratch::new("inspect-huge-claims");
    let mut p = vector();
    p.issuer.issuer_name = "x".repeat(1_000_000);
    let file = s.write("big.json", p.to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &file]);
    run.expect_code(0);
    assert!(run.stdout.len() < 8 * 1024, "{} bytes on stdout", run.stdout.len());
    let issuer = run.stdout.lines().find(|l| l.trim_start().starts_with("Issuer:")).unwrap();
    assert!(issuer.contains(&format!("(\"{}…[1000000 characters in all]\")", "x".repeat(200))), "{issuer}");
    // An escape is never cut in half: the cut counts characters, then
    // escapes them.
    let mut p = vector();
    p.learning_provenance.training_input_provenance.source_description = "\u{1b}".repeat(5000);
    let file = s.write("escapes.json", p.to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &file]);
    run.expect_code(0);
    let line = run.stdout.lines().find(|l| l.trim_start().starts_with("Training data:")).unwrap();
    assert!(line.contains(&format!("\"{}…[5000 characters in all]\"", "\\u{001b}".repeat(200))), "{line}");
    // Thousands of state components: a few lines and a count.
    let mut p = vector();
    let one = p.model_identity.learned_state_components[0].clone();
    p.model_identity.learned_state_components = vec![one; 5000];
    let file = s.write("components.json", p.to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &file]);
    run.expect_code(0);
    assert!(run.stdout.len() < 8 * 1024, "{} bytes on stdout", run.stdout.len());
    assert!(run.stdout.contains("(4992 more components, not shown)"), "{}", run.transcript());
}

#[test]
fn a_record_saved_with_a_byte_order_mark_is_refused_saying_so() {
    // QA P5-07, for the JSON form: a byte order mark is named (the verifier
    // names it too, at input.form) and so is how to save without it.
    let s = Scratch::new("inspect-bom");
    let file = s.write("bom.json", [&[0xef, 0xbb, 0xbf][..], vector().to_json().unwrap().as_bytes()].concat());
    let run = vmr(&["record", "inspect", "--record", &file]);
    run.expect_code(1);
    assert!(run.stderr.contains("not a v0.1 record: the file starts with a UTF-8 byte order mark (EF BB BF)"), "{}", run.transcript());
    assert!(run.stderr.contains("save it as UTF-8 without a byte order mark"), "{}", run.transcript());
}

#[test]
fn a_file_that_is_not_a_record_is_an_input_error_with_exit_1() {
    let s = Scratch::new("inspect-malformed");
    let json = vector().to_json().unwrap().into_bytes();
    let cose = vector().to_cose().unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("garbage", b"\xff\xfe garbage".to_vec()),
        ("brace", b"{".to_vec()),
        ("empty-object", b"{}".to_vec()),
        ("json-cut", json[..json.len() / 2].to_vec()),
        ("cose-cut", cose[..cose.len() / 2].to_vec()),
        ("tagged-cose", [&[0xd2][..], &cose].concat()),
        ("cose-trailing", [&cose[..], &[0x00]].concat()),
        ("unknown-member", json.iter().copied().take(1).chain(*b"\"extra\":1,").chain(json.iter().copied().skip(1)).collect()),
        ("oversized", [&json[..], &vec![b' '; 1024 * 1024]].concat()),
    ];
    for (name, bytes) in cases {
        let file = s.write(name, &bytes);
        let run = vmr(&["record", "inspect", "--record", &file]);
        run.expect_code(1);
        assert!(run.stdout.is_empty(), "{name}:\n{}", run.transcript());
        assert!(run.stderr.starts_with("vmr: error: "), "{name}:\n{}", run.transcript());
        assert!(run.stderr.contains("not a v0.1 record"), "{name}:\n{}", run.transcript());
    }
    let run = vmr(&["record", "inspect", "--record", &s.arg("missing.vmr")]);
    run.expect_code(1);
    assert!(run.stderr.contains("cannot read record"), "{}", run.transcript());
}

#[test]
fn paths_are_shown_as_given_with_only_unsafe_characters_escaped() {
    // A path is the operator's own argument: its backslashes are shown as
    // typed ('C:\Users\...', not 'C:\\Users\\...'), and only what a
    // terminal would act on or hide is escaped.
    let s = Scratch::new("inspect-paths");
    let file = s.write("record.json", vector().to_json().unwrap());
    let run = vmr(&["record", "inspect", "--record", &file]);
    run.expect_code(0);
    let line = run.stdout.lines().find(|l| l.trim_start().starts_with("File:")).unwrap();
    assert!(line.contains(&format!("'{file}' (JSON form, ")), "{line}");

    let windows = r"C:\no-such-dir\vmr-demo\model.vmr";
    let run = vmr(&["record", "inspect", "--record", windows]);
    run.expect_code(1);
    assert!(run.stderr.contains(&format!("cannot read record '{windows}'")), "{}", run.transcript());

    let hostile = s.arg("no-such-\u{1b}[2J-\u{202e}lmt.json");
    let run = vmr(&["record", "inspect", "--record", &hostile]);
    run.expect_code(1);
    let escaped = hostile.replace('\u{1b}', "\\u{001b}").replace('\u{202e}', "\\u{202e}");
    assert!(run.stderr.contains(&format!("'{escaped}'")), "{}", run.transcript());
    assert!(!run.stderr.contains('\u{1b}') && !run.stderr.contains('\u{202e}'), "{}", run.transcript());
}
