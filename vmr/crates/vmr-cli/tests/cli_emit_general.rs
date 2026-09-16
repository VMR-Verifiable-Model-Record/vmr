// tests/cli_emit_general.rs — task 10.13a, commits B6/B7
// (docs/dev/task-10.13a.md §3, §12): `vmr record emit` for any AI model,
// from any vendor, whose weights the issuer holds, given as a folder or one
// file, in every build of vmr, with no engine.
//
// Every model folder is made here; every expected digest is computed here
// from the names and bytes written, with the format crate's named-set digest.
// The record is then verified by `vmr record verify` against a store that
// trusts the test key.

mod common;
use common::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use vmr_record::hash::{format_hash, sha256};
use vmr_record::named_set::named_set_digest;
use vmr_record::Record;

const KEY_LABEL: &str = "khalm-vmr vmr-cli general emit test key (test-only)";
const ISSUER: &str = "did:web:example.org";
const ISSUED: &str = "2026-09-14T00:00:00Z";

/// The files of the test model: (name, bytes).
fn model_files() -> Vec<(String, Vec<u8>)> {
    [
        ("config.json", b"{\"architectures\":[\"Example\"]}\n".to_vec()),
        ("model-00001-of-00002.safetensors", vec![1u8; 4096]),
        ("model-00002-of-00002.safetensors", vec![2u8; 1024]),
        ("tokenizer.json", b"{\"version\":\"1.0\"}\n".to_vec()),
        ("sub/nested.bin", b"nested file\n".to_vec()),
    ]
    .into_iter()
    .map(|(n, b)| (n.to_string(), b))
    .collect()
}

fn write_folder(root: &Path, files: &[(String, Vec<u8>)]) {
    for (name, bytes) in files {
        let path = name.split('/').fold(root.to_path_buf(), |p, s| p.join(s));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
}

fn digest_of(files: &[(String, Vec<u8>)]) -> String {
    let mut members: Vec<(&str, [u8; 32])> = files.iter().map(|(n, b)| (n.as_str(), sha256(b))).collect();
    members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    format_hash(&named_set_digest(&members).unwrap())
}

/// A general manifest: not-held training, no deployment, no evaluation.
fn manifest() -> Value {
    json!({
        "manifest_version": "0.1",
        "issuer": { "issuer_id": ISSUER, "issuer_name": "Example issuer", "attestation_level": "software" },
        "model_format": "safetensors",
        "model": {
            "architecture": { "type": "transformer", "topology": "decoder-only", "precision": "bfloat16" },
            "parameter_count": 1280
        },
        "training": {
            "environment": { "hardware_id": "", "tee_measurement": "", "software_hash": "", "training_software": "" },
            "input_provenance": { "source_type": "", "source_description": "" },
            "input_disclosure": "not-held"
        },
        "policy_compliance": {
            "policy_pack_id": "example-policy-pack-v1",
            "evaluated_at": ISSUED,
            "results": [],
            "overall_status": "indeterminate"
        },
        "lineage": { "lineage_type": "initial" }
    })
}

struct Setup {
    s: Scratch,
    model: PathBuf,
    key: String,
}

fn setup(label: &str) -> Setup {
    let s = Scratch::new(label);
    let model = s.subdir("model");
    write_folder(&model, &model_files());
    let key = write_test_key(&s, "issuer.pem", KEY_LABEL);
    Setup { s, model, key }
}

impl Setup {
    fn manifest_file(&self, name: &str, m: &Value) -> String {
        self.s.write(name, serde_json::to_vec_pretty(m).unwrap())
    }

    /// `record emit --model <model>` with the given manifest and extra args.
    fn emit(&self, model: &Path, manifest: &Value, output: &str, extra: &[&str]) -> Run {
        let m = self.manifest_file("manifest.json", manifest);
        let model = model.to_string_lossy().into_owned();
        let out = self.s.arg(output);
        let mut args = vec![
            "record", "emit", "--model", &model, "--manifest", &m, "--key", &self.key, "--output", &out,
            "--issued-at", ISSUED,
        ];
        args.extend_from_slice(extra);
        vmr(&args)
    }

    fn record(&self, output: &str) -> Record {
        Record::from_json(&std::fs::read_to_string(self.s.path(output)).unwrap()).unwrap()
    }

    /// A trust store trusting the test key for ISSUER.
    fn store(&self) -> String {
        let public = self.s.arg("issuer.pub.json");
        vmr(&["key", "export", "--key", &self.key, "--output", &public]).expect_code(0);
        let store = self.s.arg("trust-store.json");
        vmr(&[
            "trust-store", "add", "--trust-store", &store, "--public-key", &public, "--issuer-id", ISSUER,
            "--issuer-name", "Example issuer", "--attestation-level", "software", "--valid-from", "2026-09-01T00:00:00Z",
        ])
        .expect_code(0);
        store
    }
}

#[test]
fn emit_a_model_folder_writes_a_record_that_verifies() {
    let st = setup("general-emit");
    let run = st.emit(&st.model, &manifest(), "record.json", &["--format", "json"]);
    run.expect_code(0);
    let files = model_files();
    let model_hash = digest_of(&files);
    assert!(run.stdout.starts_with("Emitted record: urn:uuid:"), "{}", run.transcript());
    assert!(run.stdout.contains(&format!("  Model hash:            {model_hash} (5 files read, ")), "{}", run.transcript());
    assert!(run.stdout.contains("  Components:            every file of the model (5)"), "{}", run.transcript());
    assert!(run.stdout.contains("  Training records:      none committed: not held by the issuer"), "{}", run.transcript());
    assert!(run.stdout.contains("declared in the manifest, not evaluated"), "{}", run.transcript());
    // Every name hashed is shown, with its hash and size (spec §7.2's SHOULD).
    assert!(run.stdout.contains("Files hashed:"), "{}", run.transcript());
    for (name, bytes) in &files {
        let line = format!("  {}  {}  {name}", hex_of(&sha256(bytes)), bytes.len());
        assert!(run.stdout.contains(&line), "missing {line:?}:\n{}", run.transcript());
    }

    let p = st.record("record.json");
    let m = &p.model_identity;
    assert_eq!((m.model_hash.as_str(), m.learned_state_hash.as_str(), m.model_format.as_str()), (model_hash.as_str(), model_hash.as_str(), "safetensors"));
    let names: Vec<&str> = m.learned_state_components.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["config.json", "model-00001-of-00002.safetensors", "model-00002-of-00002.safetensors", "sub/nested.bin", "tokenizer.json"]);
    assert_eq!(m.parameter_count, Some(1280));
    assert_eq!(p.learning_provenance.training_input_disclosure.as_deref(), Some("not-held"));
    assert!(p.deployment_context.is_none());

    let store = st.store();
    let run = vmr(&["record", "verify", "--record", &st.s.arg("record.json"), "--trust-store", &store, "--at", "2026-09-15T00:00:00Z"]);
    run.expect_code(0);
    assert!(headline(&run).starts_with("✓ Record valid"), "{}", run.transcript());
    // Inspect reads it in the general description's own words.
    let run = vmr(&["record", "inspect", "--record", &st.s.arg("record.json")]);
    run.expect_code(0);
    assert!(run.stdout.contains(&model_hash), "{}", run.transcript());
}

#[test]
fn a_model_given_as_one_file_is_named_by_its_own_name() {
    let st = setup("general-one-file");
    let file = st.model.join("sub").join("nested.bin");
    st.emit(&file, &manifest(), "one.json", &["--format", "json"]).expect_code(0);
    let p = st.record("one.json");
    let names: Vec<&str> = p.model_identity.learned_state_components.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["nested.bin"]);
    assert_eq!(p.model_identity.model_hash, digest_of(&[("nested.bin".to_string(), b"nested file\n".to_vec())]));
}

#[test]
fn a_model_given_by_another_spelling_gets_the_record_of_its_stored_name() {
    // QA QM-01: one file, one record, however its path is spelled on a
    // case-insensitive file system.
    let st = setup("general-typed-spelling");
    let one = st.s.subdir("one");
    std::fs::write(one.join("weights.bin"), [0u8; 4]).unwrap();
    let typed = one.join("WEIGHTS.BIN");
    if !typed.exists() {
        eprintln!("not run: this folder is case-sensitive, so WEIGHTS.BIN does not open weights.bin");
        return;
    }
    st.emit(&one.join("weights.bin"), &manifest(), "stored.json", &["--format", "json"]).expect_code(0);
    let run = st.emit(&typed, &manifest(), "typed.json", &["--format", "json"]);
    run.expect_code(0);
    let p = st.record("typed.json");
    let names: Vec<&str> = p.model_identity.learned_state_components.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["weights.bin"], "{}", run.transcript());
    assert_eq!(
        std::fs::read(st.s.path("typed.json")).unwrap(),
        std::fs::read(st.s.path("stored.json")).unwrap(),
        "the record of the stored name, byte for byte"
    );
}

#[cfg(unix)]
#[test]
fn a_component_refusal_quotes_the_name_escaped_once() {
    // QA QM-06: a `\` in a component name shows as `\\`, escaped once, as the
    // CLI escapes every name; never as four.
    let st = setup("general-component-escape");
    let run = st.emit(&st.model, &manifest(), "refused.json", &["--component", "sub\\a.bin"]);
    run.expect_code(1);
    assert!(run.stderr.contains("component \"sub\\\\a.bin\" is not a file of the model"), "{}", run.transcript());
    assert!(!st.s.path("refused.json").exists(), "nothing written");
}

#[test]
fn a_future_issued_at_is_refused_and_the_message_names_a_record() {
    // QA QM-08: the general path's future-time refusal says "record".
    let st = setup("general-future");
    let m = st.manifest_file("m.json", &manifest());
    let model = st.model.to_string_lossy().into_owned();
    let out = st.s.arg("future.vmr");
    let run = vmr(&[
        "record", "emit", "--model", &model, "--manifest", &m, "--key", &st.key, "--output", &out, "--issued-at",
        "2099-01-01T00:00:00Z",
    ]);
    run.expect_code(1);
    assert!(run.stderr.contains("a verifier checking the record now would reject it (time.not_future)"), "{}", run.transcript());
    assert!(!st.s.path("future.vmr").exists(), "nothing written");
}

#[test]
fn emission_is_byte_reproducible_across_processes() {
    let st = setup("general-reproducible");
    st.emit(&st.model, &manifest(), "a.vmr", &[]).expect_code(0);
    st.emit(&st.model, &manifest(), "b.vmr", &[]).expect_code(0);
    let a = std::fs::read(st.s.path("a.vmr")).unwrap();
    assert_eq!(a, std::fs::read(st.s.path("b.vmr")).unwrap(), "same folder, same issuer inputs, same bytes");
    assert_eq!(a.first(), Some(&0x84), "COSE by default");
    // One changed issuer input: another record.
    let mut other = manifest();
    other["issuer"]["issuer_name"] = json!("Another name");
    st.emit(&st.model, &other, "c.vmr", &[]).expect_code(0);
    assert_ne!(a, std::fs::read(st.s.path("c.vmr")).unwrap());
}

#[test]
fn components_name_the_learned_state_and_model_hash_still_covers_every_file() {
    let st = setup("general-components");
    let run = st.emit(
        &st.model,
        &manifest(),
        "weights.json",
        &["--format", "json", "--component", "model-00002-of-00002.safetensors", "--component", "model-00001-of-00002.safetensors"],
    );
    run.expect_code(0);
    assert!(run.stdout.contains("  Components:            2 of 5 files (--component)"), "{}", run.transcript());
    let p = st.record("weights.json");
    assert_eq!(p.model_identity.model_hash, digest_of(&model_files()));
    let weights: Vec<(String, Vec<u8>)> = model_files().into_iter().filter(|(n, _)| n.ends_with(".safetensors")).collect();
    assert_eq!(p.model_identity.learned_state_hash, digest_of(&weights));

    for (component, expect) in [("missing.bin", "is not a file of the model"), ("sub\\..\\x", "")] {
        if component.contains('\\') && !cfg!(windows) {
            continue;
        }
        let run = st.emit(&st.model, &manifest(), "refused.json", &["--component", component]);
        run.expect_code(1);
        assert!(run.stderr.contains(expect), "{component}: {}", run.transcript());
        assert!(!st.s.path("refused.json").exists(), "nothing written");
    }
}

#[test]
fn training_records_are_committed_as_a_named_set_or_refused_when_given_twice_or_not_at_all() {
    let st = setup("general-records");
    let records = st.s.subdir("records");
    let data: Vec<(String, Vec<u8>)> = (0..3).map(|i| (format!("shard-{i}.jsonl"), format!("record {i}\n").into_bytes())).collect();
    write_folder(&records, &data);
    let mut m = manifest();
    m["training"].as_object_mut().unwrap().remove("input_disclosure");
    let run = st.emit(&st.model, &m, "trained.json", &["--format", "json", "--training-records", &records.to_string_lossy()]);
    run.expect_code(0);
    let p = st.record("trained.json");
    let l = &p.learning_provenance;
    assert_eq!(l.training_input_format.as_deref(), Some("named-set-v1"));
    assert_eq!(l.training_input_count, 3);
    assert_eq!(l.training_input_digest, digest_of(&data));
    assert!(run.stdout.contains("  Training records:      named-set-v1, 3 records, digest "), "{}", run.transcript());

    // Records and a disclosure together, or neither: refused before signing.
    let both = st.emit(&st.model, &manifest(), "both.json", &["--training-records", &records.to_string_lossy()]);
    both.expect_code(1);
    assert!(both.stderr.contains("--training-records") && both.stderr.contains("input_disclosure"), "{}", both.transcript());
    let neither = st.emit(&st.model, &m, "neither.json", &[]);
    neither.expect_code(1);
    assert!(neither.stderr.contains("--training-records") && neither.stderr.contains("input_disclosure"), "{}", neither.transcript());
    assert!(!st.s.path("both.json").exists() && !st.s.path("neither.json").exists());
}

#[test]
fn a_manifest_that_is_not_one_of_a_models_files_is_refused_before_any_file_is_read() {
    let st = setup("general-manifest-refusals");
    let mut profile = manifest();
    profile["model_format"] = json!("snn-compact-v1");
    let mut no_format = manifest();
    no_format.as_object_mut().unwrap().remove("model_format");
    let mut no_model = manifest();
    no_model.as_object_mut().unwrap().remove("model");
    for (m, expect) in [(profile, "profile"), (no_format, "model_format"), (no_model, "\"model\"")] {
        let run = st.emit(&st.model, &m, "refused.vmr", &[]);
        run.expect_code(1);
        assert!(run.stderr.contains(expect), "expected {expect:?}:\n{}", run.transcript());
        assert!(!st.s.path("refused.vmr").exists(), "nothing written");
    }
}

#[test]
fn an_unusable_manifests_hint_names_the_example_of_a_models_files() {
    // QA13-08: the hint of the free tool, which makes records of a model's
    // files, names the example manifest for a model's files, never the engine
    // profile's demo manifest, which this tool refuses.
    let st = setup("general-manifest-hint");
    let mut unusable = manifest();
    unusable["manifest_version"] = json!("0.2");
    let run = st.emit(&st.model, &unusable, "refused.vmr", &[]);
    run.expect_code(1);
    assert!(run.stderr.contains("docs/examples/phi-4-mini-instruct/manifest.json"), "{}", run.transcript());
    assert!(!run.stderr.contains("docs/demo/"), "{}", run.transcript());
    assert!(!st.s.path("refused.vmr").exists(), "nothing written");
}

#[test]
fn an_empty_folder_and_an_output_inside_the_model_folder_are_refused() {
    let st = setup("general-folder-refusals");
    let empty = st.s.subdir("empty");
    std::fs::create_dir_all(empty.join("only/dirs")).unwrap();
    let run = st.emit(&empty, &manifest(), "empty.vmr", &[]);
    run.expect_code(1);
    assert!(run.stderr.contains("holds no regular file"), "{}", run.transcript());

    let m = st.manifest_file("m.json", &manifest());
    let inside = st.model.join("record.vmr").to_string_lossy().into_owned();
    let model = st.model.to_string_lossy().into_owned();
    let run = vmr(&["record", "emit", "--model", &model, "--manifest", &m, "--key", &st.key, "--output", &inside, "--issued-at", ISSUED]);
    run.expect_code(1);
    assert!(run.stderr.contains("inside the model folder"), "{}", run.transcript());
    assert!(!st.model.join("record.vmr").exists());
}

#[test]
fn a_record_too_large_for_a_verifier_is_refused_and_components_make_it_fit() {
    // 6,000 files with long names: every file as a component makes a record
    // over the 1 MiB a verifier reads (spec §6.1).
    let st = setup("general-too-large");
    let big = st.s.subdir("big");
    let files: Vec<(String, Vec<u8>)> = (0..6000)
        .map(|i| (format!("layers/layer-{:02}/expert-{i:05}-of-06000-with-a-long-descriptive-name.bin", i % 60), vec![(i % 251) as u8]))
        .collect();
    write_folder(&big, &files);
    let run = st.emit(&big, &manifest(), "big.vmr", &[]);
    run.expect_code(1);
    assert!(run.stderr.contains("1048576") && run.stderr.contains("--component"), "{}", run.transcript());
    assert!(!st.s.path("big.vmr").exists());
    let one = &files[0].0;
    let run = st.emit(&big, &manifest(), "fits.vmr", &["--component", one]);
    run.expect_code(0);
    assert!(run.stdout.contains("1 of 6000 files (--component)"), "{}", run.transcript());
}

#[test]
fn bases_and_statement_references_are_the_manifests_statements_signed_as_stated() {
    let st = setup("general-bases");
    let base = st.s.subdir("base");
    write_folder(&base, &[("model.safetensors".into(), vec![9u8; 2048])]);
    let run = vmr(&["model", "hash", "--model", &base.to_string_lossy(), "--json"]);
    run.expect_code(0);
    let base_hash = serde_json::from_str::<Value>(&run.stdout).unwrap()["model_hash"].as_str().unwrap().to_string();
    let mut m = manifest();
    m["model"]["derived_from"] = json!([{ "model_hash": base_hash, "name": "the base", "relation": "quantization" }]);
    let reference = format!("sha256:{}", "cd".repeat(32));
    m["model"]["statement_references"] = json!([{ "format": "oms-v1", "digest": reference }]);
    let run = st.emit(&st.model, &m, "derived.json", &["--format", "json"]);
    run.expect_code(0);
    assert!(run.stdout.contains(&format!("  Derived from:          quantization of {base_hash} (\"the base\")")), "{}", run.transcript());
    assert!(run.stdout.contains(&format!("  Statement refs:        oms-v1 {reference} (declared, not checked)")), "{}", run.transcript());
    let p = st.record("derived.json");
    assert_eq!(p.model_identity.derived_from.as_ref().unwrap()[0].model_hash, base_hash);
    assert_eq!(p.model_identity.statement_references.as_ref().unwrap()[0].digest, reference);
    // An unregistered format without a dot is what a verifier refuses: refused here.
    m["model"]["statement_references"] = json!([{ "format": "oms-v9", "digest": reference }]);
    st.emit(&st.model, &m, "bad-ref.json", &[]).expect_code(1);
}

#[cfg(unix)]
#[test]
fn the_walks_refusals_are_input_errors_and_nothing_is_written() {
    use std::os::unix::fs::symlink;
    let st = setup("general-walk-refusals");
    let to_dir = st.s.subdir("to-dir");
    write_folder(&to_dir, &[("a.bin".into(), b"a".to_vec())]);
    symlink(st.s.subdir("elsewhere"), to_dir.join("linked")).unwrap();
    let dangling = st.s.subdir("dangling");
    write_folder(&dangling, &[("a.bin".into(), b"a".to_vec())]);
    symlink(st.s.path("nothing-here"), dangling.join("gone.bin")).unwrap();
    for (folder, expect) in [(to_dir, "resolves to a directory"), (dangling, "resolves to nothing")] {
        let run = st.emit(&folder, &manifest(), "refused.vmr", &[]);
        run.expect_code(1);
        assert!(run.stderr.contains(expect), "{expect}: {}", run.transcript());
        assert!(!st.s.path("refused.vmr").exists());
    }
    // A link to a file is hashed under its own name, and the output says so.
    let linked = st.s.subdir("linked-file");
    write_folder(&linked, &[("real.bin".into(), b"r".to_vec())]);
    symlink(linked.join("real.bin"), linked.join("alias.bin")).unwrap();
    let run = st.emit(&linked, &manifest(), "links.json", &["--format", "json"]);
    run.expect_code(0);
    assert!(run.stdout.contains("  Links:                 1 name is a link, hashed as the regular file it resolves to"), "{}", run.transcript());
}

#[cfg(windows)]
#[test]
fn a_directory_junction_in_the_model_folder_is_an_input_error() {
    let st = setup("general-junction");
    let target = st.s.subdir("elsewhere");
    // cmd reads a `/` in a path as a switch, and the scratch root may be
    // spelled with `/` (CARGO_TARGET_TMPDIR): mklink is given `\` only.
    let native = |p: &Path| p.to_string_lossy().replace('/', "\\");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(native(&st.model.join("junction")))
        .arg(native(&target))
        .output()
        .unwrap();
    assert!(
        made.status.success(),
        "mklink /J needs no privilege: {}{}",
        String::from_utf8_lossy(&made.stdout),
        String::from_utf8_lossy(&made.stderr)
    );
    let run = st.emit(&st.model, &manifest(), "refused.vmr", &[]);
    run.expect_code(1);
    assert!(run.stderr.contains("resolves to a directory"), "{}", run.transcript());
}

#[test]
fn emit_help_names_no_engine_input_and_says_what_a_record_is_for() {
    let run = vmr(&["record", "emit", "--help"]);
    run.expect_code(0);
    for text in ["--model", "--component", "--training-records", "--manifest", "--key", "--output", "--issued-at", "--record-id", "--format", "--force", "any AI model, from any vendor, whose weights you hold", "declared"] {
        assert!(run.stdout.contains(text), "{text} missing:\n{}", run.transcript());
    }
    for engine_word in ["--engine", "--profile", "--backend", "KHALM003", "KHALMTRN", "brain"] {
        assert!(!run.stdout.contains(engine_word), "{engine_word} in the non-engine build's help:\n{}", run.transcript());
    }
}

/// Lower-case hex of `bytes` (the listing's form).
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
