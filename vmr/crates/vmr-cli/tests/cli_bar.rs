// tests/cli_bar.rs — the loading bar's wiring (docs/dev/cli-polish.md CP-6;
// QA QPB-01).
//
// A test's standard error is a pipe, where the bar is never drawn. So the
// commands that read a model's files are run in this process with a bar whose
// writer records every text, over a 65 MiB file (the bar shows once 64 MiB are
// read): it must be drawn while the files are read and erased before the
// command returns. And the binary, in a pipe, must draw no bar at all.

mod common;
use common::*;
use std::sync::Mutex;
use vmr_cli::progress::Bar;

static HASH_TEXTS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static EMIT_TEXTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn record_hash(text: &str) {
    HASH_TEXTS.lock().unwrap().push(text.to_string());
}

fn record_emit(text: &str) {
    EMIT_TEXTS.lock().unwrap().push(text.to_string());
}

/// A model folder of one 65 MiB file of zeros, made with `set_len`.
fn big_model(s: &Scratch) -> std::path::PathBuf {
    let root = s.subdir("model");
    std::fs::File::create(root.join("weights.bin")).unwrap().set_len(65 << 20).unwrap();
    root
}

/// The bar was drawn, and the last text erased it.
fn drawn_then_erased(texts: &[String]) {
    let (last, before) = texts.split_last().expect("the bar handed its writer no text");
    assert!(before.iter().any(|t| t.contains('%')), "the bar was never drawn: {texts:?}");
    assert!(last.starts_with('\r') && last.chars().all(|c| c == '\r' || c == ' '), "the last text is not the erase: {texts:?}");
}

#[test]
fn model_hash_draws_the_bar_while_it_reads_and_erases_it_before_it_returns() {
    let s = Scratch::new("bar-model-hash");
    let args = vmr_cli::cli::ModelHashArgs { model: big_model(&s), json: false, full: false };
    let mut bar = Bar::new(Some(record_hash as fn(&str)), false);
    let out = vmr_cli::model_cmd::hash(&args, &mut bar).unwrap();
    drawn_then_erased(&HASH_TEXTS.lock().unwrap());
    assert!(out.stdout.starts_with("Model hash: "), "{}", out.stdout);
}

#[test]
fn emit_draws_the_bar_while_it_reads_the_model_and_erases_it_before_it_returns() {
    let s = Scratch::new("bar-emit");
    let key = write_test_key(&s, "issuer.pem", "khalm-vmr vmr-cli bar test key (test-only)");
    let manifest = serde_json::json!({
        "manifest_version": "0.1",
        "issuer": { "issuer_id": "did:web:example.org", "issuer_name": "Example issuer", "attestation_level": "software" },
        "model_format": "safetensors",
        "model": { "architecture": { "type": "transformer", "topology": "decoder-only", "precision": "bfloat16" } },
        "training": {
            "environment": { "hardware_id": "", "tee_measurement": "", "software_hash": "", "training_software": "" },
            "input_provenance": { "source_type": "", "source_description": "" },
            "input_disclosure": "not-held"
        },
        "policy_compliance": { "policy_pack_id": "example-policy-pack-v1", "evaluated_at": "2026-09-14T00:00:00Z", "results": [], "overall_status": "indeterminate" },
        "lineage": { "lineage_type": "initial" }
    });
    let manifest = s.write("manifest.json", serde_json::to_vec(&manifest).unwrap());
    let args = vmr_cli::cli::EmitArgs {
        model: Some(big_model(&s)),
        component: Vec::new(),
        training_records: None,
        manifest: manifest.into(),
        key: key.into(),
        output: s.path("record.vmr"),
        issued_at: Some(vmr_record::timestamp::Timestamp::parse("2026-09-14T00:00:00Z").unwrap()),
        record_id: None,
        format: vmr_cli::cli::FormatArg::Cose,
        force: false,
        full: false,
    };
    let mut bar = Bar::new(Some(record_emit as fn(&str)), false);
    let out = vmr_cli::emit_cmd::run(&args, &mut bar).unwrap();
    drawn_then_erased(&EMIT_TEXTS.lock().unwrap());
    assert!(out.stdout.starts_with("Emitted record: "), "{}", out.stdout);
}

#[test]
fn a_pipe_gets_no_bar_and_the_plain_text() {
    let s = Scratch::new("bar-pipe");
    let model = big_model(&s).to_string_lossy().into_owned();
    let plain = vmr(&["model", "hash", "--model", &model]);
    plain.expect_code(0);
    assert!(plain.stderr.is_empty(), "{}", plain.transcript());
    assert!(plain.stdout.starts_with("Model hash: ") && plain.stdout.contains("68157440 bytes"), "{}", plain.transcript());
    let rich = vmr(&["model", "hash", "--model", &model, "--color", "always"]);
    rich.expect_code(0);
    assert!(rich.stderr.is_empty(), "{}", rich.transcript());
}
