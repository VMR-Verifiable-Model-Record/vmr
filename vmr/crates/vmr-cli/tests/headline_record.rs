// tests/headline_record.rs — task 10.13a, commit B12 (docs/dev/task-10.13a.md
// §5.5): the headline example, docs/examples/phi-4-mini-instruct/.
//
// A record of microsoft/Phi-4-mini-instruct @ cfbefac, made by this tool from
// the model's 21 files by an example issuer that held them (did:web:example.org),
// signed with a derived, published test key. Microsoft did not issue it.
//
// In CI, with no model: the record verifies in an isolated process (as Gate 5's
// G5-5); it is the named-set digest of its committed file list; and it states
// only what its issuer can know. (Its recomputation over that list by the
// project's internal tools is an internal check outside the Community tests:
// QA13-04.)
//
// By hand, with the model folder at that commit given as VMR_HEADLINE_MODEL_DIR:
//   write_headline_record writes the committed files, and
//   the_committed_headline_record_is_what_vmr_emits_today re-emits them and
//   compares them byte for byte.
// Both are #[ignore]; run them on Windows and on WSL, and review a regenerated
// record like a vector.

mod common;
use common::*;
use std::path::{Path, PathBuf};
use vmr_record::hash::format_hash;
use vmr_record::named_set::named_set_digest;
use vmr_record::record::JwkPublicKey;
use vmr_record::Record;

const ISSUER: &str = "did:web:example.org";
const NAME: &str = "Example signer: not Microsoft, who did not issue this record";
/// The example's signing key: derived from this published label, so anyone
/// can sign with it. It proves how a record is made, never who made one.
const KEY_LABEL: &str = "khalm-vmr headline example signing key (test-only, published)";
const ISSUED: &str = "2026-09-14T00:00:00Z";
const VALID_FROM: &str = "2026-09-01T00:00:00Z";
const AT: &str = "2026-09-14T12:00:00Z";
const VALID: &str = "✓ Record valid — signed by a key the trust store trusts for this issuer";
const COMMITTED: [&str; 4] = ["files.json", "record.json", "record.vmr", "trust-store.json"];

fn example() -> PathBuf {
    repo().join("docs/examples/phi-4-mini-instruct")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(example().join(name)).unwrap_or_else(|e| panic!("docs/examples/phi-4-mini-instruct/{name}: {e}"))
}

fn record() -> Record {
    Record::from_json(std::str::from_utf8(&read("record.json")).unwrap()).unwrap()
}

/// files.json: `{"files": [{"name", "hash", "size_bytes"}]}`, in §7.2's order.
fn file_list() -> Vec<(String, String, u64)> {
    let doc: serde_json::Value = serde_json::from_slice(&read("files.json")).unwrap();
    let object = doc.as_object().unwrap();
    assert_eq!(object.keys().collect::<Vec<_>>(), ["files"], "files.json holds only its file list");
    doc["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            assert_eq!(f.as_object().unwrap().len(), 3, "{f}");
            (f["name"].as_str().unwrap().to_string(), f["hash"].as_str().unwrap().to_string(), f["size_bytes"].as_u64().unwrap())
        })
        .collect()
}

#[test]
fn the_headline_record_verifies_in_an_isolated_process() {
    let s = Scratch::new("headline-verify");
    let dir = s.subdir("verifier");
    for name in ["record.vmr", "record.json", "trust-store.json"] {
        std::fs::write(dir.join(name), read(name)).unwrap();
    }
    assert_eq!(read("record.vmr").first(), Some(&0x84), "record.vmr is the COSE form");
    for form in ["record.vmr", "record.json"] {
        let run = vmr_isolated(
            &dir,
            &[("TZ", "Pacific/Kiritimati")],
            &["record", "verify", "--record", form, "--trust-store", "trust-store.json", "--at", AT],
        );
        run.expect_code(0);
        assert_eq!(headline(&run), VALID, "{form}:\n{}", run.transcript());
        assert!(run.stdout.contains(&format!("  Issuer:        {ISSUER} ({NAME}, per trust store)")), "{}", run.transcript());
    }
    // Both forms are one record.
    assert_eq!(Record::from_cose(&read("record.vmr")).unwrap(), record());
    let mut names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, ["record.json", "record.vmr", "trust-store.json"], "verify wrote nothing");
}

#[test]
fn the_headline_record_is_the_digest_of_its_file_list() {
    let files = file_list();
    let p = record();
    let m = &p.model_identity;
    assert_eq!(files.len(), 21, "the whole repository at cfbefac");
    let mut sorted = files.clone();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    assert_eq!(files, sorted, "files.json is in spec §7.2's order");
    let members: Vec<(&str, [u8; 32])> = files
        .iter()
        .map(|(n, h, _)| (n.as_str(), hex_decode(h.strip_prefix("sha256:").unwrap()).try_into().unwrap()))
        .collect();
    let digest = format_hash(&named_set_digest(&members).unwrap());
    assert_eq!(m.model_hash, digest, "model_hash is the named-set digest of every file");
    assert_eq!(m.learned_state_hash, digest, "every file is a component");
    let components: Vec<(String, String, u64)> =
        m.learned_state_components.iter().map(|c| (c.name.clone(), c.hash.clone(), c.size_bytes)).collect();
    assert_eq!(components, files, "the components are the file list");
    let shard = files.iter().find(|f| f.0 == "model-00001-of-00002.safetensors").unwrap();
    assert!(shard.2 > 4 << 30, "one shard is over 4 GiB: {}", shard.2);
}

#[test]
fn the_headline_record_states_only_what_its_issuer_can_know() {
    let p = record();
    assert_eq!((p.issuer.issuer_id.as_str(), p.issuer.issuer_name.as_str(), p.issuer.attestation_level.as_str()), (ISSUER, NAME, "self"));
    assert!(p.issuer.issuer_name.contains("not Microsoft"), "the signer says plainly the maker did not issue it");
    // Signed with the published test key.
    let jwk = JwkPublicKey::from_verifying_key(key(KEY_LABEL).verifying_key());
    assert_eq!((&p.issuer.public_key, p.issuer.key_id.as_str()), (&jwk, jwk.key_id().as_str()));
    assert_eq!(p.issued_at, ISSUED);
    let m = &p.model_identity;
    assert_eq!(m.model_format, "safetensors");
    let manifest: serde_json::Value = serde_json::from_slice(&read("manifest.json")).unwrap();
    assert_eq!(m.parameter_count, manifest["model"]["parameter_count"].as_u64(), "the issuer's count, as parameter_count.py gives it");
    assert!(m.derived_from.is_none() && m.statement_references.is_none());
    // The training data is not held by this issuer: nothing committed.
    let l = &p.learning_provenance;
    assert_eq!(l.training_input_disclosure.as_deref(), Some("not-held"));
    assert_eq!((l.training_input_count, l.training_input_digest.as_str(), l.training_input_merkle_root.as_str()), (0, "", ""));
    assert!(l.training_input_format.is_none() && l.training_epochs.is_none() && l.training_started_at.is_none());
    // No deployment, no evaluation, no documents: nothing the issuer cannot know.
    assert!(p.deployment_context.is_none() && p.data_governance.is_none() && p.human_oversight.is_none());
    assert_eq!(p.policy_compliance.overall_status, "indeterminate");
    assert!(p.policy_compliance.results.is_empty());
    assert_eq!(p.lineage.lineage_type, "initial");
}

// ---------------------------------------------------------------------------
//  By hand, with the model folder
// ---------------------------------------------------------------------------

/// The model folder, from VMR_HEADLINE_MODEL_DIR (this project's opt-in
/// switch for tests that need a large input; AGENTS.md).
#[allow(clippy::disallowed_methods)] // the opt-in model folder is these tests' input
fn model_dir() -> Option<String> {
    std::env::var_os("VMR_HEADLINE_MODEL_DIR").map(|d| d.to_string_lossy().into_owned())
}

/// The committed files, made by the CLI into `dir`.
fn produce(model: &str, dir: &Path) {
    let s = Scratch::new("headline-produce");
    let key = write_test_key(&s, "example.pem", KEY_LABEL);
    let public = s.arg("example.pub.json");
    vmr(&["key", "export", "--key", &key, "--output", &public]).expect_code(0);
    let store = dir.join("trust-store.json").to_string_lossy().into_owned();
    vmr(&[
        "trust-store", "add", "--trust-store", &store, "--public-key", &public, "--issuer-id", ISSUER, "--issuer-name", NAME,
        "--attestation-level", "self", "--valid-from", VALID_FROM,
    ])
    .expect_code(0);
    let manifest = example().join("manifest.json").to_string_lossy().into_owned();
    for (name, form) in [("record.vmr", "cose"), ("record.json", "json")] {
        let output = dir.join(name).to_string_lossy().into_owned();
        vmr(&[
            "record", "emit", "--model", model, "--manifest", &manifest, "--key", &key, "--output", &output, "--issued-at", ISSUED,
            "--format", form,
        ])
        .expect_code(0);
    }
    let run = vmr(&["model", "hash", "--model", model, "--json"]);
    run.expect_code(0);
    let listing: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    let files = serde_json::json!({ "files": listing["files"] });
    std::fs::write(dir.join("files.json"), serde_json::to_string_pretty(&files).unwrap() + "\n").unwrap();
}

#[test]
#[ignore = "writes docs/examples/phi-4-mini-instruct/; run with VMR_HEADLINE_MODEL_DIR=<microsoft/Phi-4-mini-instruct @ cfbefac>"]
fn write_headline_record() {
    let Some(model) = model_dir() else {
        eprintln!("VMR_HEADLINE_MODEL_DIR is not set: nothing written");
        return;
    };
    for name in COMMITTED {
        let _ = std::fs::remove_file(example().join(name));
    }
    produce(&model, &example());
}

#[test]
#[ignore = "re-emits the headline record from the model; run with VMR_HEADLINE_MODEL_DIR=<microsoft/Phi-4-mini-instruct @ cfbefac>"]
fn the_committed_headline_record_is_what_vmr_emits_today() {
    let Some(model) = model_dir() else {
        eprintln!("not run: VMR_HEADLINE_MODEL_DIR is not set");
        return;
    };
    let s = Scratch::new("headline-reproduce");
    let dir = s.subdir("example");
    produce(&model, &dir);
    for name in COMMITTED {
        assert!(std::fs::read(dir.join(name)).unwrap() == read(name), "{name} differs from what vmr makes today");
    }
}
