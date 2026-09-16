// tests/cli_model_hash.rs — task 10.13a, commits B6/B7
// (docs/dev/task-10.13a.md §3.1, §12): `vmr model hash`, which shows the
// issuer every name, size and hash a record would carry before anything is
// signed (spec §7.2's SHOULD), and gives a base model's `model_hash` for
// `derived_from`. Every expected digest is computed here from the names and
// bytes written.

mod common;
use common::*;
use serde_json::Value;
use vmr_record::hash::{format_hash, sha256};
use vmr_record::named_set::named_set_digest;

fn folder(s: &Scratch) -> (std::path::PathBuf, Vec<(&'static str, Vec<u8>)>) {
    let root = s.subdir("model");
    let files = vec![
        ("config.json", b"{}".to_vec()),
        ("weights/model.safetensors", vec![7u8; 3000]),
        ("\u{6a21}\u{578b}.bin", b"non-ascii name".to_vec()),
        (".gitattributes", b"*.bin filter=lfs\n".to_vec()),
    ];
    for (name, bytes) in &files {
        let path = name.split('/').fold(root.clone(), |p, part| p.join(part));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    (root, files)
}

fn expected(files: &[(&str, Vec<u8>)]) -> String {
    let mut members: Vec<(&str, [u8; 32])> = files.iter().map(|(n, b)| (*n, sha256(b))).collect();
    members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    format_hash(&named_set_digest(&members).unwrap())
}

#[test]
fn model_hash_prints_the_named_set_digest_and_every_name_size_and_hash() {
    let s = Scratch::new("model-hash-text");
    let (root, files) = folder(&s);
    let run = vmr(&["model", "hash", "--model", &root.to_string_lossy()]);
    run.expect_code(0);
    let total: usize = files.iter().map(|(_, b)| b.len()).sum();
    let first = run.stdout.lines().next().unwrap_or("");
    assert!(first.starts_with(&format!("Model hash: {} (4 files read, {total} bytes, from '", expected(&files))), "{}", run.transcript());
    let mut sorted = files.clone();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let lines: Vec<&str> = run.stdout.lines().skip(1).collect();
    let want: Vec<String> = sorted.iter().map(|(n, b)| format!("  {}  {}  {n}", hex_of(&sha256(b)), b.len())).collect();
    assert_eq!(lines, want, "every name, in the order hashed, hidden files included");
}

#[test]
fn model_hash_json_is_the_digest_and_the_files_as_components() {
    let s = Scratch::new("model-hash-json");
    let (root, files) = folder(&s);
    let run = vmr(&["model", "hash", "--model", &root.to_string_lossy(), "--json"]);
    run.expect_code(0);
    let v: Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(v["model_hash"], expected(&files).as_str());
    let listed = v["files"].as_array().unwrap();
    assert_eq!(listed.len(), 4);
    for entry in listed {
        let name = entry["name"].as_str().unwrap();
        let bytes = &files.iter().find(|(n, _)| *n == name).unwrap().1;
        assert_eq!(entry["hash"], format_hash(&sha256(bytes)).as_str(), "{name}");
        assert_eq!(entry["size_bytes"], bytes.len(), "{name}");
        assert_eq!(entry.as_object().unwrap().len(), 3, "exactly name, hash, size_bytes");
    }
    // One file: its own name.
    let one = root.join("weights").join("model.safetensors");
    let run = vmr(&["model", "hash", "--model", &one.to_string_lossy(), "--json"]);
    run.expect_code(0);
    let v: Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(v["files"][0]["name"], "model.safetensors");
    assert_eq!(v["model_hash"], expected(&[("model.safetensors", vec![7u8; 3000])]).as_str());
}

#[test]
fn model_hash_refuses_a_missing_path_and_an_empty_folder() {
    let s = Scratch::new("model-hash-refusals");
    let run = vmr(&["model", "hash", "--model", &s.arg("no-such-model")]);
    run.expect_code(1);
    assert!(run.stderr.contains("cannot be read"), "{}", run.transcript());
    let empty = s.subdir("empty");
    let run = vmr(&["model", "hash", "--model", &empty.to_string_lossy()]);
    run.expect_code(1);
    assert!(run.stderr.contains("holds no regular file"), "{}", run.transcript());
    assert!(run.stdout.is_empty(), "{}", run.transcript());
}

#[cfg(unix)]
#[test]
fn model_hash_refuses_a_folder_that_holds_a_link_to_a_directory() {
    let s = Scratch::new("model-hash-link");
    let (root, _) = folder(&s);
    std::os::unix::fs::symlink(s.subdir("elsewhere"), root.join("linked-dir")).unwrap();
    let run = vmr(&["model", "hash", "--model", &root.to_string_lossy()]);
    run.expect_code(1);
    assert!(run.stderr.contains("resolves to a directory"), "{}", run.transcript());
}

/// Spec §7.2's example of a model of one file: `weights.bin`, four zero bytes.
const ONE_FILE_EXAMPLE: &str = "sha256:c32b0039edc7ed971446e62f8701b5a835f9c15b3fbac208f318e2626b9650ea";

#[test]
fn model_hash_names_a_file_given_by_another_spelling_as_its_folder_stores_it() {
    // QA QM-01: WEIGHTS.BIN given, weights.bin stored, on a case-insensitive
    // file system: the name and model_hash Linux gives the stored name.
    let s = Scratch::new("model-hash-typed-spelling");
    let root = s.subdir("m");
    std::fs::write(root.join("weights.bin"), [0u8; 4]).unwrap();
    let typed = root.join("WEIGHTS.BIN");
    if !typed.exists() {
        eprintln!("not run: this folder is case-sensitive, so WEIGHTS.BIN does not open weights.bin");
        return;
    }
    let run = vmr(&["model", "hash", "--model", &typed.to_string_lossy(), "--json"]);
    run.expect_code(0);
    let v: Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(v["files"][0]["name"], "weights.bin", "{}", run.transcript());
    assert_eq!(v["model_hash"], ONE_FILE_EXAMPLE, "{}", run.transcript());
}

#[test]
fn model_hash_json_escapes_what_a_terminal_acts_on_and_parses_to_the_same_names() {
    // QA QM-02: a downloaded model's file names are text its issuer did not
    // choose. `--json` escapes what a terminal acts on or hides, as
    // `record verify --json` does, and still parses to the stored names.
    let s = Scratch::new("model-hash-unsafe-names");
    let root = s.subdir("m");
    let unsafe_chars = ['\u{202e}', '\u{200b}', '\u{feff}', '\u{2028}', '\u{85}', '\u{7f}'];
    let names: Vec<String> = unsafe_chars.iter().map(|c| format!("name-{:04x}-{c}.bin", u32::from(*c))).collect();
    for name in &names {
        std::fs::write(root.join(name), name.as_bytes()).unwrap();
    }
    let run = vmr(&["model", "hash", "--model", &root.to_string_lossy(), "--json"]);
    run.expect_code(0);
    for c in unsafe_chars {
        assert!(!run.stdout.contains(c), "U+{:04X} reached standard output raw: {}", u32::from(c), run.stdout.escape_debug());
    }
    let v: Value = serde_json::from_str(&run.stdout).unwrap();
    let mut listed: Vec<String> =
        v["files"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap().to_string()).collect();
    let mut want = names.clone();
    listed.sort();
    want.sort();
    assert_eq!(listed, want, "the JSON parses to the names the folder stores");
}

#[test]
fn model_hash_help_names_what_it_shows_and_signs_nothing() {
    let run = vmr(&["model", "hash", "--help"]);
    run.expect_code(0);
    for text in ["--model", "--json", "signs nothing"] {
        assert!(run.stdout.contains(text), "{text} missing:\n{}", run.transcript());
    }
}

/// Lower-case hex of `bytes` (the listing's form).
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
