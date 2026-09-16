// tests/cli_robustness.rs — Law 9 through the binary: every command that
// reads a file, fed deterministic mutants of a valid one, exits with one of
// its documented codes, never panics, and never prints a raw control or
// bidi character (docs/dev/phase5.md C10, C13).
//
// The in-process harness (src/mutate.rs and each module's robustness test)
// runs thousands of mutants through the CLI's own readers and renderers;
// this one runs a few hundred through the whole process — file reading,
// argument handling, exit codes — as a user would meet them.

mod common;
use common::*;

#[test]
fn verify_and_inspect_survive_mutated_records() {
    let s = Scratch::new("robust-records");
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let seeds = [vector().to_json().unwrap().into_bytes(), vector().to_cose().unwrap()];
    let mut rng = Lcg(0x5EED_6001);
    for (n, seed) in seeds.iter().enumerate() {
        for i in 0..40 {
            let file = s.write(&format!("p{n}-{i}"), rng.mutant(seed));
            let verify = vmr(&["record", "verify", "--record", &file, "--trust-store", &store, "--at", T]);
            assert!(matches!(verify.code, 0 | 3), "verify exit code:\n{}", verify.transcript());
            verify.expect_code(verify.code);
            assert_terminal_safe(&verify, "verify");
            let inspect = vmr(&["record", "inspect", "--record", &file]);
            assert!(matches!(inspect.code, 0 | 1), "inspect exit code:\n{}", inspect.transcript());
            inspect.expect_code(inspect.code);
            assert_terminal_safe(&inspect, "inspect");
        }
    }
}

#[test]
fn verify_survives_mutated_trust_stores() {
    let s = Scratch::new("robust-stores");
    let record = s.write("record.json", vector().to_json().unwrap());
    let seed = vector_store("ts-basic");
    let mut rng = Lcg(0x5EED_6002);
    for i in 0..60 {
        let store = s.write(&format!("ts-{i}.json"), rng.mutant(&seed));
        let run = vmr(&["record", "verify", "--record", &record, "--trust-store", &store, "--at", T]);
        assert!(matches!(run.code, 0 | 1 | 3), "exit code:\n{}", run.transcript());
        run.expect_code(run.code);
        assert_terminal_safe(&run, "verify");
    }
}

#[test]
fn key_export_survives_mutated_key_files_and_never_echoes_them() {
    let s = Scratch::new("robust-keys");
    let key = s.arg("good.key");
    vmr(&["key", "generate", "--output", &key]).expect_code(0);
    let seed = std::fs::read(&key).unwrap();
    let body: Vec<String> = String::from_utf8(seed.clone())
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(|l| l[..16].to_string())
        .collect();
    let mut rng = Lcg(0x5EED_6003);
    for i in 0..60 {
        let file = s.write(&format!("k-{i}.key"), rng.mutant(&seed));
        let run = vmr(&["key", "export", "--key", &file]);
        assert!(matches!(run.code, 0 | 1), "exit code:\n{}", run.transcript());
        run.expect_code(run.code);
        assert_terminal_safe(&run, "key export");
        for line in &body {
            assert!(!run.stderr.contains(line.as_str()), "the key file was echoed:\n{}", run.transcript());
        }
    }
}

#[test]
fn trust_store_add_survives_mutated_public_key_files() {
    let s = Scratch::new("robust-public-keys");
    let key = s.arg("good.key");
    vmr(&["key", "generate", "--output", &key]).expect_code(0);
    let seed = vmr(&["key", "export", "--key", &key]).stdout.into_bytes();
    let mut rng = Lcg(0x5EED_6004);
    for i in 0..60 {
        let public = s.write(&format!("pub-{i}.json"), rng.mutant(&seed));
        let store = s.arg(&format!("ts-{i}.json"));
        let run = vmr(&[
            "trust-store", "add", "--trust-store", &store, "--public-key", &public,
            "--issuer-id", "did:web:factory-operator.ph", "--issuer-name", "New Clark City Fab Operator",
            "--attestation-level", "software", "--valid-from", "2026-01-01T00:00:00Z",
        ]);
        assert!(matches!(run.code, 0 | 1), "exit code:\n{}", run.transcript());
        run.expect_code(run.code);
        assert_terminal_safe(&run, "trust-store add");
        assert_eq!(s.path(&format!("ts-{i}.json")).exists(), run.code == 0, "a store is written only on success");
    }
}
