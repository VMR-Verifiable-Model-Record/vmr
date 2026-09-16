// tests/common/mod.rs — the harness every vmr-cli test uses.
//
// Every test runs the real `vmr` binary (CARGO_BIN_EXE_vmr) as a child
// process and judges its exit code, stdout and stderr (docs/dev/phase5.md
// §6). Rules (DEV_PLAN §5.2): no network, no sleeping, no global state, and
// file I/O only in a scratch directory under CARGO_TARGET_TMPDIR — one per
// test and process, removed when the test ends.

#![allow(dead_code)] // each test binary uses a different part of the harness

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// What `vmr --version` adds to the name and version of the build these
/// tests run: "KHALM-VMR, a reference implementation of the Verifiable Model
/// Record standard; record format v0.1", in the Community build (plan R4,
/// D11f-5). A build that extends vmr-cli and takes this harness by path
/// declares its own words.
pub const BUILD_WORDS: Option<&str> =
    Some("KHALM-VMR, a reference implementation of the Verifiable Model Record standard; record format v0.1");

/// What a `vmr` run produced.
pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    fn from_output(out: Output) -> Run {
        Run {
            // A process killed by a signal has no code; -1 never matches an
            // expected exit code.
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"),
            stderr: String::from_utf8_lossy(&out.stderr).replace("\r\n", "\n"),
        }
    }

    /// Everything the run printed, for assertion messages.
    pub fn transcript(&self) -> String {
        format!("exit code {}\n--- stdout ---\n{}\n--- stderr ---\n{}", self.code, self.stdout, self.stderr)
    }

    /// Assert the exit code, and that nothing panicked (a Rust panic exits
    /// with 101 and prints "panicked").
    #[track_caller]
    pub fn expect_code(&self, code: i32) -> &Run {
        assert!(!self.stderr.contains("panicked"), "vmr panicked:\n{}", self.transcript());
        assert_eq!(self.code, code, "unexpected exit code:\n{}", self.transcript());
        self
    }
}

/// The `vmr` binary under test.
pub fn vmr_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vmr"))
}

/// Run `vmr args...` in `cwd` with the inherited environment.
pub fn vmr_in(cwd: &Path, args: &[&str]) -> Run {
    let out = Command::new(vmr_path())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn vmr");
    Run::from_output(out)
}

/// Run `vmr args...` in the test process's working directory.
pub fn vmr(args: &[&str]) -> Run {
    vmr_in(Path::new(env!("CARGO_TARGET_TMPDIR")), args)
}

/// Run `vmr args...` as an isolated child: a CLEARED environment (only what
/// `env` adds, plus SystemRoot on Windows, which every Windows process
/// needs), in `cwd`. This is how the verifier's terminal is modelled: it has
/// nothing but its working directory and its arguments.
#[allow(clippy::disallowed_methods)] // reads SystemRoot to pass it on; nothing else
pub fn vmr_isolated(cwd: &Path, env: &[(&str, &str)], args: &[&str]) -> Run {
    let mut cmd = Command::new(vmr_path());
    cmd.args(args).current_dir(cwd).env_clear();
    if cfg!(windows) {
        if let Some(root) = std::env::var_os("SystemRoot") {
            cmd.env("SystemRoot", root);
        }
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    Run::from_output(cmd.output().expect("spawn vmr"))
}

/// A fresh scratch directory for one test in this process, removed by
/// [`Scratch`]'s drop.
pub struct Scratch {
    pub dir: PathBuf,
}

impl Scratch {
    pub fn new(label: &str) -> Scratch {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("vmr-cli")
            .join(format!("{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        Scratch { dir }
    }

    /// `name` inside the scratch directory.
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// `name` inside the scratch directory, as a string argument.
    pub fn arg(&self, name: &str) -> String {
        self.path(name).to_string_lossy().into_owned()
    }

    /// Write `bytes` to `name`; return the path as an argument.
    pub fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> String {
        std::fs::write(self.path(name), bytes).expect("write a scratch file");
        self.arg(name)
    }

    /// A subdirectory, created.
    pub fn subdir(&self, name: &str) -> PathBuf {
        let p = self.path(name);
        std::fs::create_dir_all(&p).expect("create a scratch subdirectory");
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The repository root.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

// ---------------------------------------------------------------------------
//  Records and trust stores for verification tests. Every key here is
//  derived from a fixed label — test-only, worthless outside tests, never
//  how a real key is made (`vmr key generate` uses the OS CSPRNG).
// ---------------------------------------------------------------------------

use vmr_record::hash::sha256;
use vmr_record::record::{JwkPublicKey, Record, SignatureSection};

/// The evaluation time the verification vectors use: the day after the
/// record vector's issued_at.
pub const T: &str = "2026-09-11T00:00:00Z";

/// Key A: the record vector's signing key (spec §9).
pub const KEY_A: &str = "khalm v0.1 test-vector signing key";
/// A forger's key: trusted by no store.
pub const KEY_FORGER: &str = "khalm-vmr vmr-cli test forger key (test-only)";

/// A derived test key.
pub fn key(label: &str) -> p256::ecdsa::SigningKey {
    vmr_record::sign::signing_key_from_secret(&sha256(label.as_bytes())).unwrap()
}

/// The committed record vector (specs/test-vectors/record/).
pub fn vector() -> Record {
    let path = repo().join("specs/test-vectors/record/example-v0.1.json");
    let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    serde_json::from_value(doc["record"].clone()).unwrap()
}

/// The general description's conformance vector (task 10.11b): a model of
/// four synthetic files, not-held training records, signed with key A.
pub fn general_vector() -> Record {
    let path = repo().join("specs/test-vectors/record/example-general-v0.1.json");
    let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    serde_json::from_value(doc["record"].clone()).unwrap()
}

/// A committed verification-vector trust store, by name (e.g. `ts-basic`).
pub fn vector_store(name: &str) -> Vec<u8> {
    std::fs::read(repo().join(format!("specs/test-vectors/verify/trust-stores/{name}.json"))).unwrap()
}

/// Sign `p` as it stands with `label`'s key.
pub fn sign_as(p: &mut Record, label: &str) {
    let sig = vmr_record::sign::sign(&key(label), &p.signature_tbs().unwrap()).unwrap();
    p.signature.algorithm = "ES256".into();
    p.signature.signature = SignatureSection::signature_field(&sig);
    p.signature.signed_payload_hash = p.signed_payload_hash().unwrap();
}

/// Embed `label`'s key wherever the record names its key, then sign with
/// it: the forger of QA PROBE 6 — internally consistent, trusted by no one.
pub fn reissue_with(p: &mut Record, label: &str) {
    let jwk = JwkPublicKey::from_verifying_key(key(label).verifying_key());
    p.issuer.key_id = jwk.key_id();
    p.signature.signing_key_id = jwk.key_id();
    p.issuer.public_key = jwk;
    sign_as(p, label);
}

/// Lower-case or upper-case hex to bytes (test inputs only).
pub fn hex_decode(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// The bytes a verification-vector input stands for (`text` or `hex`, then
/// `append_spaces` spaces) — specs/test-vectors/verify/README.md.
pub fn vector_input_bytes(input: &serde_json::Value) -> Vec<u8> {
    let mut bytes = match (input.get("text"), input.get("hex")) {
        (Some(t), None) => t.as_str().unwrap().as_bytes().to_vec(),
        (None, Some(h)) => hex_decode(h.as_str().unwrap()),
        other => panic!("an input has exactly one of text / hex: {other:?}"),
    };
    if let Some(n) = input.get("append_spaces") {
        bytes.resize(bytes.len() + n.as_u64().unwrap() as usize, b' ');
    }
    bytes
}

/// The report `vmr-verify` computes in this process for the same inputs —
/// what `vmr record verify --json` must print byte for byte.
pub fn in_process_report(
    record: &[u8],
    store: &[u8],
    at: &str,
    previous: &[Vec<u8>],
    require_complete_lineage: bool,
) -> vmr_verify::VerificationReport {
    let store = vmr_verify::TrustStore::from_json(store).unwrap();
    let refs: Vec<&[u8]> = previous.iter().map(Vec::as_slice).collect();
    let opts = vmr_verify::VerifyOptions::new(vmr_record::timestamp::Timestamp::parse(at).unwrap())
        .with_previous(&refs)
        .require_complete_lineage(require_complete_lineage);
    vmr_verify::Verifier::new(store).verify(record, &opts)
}

/// The first line of a verification rendering.
pub fn headline(run: &Run) -> &str {
    run.stdout.lines().next().unwrap_or("")
}

// ---------------------------------------------------------------------------
//  The golden state's hash, test keys and argument lists. (The engine
//  profile's emission inputs, the golden brain and the demo stream, are the
//  engine build's harness's: task 10.13a, Part A.)
// ---------------------------------------------------------------------------

/// `sha256:<hex>` of golden_state.bin as tests/fixtures/golden_hashes.json
/// records it (computed externally, Law 7), read from this crate's copy of that
/// file, tests/data/golden_hashes.json: a Community checkout holds no engine
/// fixture (task 10.13a, QA QM-07). The engine build's tests hold the copy
/// equal to the fixture's file, byte for byte.
pub fn golden_state_hash() -> String {
    let text = std::fs::read_to_string(repo().join("vmr/crates/vmr-cli/tests/data/golden_hashes.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    format!("sha256:{}", json["files"]["golden_state.bin"]["sha256"].as_str().unwrap().to_ascii_lowercase())
}

/// A derived, TEST-ONLY private key written as PKCS#8 PEM into the scratch
/// directory (real keys come from `vmr key generate`).
pub fn write_test_key(s: &Scratch, name: &str, label: &str) -> String {
    use p256::pkcs8::EncodePrivateKey;
    let pem = key(label).to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap();
    s.write(name, pem.as_bytes())
}

/// `args` as the `&[&str]` the runners take.
pub fn strs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

// ---------------------------------------------------------------------------
//  Gate 5's isolation (tests/gate5.rs; the engine build's Gate 5 tests use
//  the same, task 10.13a). A module of its own: cross_impl's support module
//  has an ISSUER and an AT of its own, and its test binary imports both.
// ---------------------------------------------------------------------------

pub mod gate5 {
    use super::{repo, vmr_isolated, Run, Scratch};
    use std::path::{Path, PathBuf};

    pub const ISSUER: &str = "did:web:factory-operator.ph";
    pub const NAME: &str = "New Clark City Fab Operator";
    /// The verification time (the committed artifact was issued 12 hours
    /// earlier).
    pub const AT: &str = "2026-09-11T12:00:00Z";

    pub const VALID: &str = "✓ Record valid — signed by a key the trust store trusts for this issuer";
    pub const NOT_VALID: &str = "✗ Record NOT valid — ";

    /// The committed Gate 5 artifact's directory, vmr-cli's tests/data/gate5/.
    pub fn artifact_dir() -> PathBuf {
        repo().join("vmr/crates/vmr-cli/tests/data/gate5")
    }

    pub fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> =
            std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    /// The verifier's terminal: `vmr record verify` in `dir`, which holds
    /// only the record and the trust store, with nothing inherited.
    pub fn isolated_verify(dir: &Path, record: &str, store: &str, json: bool) -> Run {
        let mut args = vec!["record", "verify", "--record", record, "--trust-store", store, "--at", AT];
        if json {
            args.push("--json");
        }
        vmr_isolated(dir, &[("TZ", "Pacific/Kiritimati")], &args)
    }

    /// A fresh verifier directory holding exactly `files` (name, bytes).
    pub fn verifier_dir(s: &Scratch, name: &str, files: &[(&str, Vec<u8>)]) -> PathBuf {
        let dir = s.subdir(name);
        for (file, bytes) in files {
            std::fs::write(dir.join(file), bytes).unwrap();
        }
        dir
    }

    /// `bytes` with the demo's tamper: the data-residency claim "PH" -> "SG",
    /// same length, inside the COSE payload.
    pub fn tampered(bytes: &[u8]) -> Vec<u8> {
        let needle = b"\"data_residency\":\"PH\"";
        let at = bytes.windows(needle.len()).position(|w| w == needle).expect("the claim is in the payload");
        let mut out = bytes.to_vec();
        out[at + needle.len() - 3] = b'S';
        out[at + needle.len() - 2] = b'G';
        out
    }
}

// ---------------------------------------------------------------------------
//  Mutants through the whole process (tests/cli_robustness.rs; the engine
//  build's robustness test uses the same, task 10.13a).
// ---------------------------------------------------------------------------

/// The same MMIX LCG as src/mutate.rs: fixed seeds, no clock, no `rand`.
pub struct Lcg(pub u64);

impl Lcg {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// `seed` with 1 to 4 random edits (flip, overwrite, truncate, insert,
    /// delete).
    pub fn mutant(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut v = seed.to_vec();
        for _ in 0..1 + self.below(4) {
            if v.is_empty() {
                v.push(b'{');
            }
            let at = self.below(v.len());
            match self.below(5) {
                0 => v[at] ^= 1 << self.below(8),
                1 => v[at] = self.next() as u8,
                2 => v.truncate(at),
                3 => v.insert(at, [0x1b, b'"', b'\\', 0xff, b'{'][self.below(5)]),
                _ => {
                    v.remove(at);
                }
            }
        }
        v
    }
}

/// Nothing on the terminal can move the cursor or reorder text.
pub fn assert_terminal_safe(run: &Run, what: &str) {
    for text in [&run.stdout, &run.stderr] {
        let bad = text.chars().find(|&c| {
            (c.is_control() && c != '\n')
                || matches!(u32::from(c), 0x202a..=0x202e | 0x2066..=0x2069 | 0x2028 | 0x2029 | 0x200e | 0x200f)
        });
        assert!(bad.is_none(), "{what}: raw {bad:?} printed:\n{}", run.transcript());
    }
}
