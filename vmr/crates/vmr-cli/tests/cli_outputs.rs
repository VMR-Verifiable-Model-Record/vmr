// tests/cli_outputs.rs — what a command that writes a file refuses to write
// to, whatever --force says (QA P5-02; docs/CLI.md §5, docs/dev/phase5.md C7).
//
// `create_new` refuses an existing FILE, but on Windows a reserved device
// name opens the device: `key generate --output CON` printed the private key
// on the console, COM1 and AUX sent it to a serial port and reported
// success, LPT1 hung. Every output - key generate, key export, record emit
// --output, trust-store add --trust-store - is now refused by name before
// anything is opened, and an existing target that is not a regular file (a
// directory, a device, a pipe) is refused on every platform, even with
// --force. These tests never write to a device: each name is refused before
// an open, and the Windows test starts with a name that is harmless if it is
// not refused.

mod common;
use common::*;

/// `key generate`, run in `dir`, with `output` as its --output (and
/// `extra`); it must be refused with exit 1 and print no key. (It must also
/// return: a device open could block - LPT1 did - and would hang the test.
/// The name is refused before any open, so nothing can block.)
#[track_caller]
fn refused_key_generate(dir: &std::path::Path, output: &str, extra: &[&str], fragment: &str) {
    let mut args = vec!["key", "generate", "--output", output];
    args.extend_from_slice(extra);
    let run = vmr_in(dir, &args);
    run.expect_code(1);
    assert!(run.stdout.is_empty(), "{output:?}:\n{}", run.transcript());
    assert!(!run.stderr.contains("PRIVATE KEY"), "{output:?}:\n{}", run.transcript());
    assert!(run.stderr.contains(fragment), "{output:?}: expected `{fragment}`:\n{}", run.transcript());
    assert!(run.stderr.contains("nothing was written"), "{output:?}:\n{}", run.transcript());
}

/// A public key file and a private key in `s`, made by the CLI.
fn keys(s: &Scratch) -> (String, String) {
    let key = s.arg("k.pem");
    vmr(&["key", "generate", "--output", &key]).expect_code(0);
    let public = s.arg("k.pub.json");
    vmr(&["key", "export", "--key", &key, "--output", &public]).expect_code(0);
    (key, public)
}

#[cfg(windows)]
#[test]
fn windows_device_names_and_altered_names_are_refused_before_anything_is_opened() {
    let s = Scratch::new("outputs-windows-names");
    // First, names Windows would silently alter: 'k.pem.' would create
    // 'k.pem'. (Harmless if not refused, so it goes first.)
    for name in ["k.pem.", "k.pem ", "trailing..."] {
        refused_key_generate(&s.dir, name, &[], "Windows would create the file without it");
    }
    assert!(!s.path("k.pem").exists() && !s.path("trailing").exists(), "nothing was created");
    // The reserved device names, in any case, with or without an extension,
    // a trailing colon or spaces before the extension; the superscript
    // COM/LPT digits; the console's own names.
    for name in [
        "CON", "con", "Con.key", "PRN", "AUX", "aux.json", "NUL", "nul.pem", "COM1", "com9.pem", "COM0", "LPT1",
        "lpt9.vmr", "LPT0", "COM1:", "CON .txt", "CONIN$", "conout$", "COM\u{b9}", "LPT\u{b3}.key",
    ] {
        refused_key_generate(&s.dir, name, &[], "is a Windows device name");
        refused_key_generate(&s.dir, name, &["--force"], "is a Windows device name");
    }
    // Device-namespace paths.
    for path in [r"\\.\COM1", r"\\.\pipe\tlm-test", r"\\?\GLOBALROOT\Device\Null", "//./NUL", r"\??\NUL"] {
        refused_key_generate(&s.dir, path, &["--force"], "is a Windows device path");
    }
    // The other writers refuse the same way, before reading anything.
    let (key, public) = keys(&s);
    for name in ["CON", "NUL", "COM1", "LPT1", "k.pub.json."] {
        let run = vmr_in(&s.dir, &["key", "export", "--key", &key, "--output", name, "--force"]);
        run.expect_code(1);
        assert!(run.stdout.is_empty() && run.stderr.contains("nothing was written"), "{name}:\n{}", run.transcript());
        let run = vmr_in(
            &s.dir,
            &[
                "trust-store", "add", "--trust-store", name, "--public-key", &public, "--issuer-id", "did:web:x.example",
                "--issuer-name", "X", "--attestation-level", "software", "--valid-from", "2026-01-01T00:00:00Z",
            ],
        );
        run.expect_code(1);
        assert!(run.stdout.is_empty() && run.stderr.contains("nothing was written"), "{name}:\n{}", run.transcript());
        assert!(run.stderr.contains("--trust-store"), "the hint names the option:\n{}", run.transcript());
    }
    // A name that only contains a device name is an ordinary file.
    for name in ["console.key", "comet.pem", "lpt10.key", "com10.key", "a.con"] {
        let run = vmr_in(&s.dir, &["key", "generate", "--output", name]);
        run.expect_code(0);
        assert!(s.path(name).is_file(), "{name}");
    }
}

#[test]
fn an_existing_directory_is_never_written_even_with_force() {
    let s = Scratch::new("outputs-directory");
    let (key, public) = keys(&s);
    let dir = s.subdir("out");
    let dir = dir.to_string_lossy().into_owned();
    refused_key_generate(&s.dir, &dir, &["--force"], "exists and is not a regular file");
    let run = vmr(&["key", "export", "--key", &key, "--output", &dir, "--force"]);
    run.expect_code(1);
    assert!(run.stderr.contains("exists and is not a regular file"), "{}", run.transcript());
    let run = vmr(&[
        "trust-store", "add", "--trust-store", &dir, "--public-key", &public, "--issuer-id", "did:web:x.example",
        "--issuer-name", "X", "--attestation-level", "software", "--valid-from", "2026-01-01T00:00:00Z",
    ]);
    run.expect_code(1);
    assert!(run.stderr.contains("exists and is not a regular file"), "{}", run.transcript());
    assert!(std::fs::read_dir(s.path("out")).unwrap().next().is_none(), "the directory is left empty");
}

#[cfg(unix)]
#[test]
fn a_device_or_a_pipe_is_never_written_even_with_force() {
    let s = Scratch::new("outputs-unix-devices");
    // /dev/stdout would put the private key on standard output.
    for device in ["/dev/stdout", "/dev/stderr", "/dev/null"] {
        refused_key_generate(&s.dir, device, &["--force"], "exists and is not a regular file");
        refused_key_generate(&s.dir, device, &[], "exists and is not a regular file");
    }
    // A FIFO with no reader would block the write forever.
    let fifo = s.arg("pipe");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status().expect("run mkfifo");
    assert!(made.success(), "mkfifo {fifo}");
    refused_key_generate(&s.dir, &fifo, &["--force"], "exists and is not a regular file");
}

#[test]
fn force_never_replaces_the_commands_own_input() {
    // QA P5-11: `key export --key k.pem --output k.pem --force` left the
    // public key where the private key was - the key was gone. --force
    // replaces an old output, never an input: the same file, however it is
    // spelled, is refused and left as it was.
    let s = Scratch::new("outputs-own-input");
    let (key, public) = keys(&s);
    let original = std::fs::read(&key).unwrap();
    let relative = format!(".{}k.pem", std::path::MAIN_SEPARATOR);
    for output in [key.as_str(), relative.as_str()] {
        let run = vmr_in(&s.dir, &["key", "export", "--key", &key, "--output", output, "--force"]);
        run.expect_code(1);
        assert!(run.stderr.contains("is the file this command reads as --key"), "{output}:\n{}", run.transcript());
        assert!(run.stderr.contains("nothing was written"), "{output}:\n{}", run.transcript());
        assert_eq!(std::fs::read(&key).unwrap(), original, "{output}: the private key is intact");
    }
    if cfg!(windows) {
        // Windows file names are case-insensitive: K.PEM is k.pem.
        let run = vmr_in(&s.dir, &["key", "export", "--key", &key, "--output", "K.PEM", "--force"]);
        run.expect_code(1);
        assert_eq!(std::fs::read(&key).unwrap(), original);
    }
    // trust-store add: the public key file is not the store.
    let before = std::fs::read(&public).unwrap();
    let run = vmr(&[
        "trust-store", "add", "--trust-store", &public, "--public-key", &public, "--issuer-id", "did:web:x.example",
        "--issuer-name", "X", "--attestation-level", "software", "--valid-from", "2026-01-01T00:00:00Z",
    ]);
    run.expect_code(1);
    assert!(run.stderr.contains("is the file this command reads as --public-key"), "{}", run.transcript());
    assert_eq!(std::fs::read(&public).unwrap(), before);
    // Another file is still replaced with --force.
    let other = s.write("other.pub.json", "old");
    vmr(&["key", "export", "--key", &key, "--output", &other, "--force"]).expect_code(0);
}

#[cfg(unix)]
#[test]
fn a_hard_link_to_an_input_is_the_same_file() {
    let s = Scratch::new("outputs-hard-link");
    let (key, _) = keys(&s);
    let link = s.arg("link.pem");
    std::fs::hard_link(&key, &link).unwrap();
    let original = std::fs::read(&key).unwrap();
    let run = vmr(&["key", "export", "--key", &key, "--output", &link, "--force"]);
    run.expect_code(1);
    assert!(run.stderr.contains("is the file this command reads as --key"), "{}", run.transcript());
    assert_eq!(std::fs::read(&key).unwrap(), original);
}
