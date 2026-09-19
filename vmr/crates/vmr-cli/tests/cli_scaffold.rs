// tests/cli_scaffold.rs — TASKS 5.1: the `vmr` binary, its command tree and
// the exit-code contract (docs/dev/phase5.md §2, C1, C10).
//
// What every later command relies on: `--help` and `--version` succeed on
// stdout; every usage error is exit code 1 on stderr (clap's own code, 2, is
// reserved for engine errors here); and the binary says which build it is.

mod common;
use common::vmr;
use vmr_cli::names::TOOL;

#[test]
fn version_names_the_binary_and_its_build_flavor() {
    let run = vmr(&["--version"]);
    run.expect_code(0);
    assert!(run.stdout.starts_with("vmr 0.1.3"), "{}", run.transcript());
    // D11f-5: the version names the software and this build's reference
    // status, and the record format it implements, so that 0.1.3 is not read
    // as the standard's own version (the engine build's version says what it
    // adds beyond that, and its own tests check it).
    assert_eq!(
        run.stdout.trim_end(),
        "vmr 0.1.3 (KHALM-VMR, a reference implementation of the Verifiable Model Record standard; record format v0.1)",
        "{}",
        run.transcript()
    );
}

#[test]
fn help_describes_the_tool_and_the_exit_codes() {
    let run = vmr(&["--help"]);
    run.expect_code(0);
    assert!(run.stdout.contains("Usage: vmr"), "{}", run.transcript());
    assert!(run.stdout.contains("offline"), "{}", run.transcript());
    for code in ["0 ", "1 ", "3 ", "4 "] {
        assert!(run.stdout.contains(&format!("  {code}")), "exit code {code}missing:\n{}", run.transcript());
    }
    assert!(run.stderr.is_empty(), "{}", run.transcript());
}

#[test]
fn no_arguments_prints_usage_and_exits_1() {
    let run = vmr(&[]);
    run.expect_code(1);
    assert!(run.stderr.contains("Usage: vmr"), "{}", run.transcript());
    assert!(run.stdout.is_empty(), "{}", run.transcript());
}

#[test]
fn an_unknown_subcommand_or_flag_is_a_usage_error_exit_1() {
    for args in [&["frobnicate"][..], &["--frobnicate"]] {
        let run = vmr(args);
        run.expect_code(1);
        assert!(run.stderr.contains("error:"), "{}", run.transcript());
        assert!(run.stdout.is_empty(), "{}", run.transcript());
    }
}

/// The characters on a terminal that act or hide: C0 controls but LF, DEL,
/// C1 controls, the bidi controls and the zero-width ones.
fn raw_unsafe(text: &str) -> Vec<char> {
    text.chars()
        .filter(|&c| {
            (c.is_control() && c != '\n')
                || matches!(u32::from(c), 0x200b..=0x200f | 0x202a..=0x202e | 0x2066..=0x2069 | 0x2028 | 0x2029 | 0xfeff)
        })
        .collect()
}

#[test]
fn a_usage_error_never_echoes_an_argument_raw() {
    // QA P5-03: clap's own messages quote the offending argument. Whatever
    // it holds - an ANSI escape that would repaint the screen, a
    // right-to-left override, a zero-width space - reaches stderr escaped
    // (docs/CLI.md §5), with the usual exit code 1 and nothing on stdout.
    let hostile = "\u{1b}[31mRED\u{1b}[0m\u{202e}txt.dlrow\u{200b}";
    for args in [
        vec!["record", "verify", "--record", "p", "--trust-store", "t", hostile],
        vec!["record", "verify", "--record", "p", "--trust-store", "t", "--at", hostile],
        vec![
            "trust-store", "add", "--trust-store", "t", "--public-key", "k", "--issuer-id", "did:web:x",
            "--issuer-name", "n", "--attestation-level", hostile, "--valid-from", "2026-01-01T00:00:00Z",
        ],
        vec![hostile],
    ] {
        let run = vmr(&args);
        run.expect_code(1);
        assert!(run.stdout.is_empty(), "{}", run.transcript());
        assert!(run.stderr.contains("error:"), "{}", run.transcript());
        assert_eq!(raw_unsafe(&run.stderr), Vec::<char>::new(), "raw on stderr:\n{}", run.transcript());
        assert!(run.stderr.contains("\\u{001b}[31mRED"), "the argument is shown, escaped:\n{}", run.transcript());
    }
}

#[test]
fn help_and_usage_name_the_two_display_options() {
    // QA QP-07: --color and --ascii (docs/dev/cli-polish.md CP-2) are global
    // options, so every help page lists them and a usage line reads
    // [OPTIONS]. The results and errors a pipe gets did not change.
    for (args, usage) in [
        (&["--help"][..], "Usage: vmr [OPTIONS] <COMMAND>"),
        (&["record", "inspect", "--help"], "Usage: vmr record inspect [OPTIONS] --record <FILE>"),
    ] {
        let run = vmr(args);
        run.expect_code(0);
        for want in [usage, "--color <WHEN>", "--ascii"] {
            assert!(run.stdout.contains(want), "missing `{want}`:\n{}", run.transcript());
        }
    }
}

#[test]
fn help_and_version_are_unchanged_on_stdout() {
    // The escaping must not touch clap's own output: --help and --version
    // still go to stdout, exit 0, nothing escaped in them.
    let run = vmr(&["record", "verify", "--help"]);
    run.expect_code(0);
    assert!(run.stdout.starts_with("Verify a record against a trust store, offline."), "{}", run.transcript());
    assert!(!run.stdout.contains("\\u{"), "{}", run.transcript());
    assert!(run.stderr.is_empty(), "{}", run.transcript());
}

/// Every help page of the Community build.
const HELP_PAGES: [&[&str]; 8] = [
    &["--help"],
    &["record", "emit", "--help"],
    &["record", "verify", "--help"],
    &["record", "inspect", "--help"],
    &["model", "hash", "--help"],
    &["key", "generate", "--help"],
    &["key", "export", "--help"],
    &["trust-store", "add", "--help"],
];

#[test]
fn help_cites_no_repository_path_and_names_no_engine() {
    // docs/dev/cli-polish.md CP-3 and §6 F2, F4: the Community build's help
    // names the standard's documents, never a path in this repository, and
    // names no engine.
    for args in HELP_PAGES {
        let run = vmr(args);
        run.expect_code(0);
        for path in ["specs/", "docs/", ".md"] {
            assert!(!run.stdout.contains(path), "{args:?} cites `{path}`:\n{}", run.transcript());
        }
        assert!(!run.stdout.to_lowercase().contains("engine"), "{args:?} names an engine:\n{}", run.transcript());
    }
}

/// The exit codes the table at the end of a help page lists.
fn exit_codes(args: &[&str]) -> Vec<u8> {
    let run = vmr(args);
    run.expect_code(0);
    let table = run.stdout.split("Exit codes:").nth(1).unwrap_or_default().to_string();
    (0..=4u8).filter(|code| table.lines().any(|line| line.starts_with(&format!("  {code}  ")))).collect()
}

#[test]
fn each_help_lists_only_the_exit_codes_its_command_returns() {
    // docs/dev/cli-polish.md CP-3: the top-level help keeps the whole table of
    // the Community build, which has no exit code 2; a command's help lists
    // its own codes.
    assert_eq!(exit_codes(&["--help"]), [0, 1, 3, 4]);
    assert_eq!(exit_codes(&["record", "verify", "--help"]), [0, 1, 3, 4]);
    for args in [
        &["record", "emit", "--help"][..],
        &["record", "inspect", "--help"],
        &["model", "hash", "--help"],
        &["key", "generate", "--help"],
        &["key", "export", "--help"],
        &["trust-store", "add", "--help"],
    ] {
        assert_eq!(exit_codes(args), [0, 1], "{args:?}");
    }
}

#[test]
fn help_says_what_the_tool_is_and_claims_no_more() {
    // docs/dev/cli-polish.md CP-3, CP-10: a reference implementation of the
    // standard, never the only or an official one. The name comes from
    // vmr_cli::names, as the help's does.
    let run = vmr(&["--help"]);
    run.expect_code(0);
    let sentence = format!("{TOOL} is a reference implementation of the Verifiable Model Record standard");
    assert!(run.stdout.contains(&sentence), "{}", run.transcript());
    for claim in ["the reference implementation", "official", "the only", "certified"] {
        assert!(!run.stdout.contains(claim), "`{claim}` in:\n{}", run.transcript());
    }
    // D11f-5, the owner's goal-fit rule: a record made by any conforming
    // tool, of any vendor's model, verifies the same way as this one's.
    assert!(
        run.stdout.contains("Records made by any conforming tool are equally valid"),
        "{}",
        run.transcript()
    );
}

#[test]
fn no_option_description_ends_with_a_period() {
    // QA QPB-07: clap drops a doc comment's final period, not an explicit
    // help string's; no option line ends with one.
    for args in HELP_PAGES {
        let run = vmr(args);
        run.expect_code(0);
        let options = run.stdout.split("Options:").nth(1).unwrap_or_default();
        let options = options.split("Exit codes:").next().unwrap_or_default();
        for line in options.lines() {
            assert!(!line.trim_end().ends_with('.'), "{args:?}: `{line}`\n{}", run.transcript());
        }
    }
}
