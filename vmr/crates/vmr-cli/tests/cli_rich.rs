// tests/cli_rich.rs — the screens a person sees at a terminal
// (docs/dev/cli-polish.md CP-2 to CP-5).
//
// A test's standard output is a pipe, so `vmr` prints its plain text there,
// exactly as before this change: every other test file pins that text.
// `--color always` draws the terminal screens into the pipe as well, which is
// how these tests see them. They check what the design promises: the same
// values as the plain text; frames whose every line is as wide as the next;
// nothing a record or a trust store says able to break a line, a style or a
// border; plain ASCII with --ascii; --json and the plain text untouched;
// "compliant" never without its qualifier; and the error screens.

mod common;
use common::*;
use serde_json::Value;
use vmr_cli::names::{RECORD_EXTENSION, TOOL};

const ESC: char = '\u{1b}';

/// The first row of the standard's logo (docs/dev/cli-polish.md CP-3): squares 0, 4 and 6 of
/// eight, four characters each.
const LOGO_TOP: &str = "\u{2588}\u{2588}\u{2588}\u{2588}            \u{2588}\u{2588}\u{2588}\u{2588}    \u{2588}\u{2588}\u{2588}\u{2588}";

/// Every escape sequence the screens write, the closed set of `rich.rs`'s
/// styles, written out here (QA QP-08).
const SEQUENCES: [&str; 12] = [
    "\u{1b}[0m",
    "\u{1b}[1m",
    "\u{1b}[90m",
    "\u{1b}[1;32m",
    "\u{1b}[1;31m",
    "\u{1b}[1;33m",
    "\u{1b}[33m",
    "\u{1b}[1;36m",
    "\u{1b}[1;30;42m",
    "\u{1b}[1;97;41m",
    "\u{1b}[1;30;43m",
    "\u{1b}[1;30;46m",
];

/// A screen's text: every sequence of the closed set removed. Any other
/// escape sequence fails the test.
fn strip(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(at) = rest.find(ESC) {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let Some(sequence) = SEQUENCES.iter().find(|q| tail.starts_with(**q)) else {
            let start: String = tail.chars().take(12).collect();
            panic!("an escape sequence outside the screens' set at `{}` in:\n{s}", start.escape_debug());
        };
        rest = &tail[sequence.len()..];
    }
    out.push_str(rest);
    out
}

/// The screens' Unicode width tables (`src/width_tables.rs`).
mod width_tables {
    include!("../src/width_tables.rs");
}

/// The columns a text takes on a terminal: none for a combining mark, two for
/// a wide East Asian character or emoji, else one.
fn columns(text: &str) -> usize {
    let within = |table: &[(u32, u32)], cp: u32| table.iter().any(|(lo, hi)| (*lo..=*hi).contains(&cp));
    text.chars()
        .map(|c| {
            let cp = u32::from(c);
            if within(width_tables::ZERO, cp) {
                0
            } else if within(width_tables::WIDE, cp) {
                2
            } else {
                1
            }
        })
        .sum()
}

/// Wide characters, emoji and combining marks of several scripts (QA QP-05),
/// with no space, so that a screen never breaks a line inside them.
const WIDE: &str = "\u{754c}\u{1f680}\u{26a1}\u{2705}\u{1fa7a}e\u{301}\u{591}\u{e31}\u{93f}";

/// No character a terminal acts on or hides, but the line break.
fn terminal_safe(s: &str) -> bool {
    !s.chars().any(|c| {
        (c.is_control() && c != '\n')
            || matches!(u32::from(c), 0x202a..=0x202e | 0x2066..=0x2069 | 0x2028 | 0x2029 | 0x200e | 0x200f | 0x061c)
    })
}

/// A line of a banner or a table: two spaces, then a border character.
fn is_frame(line: &str) -> bool {
    line.starts_with("  ")
        && line.chars().nth(2).is_some_and(|c| matches!(c, '│' | '┌' | '├' | '└' | '╭' | '╰' | '|' | '+'))
}

/// Every frame line of a screen is 96 terminal columns wide, measured as a
/// terminal draws it, not in characters (QA QP-05).
fn frames_are_even(screen: &str) {
    let frames: Vec<&str> = screen.lines().filter(|l| is_frame(l)).collect();
    assert!(!frames.is_empty(), "no frame lines in:\n{screen}");
    for l in frames {
        assert_eq!(columns(l), 96, "uneven frame line `{l}` in:\n{screen}");
    }
}

/// The record ids and hashes a plain output shows.
fn values(plain: &str) -> Vec<String> {
    plain
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | '(' | ')' | '"'))
        .filter(|t| t.starts_with("sha256:") || t.starts_with("urn:uuid:"))
        .map(str::to_string)
        .collect()
}

fn with(args: &[&str], extra: &[&str]) -> Vec<String> {
    args.iter().chain(extra).map(|s| s.to_string()).collect()
}

/// The Gate 5 record and its trust store, copied into the scratch directory.
fn gate5(s: &Scratch) -> (String, String) {
    let dir = repo().join("vmr/crates/vmr-cli/tests/data/gate5");
    (
        s.write("model.vmr", std::fs::read(dir.join("model.vmr")).unwrap()),
        s.write("trust-store.json", std::fs::read(dir.join("trust-store.json")).unwrap()),
    )
}

const AT: &str = "2026-09-11T12:00:00Z";

#[test]
fn a_pass_is_drawn_with_the_same_values_as_the_plain_text() {
    let s = Scratch::new("rich-verify-pass");
    let (record, store) = gate5(&s);
    let args: [&str; 8] = ["record", "verify", "--record", &record, "--trust-store", &store, "--at", AT];
    let plain = vmr(&args);
    plain.expect_code(0);
    let rich = vmr(&strs(&with(&args, &["--color", "always"])));
    rich.expect_code(0);
    assert!(rich.stdout.contains(ESC), "{}", rich.transcript());
    let screen = strip(&rich.stdout);
    for want in ["√ VALID", "Signed by a key your trust store trusts for this issuer", "Signing key", "Checked at", "from --at"] {
        assert!(screen.contains(want), "missing `{want}`:\n{screen}");
    }
    let shown = values(&plain.stdout);
    assert!(shown.len() >= 4, "{}", plain.transcript());
    for value in shown {
        assert!(screen.contains(&value), "missing `{value}`:\n{screen}");
    }
    frames_are_even(&screen);
    assert!(terminal_safe(&screen), "{screen}");
    assert!(rich.stderr.is_empty(), "{}", rich.transcript());
}

#[test]
fn a_pipe_gets_the_plain_text_and_json_never_changes() {
    let s = Scratch::new("rich-plain");
    let (record, store) = gate5(&s);
    let args: [&str; 8] = ["record", "verify", "--record", &record, "--trust-store", &store, "--at", AT];
    let default = vmr(&args);
    default.expect_code(0);
    assert!(!default.stdout.contains(ESC), "{}", default.transcript());
    assert!(default.stdout.starts_with("✓ Record valid — "), "{}", default.transcript());
    // --color never still means boxes on a terminal; into a pipe it is the
    // plain text, byte for byte.
    let never = vmr(&strs(&with(&args, &["--color", "never", "--ascii"])));
    never.expect_code(0);
    assert_eq!(never.stdout, default.stdout);
    let json = vmr(&strs(&with(&args, &["--json"])));
    json.expect_code(0);
    let json_always = vmr(&strs(&with(&args, &["--json", "--color", "always", "--ascii"])));
    json_always.expect_code(0);
    assert_eq!(json_always.stdout, json.stdout);
    let _: Value = serde_json::from_str(&json.stdout).unwrap();
}

#[test]
fn ascii_draws_the_same_screen_without_box_characters() {
    let s = Scratch::new("rich-ascii");
    let (record, store) = gate5(&s);
    let args: [&str; 11] = ["record", "verify", "--record", &record, "--trust-store", &store, "--at", AT, "--color", "always", "--ascii"];
    let run = vmr(&args);
    run.expect_code(0);
    let screen = strip(&run.stdout);
    assert!(!screen.chars().any(|c| ('\u{2500}'..='\u{257f}').contains(&c)), "box drawing left:\n{screen}");
    assert!(screen.contains("+---") && screen.contains("VALID"), "{screen}");
    frames_are_even(&screen);
}

#[test]
fn a_failure_shows_its_check_and_the_claims_as_not_verified() {
    let s = Scratch::new("rich-verify-fail");
    let (record, store) = gate5(&s);
    let tampered = s.write("tampered.vmr", changed_claim(&std::fs::read(&record).unwrap()));
    let run = vmr(&["record", "verify", "--record", &tampered, "--trust-store", &store, "--at", AT, "--color", "always"]);
    run.expect_code(3);
    let screen = strip(&run.stdout);
    for want in ["× NOT VALID", "Failed check", "signature.valid", "NOT VERIFIED", "What the record claims"] {
        assert!(screen.contains(want), "missing `{want}`:\n{screen}");
    }
    frames_are_even(&screen);
}

/// The COSE bytes with the residency claim changed, byte for byte (the
/// payload is JSON inside a binary envelope, so the edit is on bytes).
fn changed_claim(bytes: &[u8]) -> Vec<u8> {
    let from = b"\"data_residency\":\"PH\"";
    let to = b"\"data_residency\":\"SG\"";
    let at = bytes.windows(from.len()).position(|w| w == from).expect("the claim is in the record");
    let mut out = bytes.to_vec();
    out[at..at + to.len()].copy_from_slice(to);
    out
}

#[test]
fn the_policy_screen_keeps_two_statements_and_qualifies_compliant() {
    let s = Scratch::new("rich-policy");
    let (record, store) = gate5(&s);
    let pack = repo().join("specs/policy-packs/khalm-reading-eu-ai-act-2026.json").display().to_string();
    let args: [&str; 10] = ["record", "verify", "--record", &record, "--trust-store", &store, "--at", AT, "--policy-pack", &pack];
    let plain = vmr(&args);
    plain.expect_code(0);
    let rich = vmr(&strs(&with(&args, &["--color", "always"])));
    rich.expect_code(0);
    let screen = strip(&rich.stdout);
    for want in [
        "Declared",
        "Evaluated here",
        "√ compliant",
        "its mandatory rules pass",
        "Only mandatory rules decide",
        "eu-ai-act-human-oversight",
        "× fail",
        "Pack payload",
        // The owner, 2026-09-16: the screen says what a pack result is, and
        // where to read what it does not mean.
        "Pack reading",
        "the pack author's reading of the cited text",
        "docs/POLICY_PACKS.md",
    ] {
        assert!(screen.contains(want), "missing `{want}`:\n{screen}");
    }
    for value in values(&plain.stdout) {
        assert!(screen.contains(&value), "missing `{value}`:\n{screen}");
    }
    // "compliant" never stands without its qualifier: on its own line or the
    // next, the mandatory rules or the issuer's declaration are named.
    let lines: Vec<&str> = screen.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("compliant") && !line.contains("non-compliant") {
            let next = lines.get(i + 1).copied().unwrap_or_default();
            assert!(
                [line, &next].iter().any(|l| l.contains("mandatory rules") || l.contains("declares")),
                "`compliant` without its qualifier on `{line}`:\n{screen}"
            );
        }
    }
    assert!(!screen.contains("COMPLIANT"), "{screen}");
    // Every rule of the pack is listed: six, within the screen's bound.
    let rules: Value = serde_json::from_str(&std::fs::read_to_string(&pack).unwrap()).unwrap();
    let ids: Vec<&str> = rules["rules"].as_array().unwrap().iter().map(|r| r["rule_id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), 6, "{ids:?}");
    for id in ids {
        assert!(screen.contains(id), "rule `{id}` missing:\n{screen}");
    }
    frames_are_even(&screen);
}

#[test]
fn inspect_is_drawn_unverified_with_the_signature_not_checked() {
    let s = Scratch::new("rich-inspect");
    let record = s.write("record.vmr", std::fs::read(repo().join("docs/examples/phi-4-mini-instruct/record.vmr")).unwrap());
    let plain = vmr(&["record", "inspect", "--record", &record]);
    plain.expect_code(0);
    let rich = vmr(&["record", "inspect", "--record", &record, "--color", "always"]);
    rich.expect_code(0);
    let screen = strip(&rich.stdout);
    for want in ["UNVERIFIED", "NOT CHECKED", "Model hash", "Components", "DECLARED"] {
        assert!(screen.contains(want), "missing `{want}`:\n{screen}");
    }
    for value in values(&plain.stdout) {
        assert!(screen.contains(&value), "missing `{value}`:\n{screen}");
    }
    frames_are_even(&screen);
}

#[test]
fn the_key_and_trust_store_screens() {
    let s = Scratch::new("rich-keys");
    let key = s.arg("signer.key");
    let public = s.arg("signer.pub.json");
    let store = s.arg("ts.json");
    let generated = vmr(&["key", "generate", "--output", &key, "--color", "always"]);
    generated.expect_code(0);
    let exported = vmr(&["key", "export", "--key", &key, "--output", &public, "--color", "always"]);
    exported.expect_code(0);
    let file: Value = serde_json::from_str(&std::fs::read_to_string(&public).unwrap()).unwrap();
    let thumbprint = file["key_id"].as_str().unwrap().trim_start_matches("urn:ietf:params:oauth:jwk-thumbprint:sha-256:").to_string();
    let generated = strip(&generated.stdout);
    assert!(generated.contains("KEY CREATED") && generated.contains("keep it secret") && generated.contains(&thumbprint), "{generated}");
    frames_are_even(&generated);
    let exported = strip(&exported.stdout);
    assert!(exported.contains("EXPORTED") && exported.contains(&thumbprint), "{exported}");
    let added = vmr(&[
        "trust-store", "add", "--trust-store", &store, "--public-key", &public, "--issuer-id", "did:web:example.org",
        "--issuer-name", "Example signer", "--attestation-level", "self", "--valid-from", "2026-01-01T00:00:00Z",
        "--color", "always",
    ]);
    added.expect_code(0);
    let added = strip(&added.stdout);
    for want in ["TRUSTED", "did:web:example.org", "Example signer", "up to self", "created"] {
        assert!(added.contains(want), "missing `{want}`:\n{added}");
    }
    frames_are_even(&added);
    // The public key written to standard output is data: JSON, never a screen.
    let to_stdout = vmr(&["key", "export", "--key", &key, "--color", "always"]);
    to_stdout.expect_code(0);
    assert!(!to_stdout.stdout.contains(ESC), "{}", to_stdout.transcript());
    let _: Value = serde_json::from_str(&to_stdout.stdout).unwrap();
}

#[test]
fn errors_are_drawn_with_an_error_badge_and_a_hint() {
    let s = Scratch::new("rich-errors");
    let (_record, store) = gate5(&s);
    let missing = s.arg("nope.vmr");
    let run = vmr(&["record", "verify", "--record", &missing, "--trust-store", &store, "--color", "always"]);
    run.expect_code(1);
    assert!(run.stdout.is_empty(), "{}", run.transcript());
    let screen = strip(&run.stderr);
    assert!(screen.contains(" ERROR ") && screen.contains("cannot read record"), "{screen}");
    assert!(!screen.contains("vmr: error:"), "{screen}");
    let plain = vmr(&["record", "verify", "--record", &missing, "--trust-store", &store]);
    plain.expect_code(1);
    assert!(plain.stderr.starts_with("vmr: error: cannot read record"), "{}", plain.transcript());
    // A usage error: clap refuses the line before --color is parsed, and the
    // screen still follows it.
    let usage = vmr(&["record", "verify", "--trust-stor", "x", "--color", "always"]);
    usage.expect_code(1);
    let screen = strip(&usage.stderr);
    assert!(screen.contains(" ERROR ") && screen.contains("hint") && screen.contains("--trust-store"), "{screen}");
    // An argument holding an escape sequence is still shown escaped.
    let hostile = vmr(&["record", "verify", "--at", "x\u{1b}[31mRED", "--color", "always"]);
    hostile.expect_code(1);
    let screen = strip(&hostile.stderr);
    assert!(terminal_safe(&screen) && screen.contains("\\u{001b}[31mRED"), "{screen}");
}

#[test]
fn a_trust_store_name_cannot_break_the_screen() {
    let s = Scratch::new("rich-hostile");
    let record = s.write("record.json", vector().to_json().unwrap());
    let mut store: Value = serde_json::from_slice(&vector_store("ts-basic")).unwrap();
    let issuer = store["issuers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|i| i["issuer_id"] == "did:web:factory-operator.ph")
        .unwrap();
    issuer["issuer_name"] = Value::String(format!("Evil\u{1b}[2J\u{202e}\r\n{WIDE}{}", "x".repeat(150)));
    let store = s.write("ts.json", serde_json::to_vec(&store).unwrap());
    let run = vmr(&["record", "verify", "--record", &record, "--trust-store", &store, "--at", T, "--color", "always"]);
    run.expect_code(0);
    let screen = strip(&run.stdout);
    assert!(terminal_safe(&screen), "{screen}");
    assert!(screen.contains("\\u{001b}[2J"), "the name is shown escaped:\n{screen}");
    assert!(screen.contains(WIDE), "wide characters and marks are shown as they are:\n{screen}");
    frames_are_even(&screen);
}

/// The first character of the P5-03 and QA QM-02 class in `s`, if any: a
/// control other than the line break, a bidi control, a zero-width character,
/// a line or paragraph separator, a byte order mark.
fn raw_character(s: &str) -> Option<char> {
    s.chars().find(|c| {
        (c.is_control() && *c != '\n')
            || matches!(u32::from(*c), 0x061c | 0x200b..=0x200f | 0x202a..=0x202e | 0x2028 | 0x2029 | 0x2066..=0x2069 | 0xfeff)
    })
}

#[test]
fn hostile_text_in_a_record_and_a_pack_cannot_break_a_screen() {
    // Text from a record (its own issuer name) and from a policy pack (a rule's
    // reference) holding escape sequences, a right-to-left override, a
    // zero-width space, a byte order mark, a line separator, DEL, a C1 control
    // and a line break, drawn under --color always, beside emoji, wide
    // characters and combining marks (QA QP-05). The screens escape it
    // before they style or measure it: nothing of that class reaches stdout
    // raw, the only escape sequences are the screens' own (strip checks), and
    // every frame line keeps its width in terminal columns.
    const HOSTILE: &str = "\u{1b}[2J\u{1b}[31m\u{202e}\u{200b}\u{feff}\u{2028}\u{7f}\u{85}\r\n";
    let s = Scratch::new("rich-hostile-record-pack");
    let check = |run: &Run, what: &str| {
        let screen = strip(&run.stdout);
        if let Some(c) = raw_character(&screen) {
            panic!("{what}: a raw U+{:04X} reached stdout:\n{screen}", u32::from(c));
        }
        frames_are_even(&screen);
        assert!(screen.contains("\\u{202e}"), "{what}: the text is shown escaped:\n{screen}");
        assert!(screen.contains("\u{1fa7a}"), "{what}: the emoji is on the screen:\n{screen}");
    };

    // The record's own issuer name: among a failure's claims, and in inspect.
    let mut record = vector();
    record.issuer.issuer_name = format!("Evil{HOSTILE}{WIDE}{}", "x".repeat(120));
    let path = s.write("record.json", record.to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let failed = vmr(&["record", "verify", "--record", &path, "--trust-store", &store, "--at", T, "--color", "always"]);
    failed.expect_code(3);
    assert!(strip(&failed.stdout).contains("NOT VERIFIED"), "{}", failed.transcript());
    check(&failed, "record verify");
    let inspected = vmr(&["record", "inspect", "--record", &path, "--color", "always"]);
    inspected.expect_code(0);
    check(&inspected, "record inspect");

    // Every rule's reference of a pack, in the rules table.
    let (gate5_record, gate5_store) = gate5(&s);
    let mut pack: Value =
        serde_json::from_str(&std::fs::read_to_string(repo().join("specs/policy-packs/khalm-reading-eu-ai-act-2026.json")).unwrap()).unwrap();
    for rule in pack["rules"].as_array_mut().unwrap() {
        rule["reference"] = Value::String(format!("Art. 14(3){HOSTILE}{WIDE}{}", "y".repeat(90)));
    }
    pack.as_object_mut().unwrap().remove("signature");
    let pack = s.write("pack.json", serde_json::to_vec(&pack).unwrap());
    let evaluated = vmr(&[
        "record", "verify", "--record", &gate5_record, "--trust-store", &gate5_store, "--at", AT, "--policy-pack", &pack,
        "--color", "always",
    ]);
    evaluated.expect_code(0);
    check(&evaluated, "record verify --policy-pack");
}

/// A copy of the EU AI Act reference pack, edited, in the scratch directory.
fn eu_pack(s: &Scratch, name: &str, edit: impl FnOnce(&mut Value)) -> String {
    let mut pack: Value =
        serde_json::from_str(&std::fs::read_to_string(repo().join("specs/policy-packs/khalm-reading-eu-ai-act-2026.json")).unwrap()).unwrap();
    edit(&mut pack);
    s.write(name, serde_json::to_vec(&pack).unwrap())
}

#[test]
fn a_failing_rule_past_the_screens_bound_is_still_shown() {
    // QA QP-01: a pack of 40 rules whose one failing rule, made mandatory, is
    // the 40th (as QA/repro/cpa_common.py builds eu-40.json). The screen lists
    // the rules that did not pass first, so the rule that decided the result
    // and its reason are on it, and the row for the rest says what they found.
    let s = Scratch::new("rich-40-rules");
    let (record, store) = gate5(&s);
    let pack = eu_pack(&s, "eu-40.json", |pack| {
        let rules = pack["rules"].as_array().unwrap().clone();
        let passing: Vec<Value> = rules.iter().filter(|r| r["rule_id"] != "eu-ai-act-human-oversight").cloned().collect();
        let mut all: Vec<Value> = (0..34)
            .map(|k| {
                let mut r = passing[k % passing.len()].clone();
                r["rule_id"] = Value::String(format!("qa-copy-{k:02}-{}", r["rule_id"].as_str().unwrap()));
                r
            })
            .collect();
        let mut tail = rules;
        for r in &mut tail {
            if r["rule_id"] == "eu-ai-act-human-oversight" {
                r["severity"] = Value::String("mandatory".into());
            }
        }
        tail.sort_by_key(|r| r["rule_id"] == "eu-ai-act-human-oversight");
        all.extend(tail);
        pack["rules"] = Value::Array(all);
        pack["pack_id"] = Value::String("qa-many-rules".into());
    });
    let run = vmr(&[
        "record", "verify", "--record", &record, "--trust-store", &store, "--at", AT, "--policy-pack", &pack, "--color", "always",
    ]);
    run.expect_code(4);
    let screen = strip(&run.stdout);
    for want in ["eu-ai-act-human-oversight", "× fail", "no /human_oversight member", "… 8 more rules, all passed, not shown"] {
        assert!(screen.contains(want), "missing `{want}`:\n{screen}");
    }
    frames_are_even(&screen);
}

#[test]
fn a_verified_record_that_is_not_accepted_says_so_in_its_banner() {
    // QA QP-03 (the owner approved the second badge on 2026-09-15): a genuine
    // record the evaluation does not accept (exit 4) is headed by VALID and by
    // NOT ACCEPTED, inside the banner; a record the pack accepts is not.
    let s = Scratch::new("rich-not-accepted");
    let (record, store) = gate5(&s);
    let pack = eu_pack(&s, "eu-mandatory.json", |pack| {
        for r in pack["rules"].as_array_mut().unwrap() {
            r["severity"] = Value::String("mandatory".into());
        }
    });
    let banner = |screen: &str| -> Vec<String> {
        screen.lines().skip_while(|l| !l.contains('╭')).take_while(|l| !l.contains('╰')).map(str::to_string).collect()
    };
    let run = vmr(&[
        "record", "verify", "--record", &record, "--trust-store", &store, "--at", AT, "--policy-pack", &pack, "--color", "always",
    ]);
    run.expect_code(4);
    let screen = strip(&run.stdout);
    let lines = banner(&screen);
    assert!(lines.iter().any(|l| l.contains("√ VALID")), "{screen}");
    assert!(lines.iter().any(|l| l.contains("× NOT ACCEPTED")), "no NOT ACCEPTED in the banner:\n{screen}");
    let eu = repo().join("specs/policy-packs/khalm-reading-eu-ai-act-2026.json").display().to_string();
    let accepted = vmr(&[
        "record", "verify", "--record", &record, "--trust-store", &store, "--at", AT, "--policy-pack", &eu, "--color", "always",
    ]);
    accepted.expect_code(0);
    assert!(!strip(&accepted.stdout).contains("NOT ACCEPTED"), "{}", accepted.transcript());
}

#[test]
fn inspect_draws_a_key_id_as_the_record_states_it() {
    // QA QP-04: inspect shows a record's unchecked claims as the record states
    // them, so a key id without its prefix does not look like one with it.
    let s = Scratch::new("rich-inspect-key-id");
    let whole = vector();
    let mut bare = vector();
    bare.issuer.key_id = bare.issuer.key_id.trim_start_matches("urn:ietf:params:oauth:jwk-thumbprint:sha-256:").to_string();
    assert_ne!(bare.issuer.key_id, whole.issuer.key_id);
    let whole_path = s.write("whole.json", whole.to_json().unwrap());
    let bare_path = s.write("bare.json", bare.to_json().unwrap());
    let rows = |path: &str| -> Vec<String> {
        let run = vmr(&["record", "inspect", "--record", path, "--color", "always"]);
        run.expect_code(0);
        strip(&run.stdout).lines().filter(|l| l.contains("Signing key")).map(str::to_string).collect()
    };
    let (whole_rows, bare_rows) = (rows(&whole_path), rows(&bare_path));
    assert_ne!(whole_rows, bare_rows, "the two key ids are drawn alike");
    assert!(whole_rows.iter().all(|l| l.contains("urn:ietf:params:oauth:jwk-thumbprint:")), "{whole_rows:?}");
}

#[test]
fn the_error_of_a_json_run_is_plain_text() {
    // QA QP-06 (the reviewer's option A): a command that writes data a script
    // reads (--json, a public key to standard output) keeps its error plain,
    // even with --color always; without --json the same error is a screen.
    let s = Scratch::new("rich-json-error");
    let (_record, store) = gate5(&s);
    let missing = s.arg("nope.vmr");
    let data_runs: [Vec<&str>; 3] = [
        vec!["record", "verify", "--record", missing.as_str(), "--trust-store", store.as_str(), "--json", "--color", "always"],
        vec!["model", "hash", "--model", missing.as_str(), "--json", "--color", "always"],
        vec!["key", "export", "--key", missing.as_str(), "--color", "always"],
    ];
    for args in data_runs {
        let run = vmr(&args);
        run.expect_code(1);
        assert!(run.stderr.starts_with("vmr: error: ") && !run.stderr.contains(ESC), "{args:?}:\n{}", run.transcript());
    }
    let screen = vmr(&["record", "verify", "--record", &missing, "--trust-store", &store, "--color", "always"]);
    screen.expect_code(1);
    assert!(screen.stderr.contains(ESC) && strip(&screen.stderr).contains(" ERROR "), "{}", screen.transcript());
}

#[test]
fn the_help_and_version_screens_show_the_wordmark() {
    // docs/dev/cli-polish.md CP-3, CP-10: on a terminal, the tool's help and
    // version are a screen: the standard's logo; the tool's name and version as
    // a reference implementation of the standard; the commands in a bordered
    // table; examples; the exit codes in a line. Every name comes from
    // vmr_cli::names.
    let version = env!("CARGO_PKG_VERSION");
    let caption = format!("{TOOL} {version} \u{b7} a reference implementation of the standard");
    let example = format!("{TOOL} record verify --record model.{RECORD_EXTENSION} --trust-store trust-store.json");
    for args in [&["--help", "--color", "always"][..], &["-h", "--color", "always"]] {
        let run = vmr(args);
        run.expect_code(0);
        assert!(run.stdout.contains(ESC), "{}", run.transcript());
        let screen = strip(&run.stdout);
        for want in [
            LOGO_TOP,
            "Verifiable Model Record",
            caption.as_str(),
            "Records",
            "record emit",
            "record verify",
            "record inspect",
            "model hash",
            "key generate",
            "key export",
            "trust-store add",
            "Get started",
            example.as_str(),
            "0 done",
            "4 valid, not accepted by a policy pack",
        ] {
            assert!(screen.contains(want), "missing `{want}`:\n{screen}");
        }
        assert!(!screen.to_lowercase().contains("engine"), "{screen}");
        frames_are_even(&screen);
    }
    let run = vmr(&["--version", "--color", "always"]);
    run.expect_code(0);
    let screen = strip(&run.stdout);
    assert!(screen.contains(LOGO_TOP) && screen.contains(&caption), "{screen}");

    // Into a pipe, help and version draw neither the logo nor a screen's mark.
    for args in [&["--help"][..], &["-h"], &["--version"]] {
        let piped = vmr(args);
        piped.expect_code(0);
        assert!(!piped.stdout.contains(ESC) && !piped.stdout.contains(['\u{2588}', '\u{221a}', '\u{d7}']), "{}", piped.transcript());
    }

    // Into a pipe, the version stays clap's line, and a command's own help is
    // never a screen.
    assert_eq!(
        vmr(&["--version"]).stdout.trim_end(),
        format!("{TOOL} {version} (KHALM-VMR, a reference implementation of the Verifiable Model Record standard; record format v0.1)")
    );
    let own = vmr(&["record", "verify", "--help", "--color", "always"]);
    own.expect_code(0);
    assert!(!own.stdout.contains(ESC), "{}", own.transcript());

    // --ascii: no box-drawing or block character.
    let ascii = vmr(&["--help", "--color", "always", "--ascii"]);
    ascii.expect_code(0);
    let screen = strip(&ascii.stdout);
    assert!(!screen.chars().any(|c| ('\u{2500}'..='\u{259f}').contains(&c)), "box or block characters left:\n{screen}");
    frames_are_even(&screen);
}

/// A model folder of three files, and each file's name with its SHA-256 in hex.
fn small_model(s: &Scratch) -> (String, Vec<(&'static str, String)>) {
    let root = s.subdir("model");
    let files: [(&'static str, &[u8]); 3] =
        [("config.json", b"{}\n"), ("weights.safetensors", &[7u8; 3000]), ("tokenizer.json", b"{\"v\":1}\n")];
    let mut hashes = Vec::new();
    for (name, bytes) in files {
        std::fs::write(root.join(name), bytes).unwrap();
        let hex: String = vmr_record::hash::sha256(bytes).iter().map(|b| format!("{b:02x}")).collect();
        hashes.push((name, hex));
    }
    (root.to_string_lossy().into_owned(), hashes)
}

#[test]
fn model_hash_is_drawn_with_its_hash_and_a_table_of_its_files() {
    // docs/dev/cli-polish.md CP-3, CP-5: a MODEL HASH banner with the whole
    // model_hash, the file count and the size; a table of every file with its
    // readable size and its hash's first 12 hex digits; --full shows each
    // hash whole. The plain text and --json never change with --full.
    let s = Scratch::new("rich-model-hash");
    let (model, files) = small_model(&s);
    let plain = vmr(&["model", "hash", "--model", &model]);
    plain.expect_code(0);
    let model_hash = values(&plain.stdout).into_iter().next().unwrap();
    let rich = vmr(&["model", "hash", "--model", &model, "--color", "always"]);
    rich.expect_code(0);
    let screen = strip(&rich.stdout);
    for want in ["MODEL HASH", model_hash.as_str(), "3 files", "2.9 KiB", "--full or --json"] {
        assert!(screen.contains(want), "missing `{want}`:\n{screen}");
    }
    for (name, hex) in &files {
        assert!(screen.contains(name), "missing `{name}`:\n{screen}");
        assert!(screen.contains(&format!("{}\u{2026}", &hex[..12])), "missing the shortened hash of {name}:\n{screen}");
        assert!(!screen.contains(hex.as_str()), "the whole hash of {name} without --full:\n{screen}");
    }
    frames_are_even(&screen);

    let full = vmr(&["model", "hash", "--model", &model, "--color", "always", "--full"]);
    full.expect_code(0);
    let screen = strip(&full.stdout);
    for (name, hex) in &files {
        assert!(screen.contains(hex.as_str()), "missing the whole hash of {name} with --full:\n{screen}");
    }
    assert!(!screen.contains("--full or --json"), "{screen}");
    frames_are_even(&screen);

    assert_eq!(vmr(&["model", "hash", "--model", &model, "--full"]).stdout, plain.stdout);
    let json = vmr(&["model", "hash", "--model", &model, "--json"]);
    json.expect_code(0);
    assert_eq!(vmr(&["model", "hash", "--model", &model, "--json", "--full", "--color", "always"]).stdout, json.stdout);
}

#[test]
fn emit_is_drawn_signed_with_the_issuers_statements_declared_and_its_files() {
    // docs/dev/cli-polish.md CP-3, CP-4, CP-5: SIGNED as a neutral badge, never
    // green; the record's id, its time and where that came from, and its key;
    // every statement of the issuer under DECLARED; the model's hash and its
    // files; numbered next steps whose command names <FILE> and the tool.
    let s = Scratch::new("rich-emit");
    let (model, files) = small_model(&s);
    let key = write_test_key(&s, "issuer.pem", "khalm-vmr vmr-cli rich emit test key (test-only)");
    let manifest = serde_json::json!({
        "manifest_version": "0.1",
        "issuer": { "issuer_id": "did:web:example.org", "issuer_name": "Example issuer", "attestation_level": "software" },
        "model_format": "safetensors",
        "model": { "architecture": { "type": "transformer", "topology": "decoder-only", "precision": "bfloat16" }, "parameter_count": 1280 },
        "training": {
            "environment": { "hardware_id": "", "tee_measurement": "", "software_hash": "", "training_software": "" },
            "input_provenance": { "source_type": "", "source_description": "" },
            "input_disclosure": "not-held"
        },
        "policy_compliance": { "policy_pack_id": "example-policy-pack-v1", "evaluated_at": "2026-09-14T00:00:00Z", "results": [], "overall_status": "indeterminate" },
        "lineage": { "lineage_type": "initial" }
    });
    let manifest_value = manifest;
    let manifest = s.write("manifest.json", serde_json::to_vec(&manifest_value).unwrap());
    let out = s.arg(&format!("record.{RECORD_EXTENSION}"));
    let emit = |output: &str, extra: &[&str]| {
        let mut args = vec![
            "record", "emit", "--model", &model, "--manifest", &manifest, "--key", &key, "--output", output,
            "--issued-at", "2026-09-14T00:00:00Z",
        ];
        args.extend_from_slice(extra);
        vmr(&args)
    };
    let run = emit(&out, &["--color", "always"]);
    run.expect_code(0);
    assert!(run.stdout.contains("\u{1b}[1;30;46m SIGNED "), "SIGNED is a neutral badge:\n{}", run.transcript());
    assert!(!run.stdout.contains("\u{1b}[1;30;42m"), "nothing is green on a record just signed:\n{}", run.transcript());
    let screen = strip(&run.stdout);
    let record = vmr_record::Record::from_cose(&std::fs::read(&out).unwrap()).unwrap();
    let thumbprint = record.issuer.key_id.trim_start_matches("urn:ietf:params:oauth:jwk-thumbprint:sha-256:").to_string();
    let next = format!("{TOOL} record verify --record <FILE> --trust-store <FILE>");
    for want in [
        "SIGNED",
        record.record_id.as_str(),
        record.model_identity.model_hash.as_str(),
        "from --issued-at",
        thumbprint.as_str(),
        "DECLARED",
        "did:web:example.org",
        "\"safetensors\"",
        "\"indeterminate\"",
        "not evaluated",
        "Next",
        next.as_str(),
    ] {
        assert!(screen.contains(want), "missing `{want}`:\n{screen}");
    }
    for (name, hex) in &files {
        assert!(screen.contains(name) && screen.contains(&format!("{}\u{2026}", &hex[..12])), "missing {name}:\n{screen}");
    }
    frames_are_even(&screen);

    // QA QPB-05: the screen states what the plain text states about the files
    // read: the exact byte total and the folder. A long path may wrap in its
    // cell, so it is looked for with the frame and the spaces taken out.
    let squeezed = |text: &str| text.chars().filter(|c| !c.is_whitespace() && *c != '\u{2502}').collect::<String>();
    assert!(screen.contains("3011 bytes"), "missing the byte total:\n{screen}");
    assert!(squeezed(&screen).contains(&squeezed(&model)), "missing the folder read:\n{screen}");
    let records = s.subdir("records");
    std::fs::write(records.join("shard-0.jsonl"), b"record 0\n").unwrap();
    let mut with_records = manifest_value.clone();
    with_records["training"].as_object_mut().unwrap().remove("input_disclosure");
    let with_records = s.write("manifest-records.json", serde_json::to_vec(&with_records).unwrap());
    let records_arg = records.to_string_lossy().into_owned();
    let run = vmr(&[
        "record", "emit", "--model", &model, "--manifest", &with_records, "--key", &key, "--output", &s.arg("records.vmr"),
        "--issued-at", "2026-09-14T00:00:00Z", "--training-records", &records_arg, "--color", "always",
    ]);
    run.expect_code(0);
    let screen = strip(&run.stdout);
    assert!(squeezed(&screen).contains(&squeezed(&records_arg)), "missing the training records' folder:\n{screen}");

    // Into a pipe, emit's plain text is as it was.
    let plain = emit(&s.arg("plain.json"), &["--format", "json"]);
    plain.expect_code(0);
    assert!(plain.stdout.starts_with("Emitted record: ") && !plain.stdout.contains(ESC), "{}", plain.transcript());
}
