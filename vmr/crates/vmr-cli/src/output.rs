//! Writing a command's outcome — its output on stdout or its error on
//! stderr — and choosing the exit code.
// ============================================================================
//  output.rs — the only place the CLI writes to the terminal
//
//  `println!` panics when stdout is a closed pipe (`vmr ... | head -1`); a
//  CLI must never panic (Law 9). Each command therefore builds its output
//  as a String, and it is written here once, with every write error handled.
//  An error's message and hint are escaped here once more on their way to
//  stderr (error_text): the last line of defence against a raw control
//  character from a file reaching the terminal.
//
//  A command may also build the screen a terminal gets (screens.rs,
//  docs/dev/cli-polish.md CP-2). view.rs decides per stream which one is
//  written: the screen on a terminal or with --color always, the plain text
//  everywhere else. A screen goes through anstream, which keeps its colour
//  (in a Windows console too) or strips it (NO_COLOR, --color never); its
//  text was escaped before it was styled, so stripping it gives nothing a
//  terminal acts on.
// ============================================================================

use crate::error::{CliError, EXIT_INPUT, EXIT_OK};
use crate::names::TOOL;
use crate::rich::{self, Line};
use crate::screens;
use crate::view::View;
use std::io::Write;
use std::process::ExitCode;
use vmr_verify::escape_controls;

/// What a command produced: text for stdout, its terminal screen, and the
/// exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Everything for stdout, as a pipe, a file or a script gets it.
    pub stdout: String,
    /// The same result as a terminal screen, when the command draws one.
    pub rich: Option<Vec<Line>>,
    /// The exit code: 0 unless the command's result says otherwise (a
    /// failed verification exits 3).
    pub code: u8,
}

impl Output {
    /// Output of a command that did its job (exit 0).
    pub fn ok(stdout: String) -> Self {
        Output { stdout, rich: None, code: EXIT_OK }
    }

    /// The same output, with the screen a terminal gets.
    pub fn with_rich(mut self, screen: Vec<Line>) -> Self {
        self.rich = Some(screen);
        self
    }
}

/// Write the outcome, as `view` says, and return its exit code.
pub fn finish(result: Result<Output, CliError>, view: View) -> ExitCode {
    match result {
        Ok(out) => {
            let written = match &out.rich {
                Some(screen) if view.rich_stdout() => {
                    write_screen_stdout(&rich::render(screen, view.ascii), view)
                }
                _ => {
                    let mut stdout = std::io::stdout().lock();
                    stdout.write_all(out.stdout.as_bytes()).and_then(|()| stdout.flush())
                }
            };
            match written {
                Ok(()) => ExitCode::from(out.code),
                Err(e) => {
                    to_stderr(&format!("{TOOL}: error: cannot write to standard output: {e}\n"));
                    ExitCode::from(EXIT_INPUT)
                }
            }
        }
        Err(e) => {
            if view.rich_stderr() {
                let hint = e.hint.as_ref().map(|h| escape_controls(h.clone()));
                let screen = screens::error(&escape_controls(e.message.clone()), hint.as_deref());
                if write_screen_stderr(&rich::render(&screen, view.ascii), view).is_err() {
                    // stderr cannot be written: the exit code still says what happened.
                }
            } else {
                to_stderr(&error_text(&e));
            }
            ExitCode::from(e.code)
        }
    }
}

/// Write a rendered screen to stdout through anstream, with the view's
/// colour choice.
fn write_screen_stdout(text: &str, view: View) -> std::io::Result<()> {
    let mut stream = anstream::AutoStream::new(std::io::stdout(), view.choice());
    stream.write_all(text.as_bytes())?;
    stream.flush()
}

/// Write a rendered screen to stderr through anstream, with the view's
/// colour choice for stderr (QA QP-02: none on a Windows console whose
/// stdout is redirected).
fn write_screen_stderr(text: &str, view: View) -> std::io::Result<()> {
    let mut stream = anstream::AutoStream::new(std::io::stderr(), view.stderr_choice());
    stream.write_all(text.as_bytes())?;
    stream.flush()
}

/// What stderr shows for `e`: `vmr: error: <message>` and, if any, a
/// `  hint: <hint>` line — each escaped with vmr-verify's `escape_controls`,
/// the last line of defence. Messages quote text from files and from the
/// system (a loader's detail, an OS error, an engine message) and every
/// command escapes what it quotes; this catches whatever one missed. It
/// escapes the same characters as `display_safe`, but keeps backslashes
/// (a Windows path) and never escapes an escape twice.
fn error_text(e: &CliError) -> String {
    let mut text = format!("{TOOL}: error: {}\n", escape_controls(e.message.clone()));
    if let Some(hint) = &e.hint {
        text.push_str(&format!("  hint: {}\n", escape_controls(hint.clone())));
    }
    text
}

/// Parsing the command line failed, or asked for `--help` / `--version`.
/// clap's text is rendered here and written like every other outcome: help
/// and version to stdout, exit 0; a usage error to stderr, escaped (QA
/// P5-03: clap quotes the offending argument, which may hold anything), exit
/// 1 - not clap's 2, which this CLI reserves for engine errors
/// (docs/dev/phase5.md C10). `args` is the command line, as text; the view
/// is read from it by hand, since clap refused it.
///
/// `tree` is the command tree this build parses. The tool's own help and
/// version, asked at the top level, get their screens from it (CP-3, CP-11);
/// a command's own help stays clap's text on every stream.
pub fn clap_outcome(e: &clap::Error, args: &[String], tree: &clap::Command) -> ExitCode {
    let view = View::scan(args);
    let text = e.render().to_string();
    let screen = top_level_screen(e.kind(), args, tree);
    if e.use_stderr() {
        let safe = clap_error_text(&text, args);
        if view.rich_stderr() {
            let lines = screen.unwrap_or_else(|| screens::usage_error(&safe));
            if write_screen_stderr(&rich::render(&lines, view.ascii), view).is_err() {
                // stderr cannot be written: the exit code still says what happened.
            }
        } else {
            to_stderr(&safe);
        }
        ExitCode::from(EXIT_INPUT)
    } else {
        let out = Output::ok(text);
        finish(Ok(match screen { Some(lines) => out.with_rich(lines), None => out }), view)
    }
}

/// The help or version screen for the tool's own help or version, asked at
/// the top level (`view::top_level`): `--help`, `-h`, no arguments at all,
/// `--version` or `-V`.
fn top_level_screen(kind: clap::error::ErrorKind, args: &[String], tree: &clap::Command) -> Option<Vec<Line>> {
    use clap::error::ErrorKind;
    if !crate::view::top_level(args) {
        return None;
    }
    match kind {
        ErrorKind::DisplayHelp | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => Some(screens::help(tree)),
        ErrorKind::DisplayVersion => Some(screens::version(tree)),
        _ => None,
    }
}

/// clap's rendered usage error with nothing a terminal acts on or hides:
/// every argument clap may quote that holds such a character - the argument,
/// or the value after `=` of `--option=value` - is escaped whole with
/// `escape_controls`, a line break inside it included (so it cannot start a
/// line of its own); then every line of the message is escaped, keeping
/// clap's own line breaks.
fn clap_error_text(text: &str, args: &[String]) -> String {
    let unsafe_text = |s: &str| escape_controls(s.to_string()) != s;
    let mut quoted: Vec<&str> = Vec::new();
    for arg in args {
        quoted.push(arg);
        if let Some((_, value)) = arg.strip_prefix('-').and_then(|a| a.split_once('=')) {
            quoted.push(value);
        }
    }
    quoted.retain(|s| unsafe_text(s));
    // The longest first, so a value never breaks up its own argument.
    quoted.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut text = text.to_string();
    for s in quoted {
        text = text.replace(s, &escape_controls(s.to_string()));
    }
    text.split('\n').map(|line| escape_controls(line.to_string())).collect::<Vec<_>>().join("\n")
}

/// Write a loading bar's text to stderr (docs/dev/cli-polish.md CP-6), before
/// the command's outcome is written. Best effort: a bar that cannot be drawn
/// changes nothing.
pub fn progress_to_stderr(text: &str) {
    let mut stderr = std::io::stderr().lock();
    write_progress(&mut stderr, text);
}

/// Write the bar's text and flush. The stream is standard error by type, so
/// the bar cannot be sent to standard output (QA QPB-01).
fn write_progress(stderr: &mut std::io::StderrLock<'_>, text: &str) {
    if stderr.write_all(text.as_bytes()).is_ok() && stderr.flush().is_err() {
        // The bar is not part of the outcome; nothing more to do.
    }
}

/// Write to stderr. When stderr itself cannot be written there is nowhere
/// left to report that; the exit code still says what happened.
fn to_stderr(text: &str) {
    let mut stderr = std::io::stderr().lock();
    if stderr.write_all(text.as_bytes()).is_ok() && stderr.flush().is_err() {
        // Same: a failed flush of stderr has no further recipient.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_and_its_hint_reach_the_terminal_escaped() {
        // The last line of defence: whatever a command put in its message or
        // hint - a loader's detail, an OS error, an engine message - stderr
        // shows it with nothing a terminal acts on or hides: ESC, CR, a bidi
        // override, a zero-width space. The rest, a path's backslashes
        // included, is kept as it is.
        let e = CliError::input("trust store 'C:\\x\\ts.json' cannot be used: unknown field `\u{1b}[2J\u{202e}\u{200b}`")
            .with_hint("see \u{1b}[32m\u{2713}\r");
        assert_eq!(
            error_text(&e),
            "vmr: error: trust store 'C:\\x\\ts.json' cannot be used: unknown field `\\u{001b}[2J\\u{202e}\\u{200b}`\n  \
             hint: see \\u{001b}[32m\u{2713}\\u{000d}\n"
        );
    }

    #[test]
    fn a_clap_error_keeps_its_lines_and_escapes_what_it_quotes() {
        // clap's structure (the message, a blank line, the usage) survives;
        // the quoted argument's ESC, RLO and even its line break do not.
        let arg = "x\u{1b}[2J\n\u{2713} Record valid\u{202e}".to_string();
        let text = format!(
            "error: unexpected argument '{arg}' found\n\nUsage: vmr record verify [OPTIONS]\n\nFor more information, try '--help'.\n"
        );
        let shown = clap_error_text(&text, &["vmr".into(), "record".into(), arg]);
        assert_eq!(
            shown,
            "error: unexpected argument 'x\\u{001b}[2J\\u{000a}\u{2713} Record valid\\u{202e}' found\n\n\
             Usage: vmr record verify [OPTIONS]\n\nFor more information, try '--help'.\n"
        );
        // A value after `=` is quoted alone by clap: escaped the same way.
        let text = "error: invalid value 'a\u{1b}b' for '--at <T>': not a timestamp\n";
        assert_eq!(
            clap_error_text(text, &["--at=a\u{1b}b".into()]),
            "error: invalid value 'a\\u{001b}b' for '--at <T>': not a timestamp\n"
        );
        // Text without such characters is clap's own, byte for byte.
        let plain = "error: unexpected argument '--frobnicate' found\n\nUsage: vmr <COMMAND>\n";
        assert_eq!(clap_error_text(plain, &["--frobnicate".into()]), plain);
    }

    #[test]
    fn escaped_text_passes_unchanged() {
        // Text that is already terminal-safe - a display_safe value, a report
        // detail, a path - is not escaped twice and keeps its backslashes, so
        // the escaping can run over every message whatever built it.
        let already = format!("{} in 'C:\\Users\\demo'", vmr_verify::display_safe("a\u{1b}b\\c"));
        assert_eq!(error_text(&CliError::input(already.clone())), format!("vmr: error: {already}\n"));
        let once = error_text(&CliError::input("x\u{1b}y\u{202e}z"));
        let message = once.trim_start_matches("vmr: error: ").trim_end_matches('\n');
        assert_eq!(error_text(&CliError::input(message)), once, "idempotent");
    }

    #[test]
    fn an_error_screen_and_a_usage_screen_hold_nothing_raw() {
        let screen = screens::error("cannot read record 'x': \\u{001b}[2J", Some("check the path"));
        let text = rich::strip(&rich::render(&screen, false));
        assert!(text.contains(" ERROR ") && text.contains("hint") && crate::mutate::terminal_safe(&text), "{text}");
        let usage = clap_error_text(
            "error: unexpected argument '--trust-stor' found\n\n  tip: a similar argument exists: '--trust-store'\n\nUsage: vmr record verify\n",
            &[],
        );
        let text = rich::strip(&rich::render(&screens::usage_error(&usage), false));
        assert!(text.contains(" ERROR ") && text.contains("--trust-store") && text.contains("Usage:"), "{text}");
    }
}
