//! Which rendering a stream gets, and whether it is coloured
//! (docs/dev/cli-polish.md CP-2, CP-4).
// ============================================================================
//  view.rs — the terminal screens, or the plain text, per stream
//
//  A stream gets the rich screens (rich.rs, screens.rs) when --color always
//  asks for them, or when it is a terminal whose TERM is not "dumb". Every
//  other stream, a pipe, a file, a script and every test that runs the
//  binary, gets the plain text, byte for byte what vmr printed before.
//  Whether a screen is coloured is anstream's decision from the same
//  --color: auto follows NO_COLOR, CLICOLOR, CLICOLOR_FORCE and the
//  terminal. Those environment reads are anstyle-query's, inside the
//  dependency; the plain text never depends on them.
//
//  Two cases keep their plain text or their colour off (QA QP-06, QP-02). A
//  command that writes data a script reads (--json, a public key to standard
//  output) keeps its error plain text. And on Windows, an error screen on a
//  console whose standard output is redirected is drawn without colour:
//  anstream switches escape-code processing on through standard output
//  first, stops at its error, and would pass codes a console then prints.
// ============================================================================

use crate::cli::ColorArg;
use std::io::IsTerminal;

/// The presentation options of one command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct View {
    /// `--color`.
    pub color: ColorArg,
    /// `--ascii`: borders and marks in plain ASCII.
    pub ascii: bool,
    /// The command writes data a script reads: its error stays plain text.
    pub data: bool,
}

impl View {
    /// The options as clap parsed them.
    pub fn new(color: ColorArg, ascii: bool) -> View {
        View { color, ascii, data: false }
    }

    /// The same view for a command that writes data a script reads (`--json`,
    /// a public key to standard output), or not (QA QP-06).
    pub fn with_data(mut self, data: bool) -> View {
        self.data = data;
        self
    }

    /// The options of a command line clap refused, so that its usage error
    /// is drawn as the line asked: `--color WHEN`, `--color=WHEN`, `--ascii`
    /// and `--json`, read up to a `--`. A value that is not one of the three
    /// leaves the default.
    pub fn scan(args: &[String]) -> View {
        let mut view = View::new(ColorArg::Auto, false);
        let mut words = args.iter().skip(1);
        while let Some(word) = words.next() {
            match word.as_str() {
                "--" => break,
                "--ascii" => view.ascii = true,
                "--json" => view.data = true,
                "--color" => {
                    if let Some(value) = words.next() {
                        view.color = parse(value).unwrap_or(view.color);
                    }
                }
                other => {
                    if let Some(value) = other.strip_prefix("--color=") {
                        view.color = parse(value).unwrap_or(view.color);
                    }
                }
            }
        }
        view
    }

    /// Whether standard output gets the rich screens.
    pub fn rich_stdout(self) -> bool {
        rich_layout(self.color, std::io::stdout().is_terminal(), anstyle_query::term_supports_color())
    }

    /// Whether standard error gets the rich screens: never for a command that
    /// writes data (QA QP-06).
    pub fn rich_stderr(self) -> bool {
        !self.data && rich_layout(self.color, std::io::stderr().is_terminal(), anstyle_query::term_supports_color())
    }

    /// anstream's colour choice for a rich screen.
    pub fn choice(self) -> anstream::ColorChoice {
        match self.color {
            ColorArg::Auto => anstream::ColorChoice::Auto,
            ColorArg::Always => anstream::ColorChoice::Always,
            ColorArg::Never => anstream::ColorChoice::Never,
        }
    }

    /// anstream's colour choice for a screen on standard error (QA QP-02).
    pub fn stderr_choice(self) -> anstream::ColorChoice {
        stderr_colour(self.choice(), cfg!(windows), std::io::stdout().is_terminal(), std::io::stderr().is_terminal())
    }
}

/// The colour choice for a screen on standard error: `choice`, except on
/// Windows when standard error is a console and standard output is not.
/// That screen is drawn without colour, with the same layout and words,
/// since anstream would pass escape codes to a console that prints them.
pub fn stderr_colour(
    choice: anstream::ColorChoice,
    windows: bool,
    stdout_terminal: bool,
    stderr_terminal: bool,
) -> anstream::ColorChoice {
    if windows && stderr_terminal && !stdout_terminal {
        anstream::ColorChoice::Never
    } else {
        choice
    }
}

/// Whether a command line asks for the tool's own help or version at the top
/// level: no word but `--help`, `-h`, `--version`, `-V`, `--ascii`, and
/// `--color` with its value (docs/dev/cli-polish.md CP-3). A command's own
/// help, `help` and a line with any other word do not.
pub fn top_level(args: &[String]) -> bool {
    let mut words = args.iter().skip(1);
    while let Some(word) = words.next() {
        if word == "--color" {
            words.next();
            continue;
        }
        if !(matches!(word.as_str(), "--help" | "-h" | "--version" | "-V" | "--ascii") || word.starts_with("--color=")) {
            return false;
        }
    }
    true
}

fn parse(value: &str) -> Option<ColorArg> {
    match value {
        "auto" => Some(ColorArg::Auto),
        "always" => Some(ColorArg::Always),
        "never" => Some(ColorArg::Never),
        _ => None,
    }
}

/// Whether a stream gets the rich screens: always with `--color always`;
/// otherwise only a terminal whose TERM is not "dumb", coloured or not.
pub fn rich_layout(color: ColorArg, is_terminal: bool, term_supports_color: bool) -> bool {
    match color {
        ColorArg::Always => true,
        ColorArg::Auto | ColorArg::Never => is_terminal && term_supports_color,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anstream::ColorChoice;

    #[test]
    fn the_rich_screens_go_to_a_terminal_or_where_always_sends_them() {
        for color in [ColorArg::Auto, ColorArg::Never] {
            assert!(rich_layout(color, true, true));
            assert!(!rich_layout(color, false, true), "a pipe gets the plain text");
            assert!(!rich_layout(color, true, false), "TERM=dumb gets the plain text");
        }
        assert!(rich_layout(ColorArg::Always, false, false));
    }

    #[test]
    fn a_refused_command_line_is_scanned_for_its_view() {
        let line = |words: &[&str]| View::scan(&words.iter().map(|w| w.to_string()).collect::<Vec<_>>());
        assert_eq!(line(&["vmr", "record", "verify"]), View::new(ColorArg::Auto, false));
        assert_eq!(line(&["vmr", "--color", "always", "--ascii"]), View::new(ColorArg::Always, true));
        assert_eq!(line(&["vmr", "x", "--color=never"]), View::new(ColorArg::Never, false));
        assert_eq!(line(&["vmr", "--color", "sometimes"]), View::new(ColorArg::Auto, false));
        assert_eq!(line(&["vmr", "--", "--color", "always"]), View::new(ColorArg::Auto, false));
        assert_eq!(line(&["vmr", "--color"]), View::new(ColorArg::Auto, false));
        assert_eq!(line(&["vmr", "record", "verify", "--json"]), View::new(ColorArg::Auto, false).with_data(true));
    }

    #[test]
    fn only_the_tools_own_help_and_version_are_top_level() {
        let line = |words: &[&str]| top_level(&words.iter().map(|w| w.to_string()).collect::<Vec<_>>());
        assert!(line(&["vmr"]));
        assert!(line(&["vmr", "--help"]));
        assert!(line(&["vmr", "-h", "--color", "always", "--ascii"]));
        assert!(line(&["vmr", "--color=never", "-V"]));
        assert!(!line(&["vmr", "record", "verify", "--help"]));
        assert!(!line(&["vmr", "help"]));
        assert!(!line(&["vmr", "--frobnicate", "--help"]));
    }

    #[test]
    fn each_color_option_is_anstreams_choice_of_the_same_name() {
        // QA QP-08: --color never must never colour, and auto must leave
        // NO_COLOR, CLICOLOR and the terminal to anstream.
        assert_eq!(View::new(ColorArg::Auto, false).choice(), ColorChoice::Auto);
        assert_eq!(View::new(ColorArg::Always, false).choice(), ColorChoice::Always);
        assert_eq!(View::new(ColorArg::Never, false).choice(), ColorChoice::Never);
    }

    #[test]
    fn an_error_screen_on_a_windows_console_with_stdout_redirected_is_not_coloured() {
        // QA QP-02: only that one case changes; every other keeps the choice.
        for choice in [ColorChoice::Auto, ColorChoice::Always, ColorChoice::Never] {
            assert_eq!(stderr_colour(choice, true, false, true), ColorChoice::Never);
            assert_eq!(stderr_colour(choice, true, true, true), choice);
            assert_eq!(stderr_colour(choice, true, false, false), choice);
            assert_eq!(stderr_colour(choice, false, false, true), choice);
        }
    }

    #[test]
    fn a_data_command_keeps_its_error_plain() {
        // QA QP-06: whatever --color says.
        for color in [ColorArg::Auto, ColorArg::Always, ColorArg::Never] {
            assert!(!View::new(color, false).with_data(true).rich_stderr());
        }
    }
}
