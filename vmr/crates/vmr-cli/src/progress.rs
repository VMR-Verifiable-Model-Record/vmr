//! The loading bar a terminal gets while a model's files are read
//! (docs/dev/cli-polish.md CP-6).
// ============================================================================
//  progress.rs — percent, bytes read and file N of M, on standard error
//
//  The bar observes vmr-builder's walk (WalkObserver) and changes nothing the
//  walk reads. `run` gives a command a bar that draws only when standard error
//  is a terminal whose TERM supports colour and the command writes no data a
//  script reads (`draws`). The bar is layout, not colour, so NO_COLOR and
//  --color never draw it too (CP-4; QA QPB-04). It shows only once 64 MiB are
//  read, then again per file and every 64 MiB: it reads no clock, so it says no
//  time remaining (CP-8). It is one line of at most 79 columns, so that an
//  80-column terminal never wraps it; each redraw after a carriage return is
//  padded to the last line's width only, and the erase before the result is
//  that wide (QA QPB-02). It writes no escape sequence.
// ============================================================================

use crate::rich::{human_size, width};
use vmr_builder::files::WalkObserver;

/// Bytes read before the bar first shows, and between its redraws.
const STEP: u64 = 64 << 20;

/// The bar's cells.
const CELLS: u64 = 20;

/// The most columns a text of the bar takes: an 80-column terminal never wraps it.
const MAX_COLUMNS: usize = 79;

/// A loading bar that hands each line to draw to `write`, or draws nothing.
pub struct Bar<W: FnMut(&str)> {
    write: Option<W>,
    ascii: bool,
    files: u64,
    total: Option<u64>,
    index: u64,
    read: u64,
    next: u64,
    /// The columns the terminal's line holds since the bar was drawn: what a
    /// redraw and the erase must cover.
    covered: usize,
    drawn: bool,
}

/// The bar a command line gets.
pub type StderrBar = Bar<fn(&str)>;

/// Whether the bar is drawn: only on a standard error that is a terminal whose
/// TERM supports colour, and never for a command that writes data a script
/// reads (QA QP-06's rule). The colour choice is not an input: with NO_COLOR or
/// --color never the bar is drawn as the screens are (CP-4; QA QPB-01, QPB-04).
pub fn draws(data: bool, stderr_terminal: bool, term_supports_color: bool) -> bool {
    !data && stderr_terminal && term_supports_color
}

/// The bar for standard error, drawn when `draw` (from [`draws`]) says so.
pub fn stderr_bar(ascii: bool, draw: bool) -> StderrBar {
    Bar::new(draw.then_some(crate::output::progress_to_stderr as fn(&str)), ascii)
}

impl<W: FnMut(&str)> Bar<W> {
    /// A bar drawn through `write` (`None`: never drawn), with `#` and `-`
    /// when `ascii`.
    pub fn new(write: Option<W>, ascii: bool) -> Self {
        Bar { write, ascii, files: 0, total: None, index: 0, read: 0, next: STEP, covered: 0, drawn: false }
    }

    /// Erase the bar, if it is drawn, before the command writes anything.
    pub fn finish(&mut self) {
        if self.drawn {
            self.emit(&format!("\r{}\r", " ".repeat(self.covered)));
            self.covered = 0;
            self.drawn = false;
        }
    }

    fn emit(&mut self, text: &str) {
        if let Some(write) = self.write.as_mut() {
            write(text);
        }
    }

    fn draw(&mut self) {
        if self.write.is_none() || self.read < STEP {
            return;
        }
        let mut line = self.line();
        let used = width(&line);
        if used < self.covered {
            line.push_str(&" ".repeat(self.covered - used));
        }
        self.covered = self.covered.max(used);
        self.emit(&format!("\r{line}"));
        self.drawn = true;
    }

    /// The line as drawn: the cells, percent, bytes read of the total, and
    /// the file; at most [`MAX_COLUMNS`] columns.
    fn line(&self) -> String {
        let (full, empty) = if self.ascii { ("#", "-") } else { ("\u{2588}", "\u{2591}") };
        let (filled, amount) = match self.total {
            Some(total) if total > 0 => {
                let read = self.read.min(total);
                let filled = u128::from(read) * u128::from(CELLS) / u128::from(total);
                let percent = u128::from(read) * 100 / u128::from(total);
                (filled as u64, format!("{percent:>3}%  {} of {}", human_size(read), human_size(total)))
            }
            _ => (0, human_size(self.read)),
        };
        let mut line = format!(
            "  {}{}  {amount}  \u{b7}  file {} of {}",
            full.repeat(filled as usize),
            empty.repeat(CELLS.saturating_sub(filled) as usize),
            self.index.saturating_add(1),
            self.files
        );
        while width(&line) > MAX_COLUMNS {
            line.pop();
        }
        line
    }
}

impl<W: FnMut(&str)> WalkObserver for Bar<W> {
    /// Only a bar that can draw asks for the total, which costs the walk a
    /// read of every file's size (QA QPB-03).
    fn wants_total(&self) -> bool {
        self.write.is_some()
    }

    fn listed(&mut self, files: u64, total_bytes: Option<u64>) {
        self.files = files;
        self.total = total_bytes;
        self.read = 0;
        self.next = STEP;
    }

    fn file_started(&mut self, index: u64, _name: &str, _size: u64) {
        self.index = index;
        if self.drawn {
            self.draw();
        }
    }

    fn bytes_read(&mut self, n: u64) {
        self.read = self.read.saturating_add(n);
        if self.read >= self.next {
            self.next = (self.read / STEP).saturating_add(1).saturating_mul(STEP);
            self.draw();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every text a bar hands to its writer while files of `sizes` are read.
    fn drawn(ascii: bool, sizes: &[u64]) -> Vec<String> {
        let mut texts = Vec::new();
        {
            let mut bar = Bar::new(Some(|text: &str| texts.push(text.to_string())), ascii);
            bar.listed(sizes.len() as u64, Some(sizes.iter().sum()));
            for (i, size) in sizes.iter().enumerate() {
                bar.file_started(i as u64, "weights.bin", *size);
                let mut left = *size;
                while left > 0 {
                    let n = left.min(1 << 20);
                    bar.bytes_read(n);
                    left -= n;
                }
            }
            bar.finish();
        }
        texts
    }

    #[test]
    fn a_model_under_64_mib_draws_nothing() {
        assert!(drawn(false, &[10 << 20, 20 << 20, 0]).is_empty());
    }

    #[test]
    fn a_large_model_draws_per_file_and_every_64_mib_then_erases_itself() {
        let texts = drawn(false, &[100 << 20, 60 << 20]);
        let (erase, lines) = texts.split_last().unwrap();
        assert!(lines.len() >= 3, "{lines:?}");
        assert!(lines[0].contains(" 40%  64.0 MiB of 160.0 MiB") && lines[0].contains("file 1 of 2"), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("file 2 of 2")), "{lines:?}");
        for line in lines {
            assert!(line.starts_with('\r') && !line.contains('\u{1b}'), "{line:?}");
        }
        let widest = lines.iter().map(|l| width(l.trim_start_matches('\r'))).max().unwrap();
        assert_eq!(erase, &format!("\r{}\r", " ".repeat(widest)), "the erase covers the widest line");
    }

    #[test]
    fn a_shorter_redraw_is_padded_over_the_longer_line_before_it() {
        // QA QPB-02: "960.0 MiB" read is wider than the "1.0 GiB" after it; the
        // redraw covers the longer line, so no character of it stays behind.
        let texts = drawn(false, &[1100 << 20]);
        let (_, lines) = texts.split_last().unwrap();
        let at = lines.iter().position(|l| l.contains("%  960.0 MiB of")).unwrap();
        assert!(lines[at + 1].contains("%  1.0 GiB of"), "{lines:?}");
        let widths: Vec<usize> = lines.iter().map(|l| width(l.trim_start_matches('\r'))).collect();
        assert!(widths.windows(2).all(|w| w[1] >= w[0]), "{widths:?}");
    }

    #[test]
    fn the_bar_is_drawn_only_on_a_terminal_for_a_command_that_writes_no_data() {
        // QA QPB-01, QPB-04: a terminal whose TERM supports colour, and a
        // command that writes no data a script reads. NO_COLOR and --color
        // never are not inputs: the bar has no colour, so they draw it too, as
        // they draw the screens (CP-4).
        assert!(draws(false, true, true), "a terminal, NO_COLOR or --color never included");
        assert!(!draws(true, true, true), "a --json run");
        assert!(!draws(false, false, true), "standard error redirected");
        assert!(!draws(false, true, false), "TERM=dumb");
    }

    #[test]
    fn only_a_bar_that_can_draw_asks_the_walk_for_its_total() {
        // QA QPB-03.
        assert!(Bar::new(Some(|_: &str| {}), false).wants_total());
        assert!(!StderrBar::new(None, false).wants_total());
    }

    #[test]
    fn ascii_draws_the_bar_with_hashes_and_dashes() {
        let texts = drawn(true, &[70 << 20]);
        assert!(texts[0].contains('#') && texts[0].contains('-'), "{texts:?}");
        assert!(texts.iter().all(|t| !t.contains('\u{2588}') && !t.contains('\u{2591}')), "{texts:?}");
    }

    #[test]
    fn every_text_fits_79_columns() {
        // QA QPB-02: an 80-column terminal wraps a longer line, and a
        // carriage return then leaves the wrapped rows behind.
        for ascii in [false, true] {
            for text in drawn(ascii, &[100 << 20, 60 << 20, 3 << 30]) {
                assert!(width(text.trim_matches('\r')) <= 79, "{text:?}");
            }
        }
    }

    /// The rows a terminal `cols` columns wide shows after `texts`, by xterm's
    /// rules: a character written into the last column leaves a pending wrap,
    /// which the next printable character takes to a new row and a carriage
    /// return cancels.
    fn terminal(texts: &[String], cols: usize) -> Vec<String> {
        let mut rows: Vec<Vec<char>> = vec![Vec::new()];
        let (mut row, mut col, mut pending) = (0usize, 0usize, false);
        for c in texts.concat().chars() {
            if c == '\r' {
                col = 0;
                pending = false;
                continue;
            }
            let w = crate::rich::char_width(c);
            if w == 0 {
                continue;
            }
            if pending || col + w > cols {
                row += 1;
                col = 0;
                pending = false;
                rows.push(Vec::new());
            }
            let line = &mut rows[row];
            while line.len() < col + w {
                line.push(' ');
            }
            line[col] = c;
            col += w;
            if col >= cols {
                col = cols - 1;
                pending = true;
            }
        }
        rows.into_iter().map(|r| r.into_iter().collect::<String>().trim_end().to_string()).collect()
    }

    #[test]
    fn an_80_column_terminal_is_left_with_no_bar() {
        // QA QPB-02: every redraw covers the last line and the erase clears
        // it, on a terminal 80 columns wide.
        for ascii in [false, true] {
            let texts = drawn(ascii, &[100 << 20, 60 << 20, 200 << 20]);
            let rows = terminal(&texts, 80);
            assert!(rows.iter().all(|r| r.is_empty()), "{rows:#?}");
        }
    }
}
