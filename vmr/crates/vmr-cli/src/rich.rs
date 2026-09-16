//! Drawing the terminal screens: banners, badges and bordered tables
//! (docs/dev/cli-polish.md CP-2 to CP-5).
// ============================================================================
//  rich.rs — the primitives of the screens a person sees at a terminal
//
//  A screen is lines of spans. A span's text is ALREADY terminal-safe: the
//  caller passed it through display_safe, shown_value, shown or
//  escape_controls, or wrote it here. Each span has one style from a closed
//  set, and render() puts that style's fixed SGR sequence around each run of
//  neighbouring spans that share it. So
//  nothing a record says can bring an escape sequence of its own, and
//  removing exactly these sequences (strip) gives back the screen's text.
//
//  Widths are terminal columns (char_width, from the Unicode tables of
//  width_tables.rs: wide East Asian characters and emoji take two, combining
//  marks none). A value wider than its cell wraps inside the cell, at a space
//  where it can and inside a word where it must: nothing is ever cut off.
//  Borders have their own style, and the screens' marks and badges theirs,
//  so --ascii redraws box-drawing characters in borders and √ and × in marks
//  and badges, and never a character of a value.
//
//  The plain text, what a pipe, a file or a script gets, does not come from
//  here: it is render.rs's, unchanged.
// ============================================================================

/// How a span looks. Each style is one fixed SGR sequence: the eight
/// standard colours, bold, underline and bright black (CP-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// No sequence at all.
    Plain,
    /// Bold: a command, a heading.
    Bold,
    /// Bright black: a label, context.
    Dim,
    /// Bright black, and the one style whose characters --ascii redraws.
    Border,
    /// Bold green: only what this verifier checked and passed.
    Ok,
    /// Bold red: what failed.
    Fail,
    /// Bold yellow: what is only claimed, or undecided.
    Caution,
    /// Bold green, for a √ of the screens' own and nothing else: --ascii
    /// redraws it (QA QP-11).
    OkMark,
    /// Bold red, for a × of the screens' own and nothing else: --ascii
    /// redraws it.
    FailMark,
    /// Yellow: a qualifier on a claim.
    Note,
    /// Bold cyan: a hint, a next step.
    Hint,
    /// Black on green: a badge for what this verifier checked and passed.
    BadgeOk,
    /// Bright white on red: a badge for what failed.
    BadgeFail,
    /// Black on yellow: a badge for what is only claimed.
    BadgeCaution,
    /// Black on cyan: a badge for a neutral action.
    BadgeNeutral,
    /// The standard's logo, in the terminal's own text colour (no sequence):
    /// --ascii draws each block as `#`.
    Logo,
}

/// Every style, so that strip removes every sequence render writes.
#[cfg(test)]
const STYLES: [Style; 16] = [
    Style::Logo,
    Style::Plain,
    Style::Bold,
    Style::Dim,
    Style::Border,
    Style::Ok,
    Style::Fail,
    Style::Caution,
    Style::OkMark,
    Style::FailMark,
    Style::Note,
    Style::Hint,
    Style::BadgeOk,
    Style::BadgeFail,
    Style::BadgeCaution,
    Style::BadgeNeutral,
];

/// Ends a style.
const RESET: &str = "\u{1b}[0m";

impl Style {
    fn sgr(self) -> &'static str {
        match self {
            Style::Plain | Style::Logo => "",
            Style::Bold => "\u{1b}[1m",
            Style::Dim | Style::Border => "\u{1b}[90m",
            Style::Ok | Style::OkMark => "\u{1b}[1;32m",
            Style::Fail | Style::FailMark => "\u{1b}[1;31m",
            Style::Caution => "\u{1b}[1;33m",
            Style::Note => "\u{1b}[33m",
            Style::Hint => "\u{1b}[1;36m",
            Style::BadgeOk => "\u{1b}[1;30;42m",
            Style::BadgeFail => "\u{1b}[1;97;41m",
            Style::BadgeCaution => "\u{1b}[1;30;43m",
            Style::BadgeNeutral => "\u{1b}[1;30;46m",
        }
    }

    /// A style that holds only the screens' own words and marks, a mark or a
    /// badge, whose √ and × --ascii redraws. A value is never in one: a √ in
    /// a verifier's detail or a pack's text keeps its character (QA QP-11).
    fn carries_marks(self) -> bool {
        matches!(
            self,
            Style::OkMark | Style::FailMark | Style::BadgeOk | Style::BadgeFail | Style::BadgeCaution | Style::BadgeNeutral
        )
    }
}

/// Text in one style.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// Terminal-safe text.
    pub text: String,
    /// Its look.
    pub style: Style,
}

/// One line of a screen.
pub type Line = Vec<Span>;

/// Plain text.
pub fn plain(text: impl Into<String>) -> Span {
    Span { text: text.into(), style: Style::Plain }
}

/// Styled text.
pub fn styled(text: impl Into<String>, style: Style) -> Span {
    Span { text: text.into(), style }
}

/// A key/value table's label column.
pub const LABEL_WIDTH: usize = 16;
/// A key/value table's value column: a whole `sha256:` hash.
pub const VALUE_WIDTH: usize = 71;
/// A frame's width between its two outer borders.
pub const INNER: usize = LABEL_WIDTH + VALUE_WIDTH + 5;
/// A frame's width, borders included.
pub const OUTER: usize = INNER + 2;
/// Every line of a screen starts with this.
const INDENT: &str = "  ";

/// The columns a character takes on a terminal: none for a combining mark,
/// two for a wide East Asian character or emoji, else one (QA QP-05). The
/// tables are generated from Python's Unicode data (`width_tables.rs`).
pub fn char_width(c: char) -> usize {
    let cp = u32::from(c);
    if in_table(crate::width_tables::ZERO, cp) {
        0
    } else if in_table(crate::width_tables::WIDE, cp) {
        2
    } else {
        1
    }
}

/// Whether `cp` is in a table of sorted, disjoint closed ranges.
fn in_table(table: &[(u32, u32)], cp: u32) -> bool {
    table
        .binary_search_by(|&(lo, hi)| {
            if hi < cp {
                std::cmp::Ordering::Less
            } else if lo > cp {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// The columns a text takes.
pub fn width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

/// The columns a line takes.
pub fn line_width(line: &[Span]) -> usize {
    line.iter().map(|span| width(&span.text)).sum()
}

/// `line` padded with plain spaces to `columns` (a wider line is left as it is).
fn pad(mut line: Line, columns: usize) -> Line {
    let used = line_width(&line);
    if used < columns {
        line.push(plain(" ".repeat(columns - used)));
    }
    line
}

/// `line` aligned right in `columns`.
fn pad_left(line: Line, columns: usize) -> Line {
    let used = line_width(&line);
    let mut out = Vec::new();
    if used < columns {
        out.push(plain(" ".repeat(columns - used)));
    }
    out.extend(line);
    out
}

/// `line` in lines of at most `max` columns, every style kept: broken after
/// the last space that fits, or inside a word that is longer than a line.
/// The space a line is broken at is dropped; every other character stays.
pub fn fit(line: &[Span], max: usize) -> Vec<Line> {
    let max = max.max(2);
    let mut lines: Vec<Vec<(char, Style)>> = Vec::new();
    let mut current: Vec<(char, Style)> = Vec::new();
    let mut used = 0usize;
    for span in line {
        for c in span.text.chars() {
            let w = char_width(c);
            let mut broke = false;
            while used + w > max && !current.is_empty() {
                broke = true;
                match current.iter().rposition(|(ch, _)| *ch == ' ').filter(|at| *at > 0) {
                    Some(at) => {
                        let rest = current.split_off(at + 1);
                        current.pop();
                        lines.push(std::mem::replace(&mut current, rest));
                    }
                    None => lines.push(std::mem::take(&mut current)),
                }
                used = current.iter().map(|(ch, _)| char_width(*ch)).sum();
            }
            if broke && c == ' ' && current.is_empty() {
                continue;
            }
            current.push((c, span.style));
            used += w;
        }
    }
    lines.push(current);
    lines.iter().map(|chars| group(chars)).collect()
}

/// Characters back into spans, one span per run of a style.
fn group(chars: &[(char, Style)]) -> Line {
    let mut line: Line = Vec::new();
    for (c, style) in chars {
        match line.last_mut() {
            Some(span) if span.style == *style => span.text.push(*c),
            _ => line.push(styled(c.to_string(), *style)),
        }
    }
    line
}

fn border(text: impl Into<String>) -> Span {
    styled(text, Style::Border)
}

fn rule(text: String) -> Line {
    vec![plain(INDENT), border(text)]
}

/// The first lines of every screen: the tool's tag and the command.
pub fn header(command: &str) -> Vec<Line> {
    vec![
        vec![plain(INDENT), styled(format!(" {} ", crate::names::TOOL), Style::BadgeNeutral), styled(format!("  {command}"), Style::Bold)],
        Vec::new(),
    ]
}

/// A command's name column in a sectioned table.
const NAME_WIDTH: usize = 18;

/// A bordered table of sections, each a heading in its rule and rows of a
/// bold name and its text, the text wrapped under itself (the help screen).
pub fn sections(groups: &[(String, Vec<(String, String)>)]) -> Vec<Line> {
    let text_width = INNER - NAME_WIDTH - 3;
    let mut out = Vec::new();
    for (i, (heading, rows)) in groups.iter().enumerate() {
        let (left, right) = if i == 0 { ('┌', '┐') } else { ('├', '┤') };
        out.push(vec![
            plain(INDENT),
            border(format!("{left}─ ")),
            styled(heading.clone(), Style::Bold),
            border(format!(" {}{right}", "─".repeat(INNER.saturating_sub(width(heading) + 3)))),
        ]);
        for (name, text) in rows {
            let names = fit(&[styled(name.clone(), Style::Bold)], NAME_WIDTH);
            let texts = fit(&[plain(text.clone())], text_width);
            for k in 0..names.len().max(texts.len()) {
                let mut line = vec![plain(INDENT), border("│"), plain("  ")];
                line.extend(pad(names.get(k).cloned().unwrap_or_default(), NAME_WIDTH));
                line.extend(pad(texts.get(k).cloned().unwrap_or_default(), text_width));
                line.push(plain(" "));
                line.push(border("│"));
                out.push(line);
            }
        }
    }
    if !groups.is_empty() {
        out.push(rule(format!("└{}┘", "─".repeat(INNER))));
    }
    out
}

/// A rounded box around `rows`, each wrapped to its width.
pub fn banner(rows: &[Line]) -> Vec<Line> {
    let mut out = vec![rule(format!("╭{}╮", "─".repeat(INNER)))];
    for row in rows {
        for part in fit(row, INNER) {
            let mut line = vec![plain(INDENT), border("│")];
            line.extend(pad(part, INNER));
            line.push(border("│"));
            out.push(line);
        }
    }
    out.push(rule(format!("╰{}╯", "─".repeat(INNER))));
    out
}

/// A row of a key/value table: a label and its value's lines.
#[derive(Debug, Clone)]
pub struct Row {
    /// The label.
    pub label: String,
    /// The value, one line per entry, each wrapped to the value column.
    pub value: Vec<Line>,
}

/// A row.
pub fn row(label: &str, value: Vec<Line>) -> Row {
    Row { label: label.to_string(), value }
}

/// A group of a key/value table.
#[derive(Debug, Clone)]
pub enum Block {
    /// Label and value rows.
    Rows(Vec<Row>),
    /// A line across the whole table.
    Heading(Line),
}

/// A bordered key/value table: its blocks separated by rules.
pub fn table(blocks: &[Block]) -> Vec<Line> {
    let Some(first) = blocks.first() else {
        return Vec::new();
    };
    let is_rows = |block: &Block| matches!(block, Block::Rows(_));
    let rule_with = |left: char, middle: char, right: char| {
        rule(format!("{left}{}{middle}{}{right}", "─".repeat(LABEL_WIDTH + 2), "─".repeat(VALUE_WIDTH + 2)))
    };
    let mut out = vec![rule_with('┌', if is_rows(first) { '┬' } else { '─' }, '┐')];
    let mut previous: Option<bool> = None;
    for block in blocks {
        let here = is_rows(block);
        if let Some(before) = previous {
            let middle = match (before, here) {
                (true, true) => '┼',
                (true, false) => '┴',
                (false, true) => '┬',
                (false, false) => '─',
            };
            out.push(rule_with('├', middle, '┤'));
        }
        match block {
            Block::Rows(rows) => {
                for r in rows {
                    let labels = fit(&[styled(r.label.clone(), Style::Dim)], LABEL_WIDTH);
                    let values: Vec<Line> = r.value.iter().flat_map(|l| fit(l, VALUE_WIDTH)).collect();
                    for i in 0..labels.len().max(values.len()) {
                        let mut line = vec![plain(INDENT), border("│ ")];
                        line.extend(pad(labels.get(i).cloned().unwrap_or_default(), LABEL_WIDTH));
                        line.push(border(" │ "));
                        line.extend(pad(values.get(i).cloned().unwrap_or_default(), VALUE_WIDTH));
                        line.push(border(" │"));
                        out.push(line);
                    }
                }
            }
            Block::Heading(heading) => {
                for part in fit(heading, INNER - 2) {
                    let mut line = vec![plain(INDENT), border("│ ")];
                    line.extend(pad(part, INNER - 2));
                    line.push(border(" │"));
                    out.push(line);
                }
            }
        }
        previous = Some(here);
    }
    let last_rows = blocks.last().is_some_and(is_rows);
    out.push(rule_with('└', if last_rows { '┴' } else { '─' }, '┘'));
    out
}

/// A bordered table of columns.
#[derive(Debug, Clone)]
pub struct Grid {
    /// Each column's heading.
    pub headers: Vec<String>,
    /// Each column's width: together, with their borders, a frame's width.
    pub widths: Vec<usize>,
    /// Whether a column is aligned right.
    pub right: Vec<bool>,
    /// Rows of cells; a cell is its lines, each wrapped to the column.
    pub rows: Vec<Vec<Vec<Line>>>,
}

/// A grid, drawn.
pub fn grid(g: &Grid) -> Vec<Line> {
    let rule_with = |left: &str, middle: &str, right: &str| {
        let columns: Vec<String> = g.widths.iter().map(|w| "─".repeat(w + 2)).collect();
        rule(format!("{left}{}{right}", columns.join(middle)))
    };
    let draw = |cells: &[Vec<Line>]| -> Vec<Line> {
        let fitted: Vec<Vec<Line>> = g
            .widths
            .iter()
            .enumerate()
            .map(|(k, w)| cells.get(k).map_or_else(Vec::new, |lines| lines.iter().flat_map(|l| fit(l, *w)).collect()))
            .collect();
        let height = fitted.iter().map(Vec::len).max().unwrap_or(0).max(1);
        (0..height)
            .map(|i| {
                let mut line = vec![plain(INDENT), border("│")];
                for (k, w) in g.widths.iter().enumerate() {
                    let cell = fitted.get(k).and_then(|c| c.get(i)).cloned().unwrap_or_default();
                    line.push(plain(" "));
                    line.extend(if g.right.get(k).copied().unwrap_or(false) { pad_left(cell, *w) } else { pad(cell, *w) });
                    line.push(plain(" "));
                    line.push(border("│"));
                }
                line
            })
            .collect()
    };
    let mut out = vec![rule_with("┌", "┬", "┐")];
    let headers: Vec<Vec<Line>> = g.headers.iter().map(|h| vec![vec![styled(h.clone(), Style::Bold)]]).collect();
    out.extend(draw(&headers));
    out.push(rule_with("├", "┼", "┤"));
    for r in &g.rows {
        out.extend(draw(r));
    }
    out.push(rule_with("└", "┴", "┘"));
    out
}

/// A line outside a frame, wrapped to the screen's width, every further line
/// starting at column `hang`.
pub fn paragraph(line: &[Span], hang: usize) -> Vec<Line> {
    fit(line, (OUTER + INDENT.len()).saturating_sub(hang))
        .into_iter()
        .enumerate()
        .map(|(i, part)| {
            if i == 0 {
                part
            } else {
                let mut indented = vec![plain(" ".repeat(hang))];
                indented.extend(part);
                indented
            }
        })
        .collect()
}

/// A screen as a terminal receives it: each run of neighbouring spans with the
/// same SGR sequence inside that sequence and one reset (so a mark and its word
/// are one run of colour), a line break after every line. With `ascii`,
/// borders and the screens' marks are redrawn in ASCII, span by span.
pub fn render(lines: &[Line], ascii: bool) -> String {
    let mut out = String::new();
    for line in lines {
        let mut open = "";
        for span in line {
            let text = if ascii && span.style == Style::Border {
                redraw_border(&span.text)
            } else if ascii && span.style == Style::Logo {
                span.text.chars().map(|c| if c == '█' { '#' } else { c }).collect()
            } else if ascii && span.style.carries_marks() {
                span.text.chars().map(|c| match c {
                    '√' => '+',
                    '×' => 'x',
                    other => other,
                }).collect()
            } else {
                span.text.clone()
            };
            if text.is_empty() {
                continue;
            }
            let sgr = span.style.sgr();
            if sgr != open {
                if !open.is_empty() {
                    out.push_str(RESET);
                }
                out.push_str(sgr);
                open = sgr;
            }
            out.push_str(&text);
        }
        if !open.is_empty() {
            out.push_str(RESET);
        }
        out.push('\n');
    }
    out
}

fn redraw_border(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '─' => '-',
            '│' => '|',
            '╭' | '╮' | '╰' | '╯' | '┌' | '┐' | '└' | '┘' | '├' | '┤' | '┬' | '┴' | '┼' => '+',
            other => other,
        })
        .collect()
}

/// A rendered screen's text: every sequence render writes removed.
#[cfg(test)]
pub fn strip(text: &str) -> String {
    let mut out = text.replace(RESET, "");
    for style in STYLES {
        let sgr = style.sgr();
        if !sgr.is_empty() {
            out = out.replace(sgr, "");
        }
    }
    out
}

/// A size for a person: bytes below 1 KiB, else KiB, MiB or GiB to one
/// decimal, rounded half up in integer arithmetic.
pub fn human_size(bytes: u64) -> String {
    for (unit, size) in [("GiB", 1u64 << 30), ("MiB", 1u64 << 20), ("KiB", 1u64 << 10)] {
        if bytes >= size {
            let tenths = bytes.saturating_mul(10).saturating_add(size / 2) / size;
            return format!("{}.{} {unit}", tenths / 10, tenths % 10);
        }
    }
    format!("{bytes} B")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_lines(lines: &[Line]) -> Vec<String> {
        strip(&render(lines, false)).lines().map(str::to_string).collect()
    }

    #[test]
    fn every_line_of_a_frame_is_as_wide_as_the_screen() {
        // Wide characters, a combining mark, a word longer than a line and an
        // empty value: every frame line still takes the screen's columns.
        let long = "x".repeat(300);
        let blocks = vec![
            Block::Rows(vec![
                row("Issuer", vec![vec![plain("did:web:example.org")], vec![plain(format!("界界界 {long} e\u{301}"))]]),
                row("A label much longer than sixteen columns", vec![vec![plain("v")]]),
                row("Empty", Vec::new()),
            ]),
            Block::Heading(vec![styled(" NOT VERIFIED ", Style::BadgeCaution), plain(format!("  {long}"))]),
            Block::Rows(vec![row("Last", vec![vec![styled("✓ pass", Style::Ok)]])]),
        ];
        let mut lines = table(&blocks);
        lines.extend(banner(&[vec![plain(long.clone())], Vec::new()]));
        lines.extend(grid(&Grid {
            headers: vec!["File".into(), "Size".into()],
            widths: vec![76, 11],
            right: vec![false, true],
            rows: vec![vec![vec![vec![plain(long.clone())]], vec![vec![plain("1.5 KiB")]]]],
        }));
        for line in text_lines(&lines) {
            assert_eq!(width(&line), OUTER + INDENT.len(), "`{line}`");
        }
    }

    #[test]
    fn fitting_keeps_every_character_but_the_spaces_it_breaks_at() {
        let line = vec![plain("alpha beta "), styled("gamma", Style::Ok), plain(" "), plain("d".repeat(25))];
        let parts = fit(&line, 10);
        for part in &parts {
            assert!(line_width(part) <= 10, "{part:?}");
        }
        let joined: String = parts.iter().flatten().map(|span| span.text.as_str()).collect();
        assert_eq!(joined.replace(' ', ""), format!("alphabetagamma{}", "d".repeat(25)));
        assert!(parts.iter().flatten().any(|span| span.style == Style::Ok && span.text == "gamma"));
        assert_eq!(fit(&[], 10), vec![Vec::<Span>::new()]);
    }

    #[test]
    fn ascii_redraws_borders_and_marks_and_nothing_else() {
        let lines = banner(&[vec![
            styled(" √ VALID ", Style::BadgeOk),
            plain(" a ─ │ √ in a value "),
            styled("√", Style::OkMark),
            styled(" pass ", Style::Ok),
            styled("×", Style::FailMark),
            styled(" fail", Style::Fail),
        ]]);
        let out = strip(&render(&lines, true));
        assert!(out.contains("+---") && out.contains('|') && out.contains(" + VALID "), "{out}");
        assert!(out.contains(" a ─ │ √ in a value + pass x fail"), "a value keeps its characters:\n{out}");
    }

    #[test]
    fn render_writes_only_its_own_sequences_and_strip_removes_them() {
        let lines = vec![STYLES.iter().map(|style| styled("x", *style)).collect::<Line>()];
        let out = render(&lines, false);
        assert_eq!(strip(&out), format!("{}\n", "x".repeat(STYLES.len())));
        // Neighbours with the same sequence share one run, so a mark and its
        // word are one run of colour; every run ends in a reset, and an empty
        // span writes nothing.
        assert_eq!(
            render(&[vec![styled("\u{2713}", Style::OkMark), styled(" pass", Style::Ok)]], false),
            "\u{1b}[1;32m\u{2713} pass\u{1b}[0m\n"
        );
        assert_eq!(
            render(&[vec![styled("a", Style::Dim), plain("b"), styled("", Style::Fail), styled("c", Style::Border)]], false),
            "\u{1b}[90ma\u{1b}[0mb\u{1b}[90mc\u{1b}[0m\n"
        );
    }

    #[test]
    fn a_sectioned_table_is_as_wide_as_the_screen_and_the_logo_redraws_in_ascii() {
        let lines = sections(&[
            ("Records".to_string(), vec![("record emit".to_string(), "x ".repeat(60))]),
            ("Keys and trust".to_string(), vec![("trust-store add".to_string(), "Trust a public key".to_string())]),
        ]);
        for line in text_lines(&lines) {
            assert_eq!(width(&line), OUTER + INDENT.len(), "`{line}`");
        }
        let ascii = strip(&render(&lines, true));
        assert!(ascii.contains("+- Records -") && !ascii.chars().any(|c| ('\u{2500}'..='\u{259f}').contains(&c)), "{ascii}");
        // The logo: its blocks become # with --ascii, the spaces between its
        // squares stay, and it is drawn in the terminal's own text colour.
        let logo = vec![vec![styled("\u{2588}\u{2588}    \u{2588}", Style::Logo)]];
        assert_eq!(strip(&render(&logo, true)), "##    #\n");
        assert_eq!(render(&logo, false), "\u{2588}\u{2588}    \u{2588}\n");
    }

    #[test]
    fn the_screens_write_exactly_these_twelve_sequences() {
        // QA QP-08: the closed set, written out here rather than read from
        // the table render uses, so a changed or added sequence fails.
        let mut want = vec![
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
        let mut written: Vec<&str> = STYLES.iter().map(|style| style.sgr()).filter(|sgr| !sgr.is_empty()).chain([RESET]).collect();
        written.sort_unstable();
        written.dedup();
        want.sort_unstable();
        assert_eq!(written, want);
        assert_eq!(Style::Border.sgr(), "\u{1b}[90m");
    }

    #[test]
    fn the_width_tables_are_sorted_ranges() {
        // char_width's binary search needs each table sorted and disjoint.
        for table in [crate::width_tables::ZERO, crate::width_tables::WIDE] {
            assert!(table.iter().all(|(lo, hi)| lo <= hi));
            assert!(table.windows(2).all(|pair| pair[0].1 < pair[1].0));
        }
        assert_eq!(width("\u{1100}\u{1161}\u{11a8}"), 2, "a Hangul syllable in jamo takes two columns");
    }

    #[test]
    fn ascii_keeps_a_mark_inside_a_value() {
        // QA QP-11: --ascii redraws the screens' own marks, never a ✓ or a ✗
        // inside a value a span quotes.
        let out = strip(&render(&[vec![styled("pack a\u{221a}b failed", Style::Fail)]], true));
        assert!(out.contains("a\u{221a}b"), "{out}");
    }

    /// Every character outside ASCII that the screens' own code draws. Each was
    /// checked on 2026-09-15 on the Windows development machine, with
    /// System.Windows.Media.GlyphTypeface.CharacterToGlyphMap, against Cascadia
    /// Mono (Windows Terminal), Consolas (the PowerShell window), Lucida Console
    /// and Courier New: every one is in all four fonts, except the rounded
    /// corners, which Lucida Console and Courier New lack; a corner ends its
    /// line, so it shifts nothing after it. A character a console font lacks is
    /// drawn from a wider fallback font and pushes the rest of its row out of
    /// line: that is how the marks U+2713 and U+2717 broke the tables.
    const SCREEN_CHARACTERS: &str = "·…─│┌┐└┘├┤┬┴┼╭╮╯╰█√×";

    #[test]
    fn the_screens_draw_only_characters_every_console_font_has() {
        let mut outside = Vec::new();
        for (file, source) in [("rich.rs", include_str!("rich.rs")), ("screens.rs", include_str!("screens.rs"))] {
            let code = source.split("\n#[cfg(test)]\nmod tests {").next().unwrap_or(source);
            for (n, line) in code.lines().enumerate() {
                let line = line.split("//").next().unwrap_or(line);
                let mut chars: Vec<char> = line.chars().filter(|c| !c.is_ascii()).collect();
                let mut rest = line;
                while let Some(at) = rest.find("\\u{") {
                    rest = &rest[at + 3..];
                    let escaped = rest.find('}').and_then(|end| u32::from_str_radix(&rest[..end], 16).ok()).and_then(char::from_u32);
                    chars.extend(escaped.filter(|c| !c.is_ascii()));
                }
                for c in chars.into_iter().filter(|c| !SCREEN_CHARACTERS.contains(*c)) {
                    outside.push(format!("{file}:{}: U+{:04X} {c}", n + 1, u32::from(c)));
                }
            }
        }
        assert!(outside.is_empty(), "characters not every console font has:\n{}", outside.join("\n"));
    }

    #[test]
    fn widths_and_sizes() {
        assert_eq!(width("abc"), 3);
        assert_eq!(width("界"), 2);
        assert_eq!(width("e\u{301}"), 1);
        // QA QP-05: emoji a terminal draws two columns wide, combining marks
        // of other scripts it draws in none, a spacing mark in one.
        assert_eq!(width("\u{1f680}"), 2);
        assert_eq!(width("\u{2705}"), 2);
        assert_eq!(width("\u{26a1}"), 2);
        assert_eq!(width("\u{1fa7a}"), 2);
        assert_eq!(width("\u{591}"), 0);
        assert_eq!(width("\u{e31}"), 0);
        assert_eq!(width("\u{93f}"), 1);
        assert_eq!(human_size(453), "453 B");
        assert_eq!(human_size(1570), "1.5 KiB");
        assert_eq!(human_size(2_418_348), "2.3 MiB");
        assert_eq!(human_size(7_694_054_130), "7.2 GiB");
    }
}
