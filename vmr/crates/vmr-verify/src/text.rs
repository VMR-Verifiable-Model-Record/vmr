//! Terminal-safe text for anything derived from untrusted input.
// ============================================================================
//  text.rs — escaping for record- and store-derived strings
//
//  A record is attacker-controlled input, and so is a trust store handed
//  to the wrong person. Any string from either that ends up in a report
//  detail or on a terminal goes through `display_safe` first: an
//  `issuer_name` carrying ANSI escapes could otherwise repaint the screen
//  with a fake "✓ Record valid" line (docs/dev/phase4.md §3.5, R6). And
//  since QA P4-06, nothing that renders as nothing gets through either: a
//  zero-width space or a tag character can make two names look identical.
//  Messages built from such strings (report details, trust-store errors)
//  are bounded and pass `escape_controls`, the same table without the
//  doubled backslash, on their way out.
// ============================================================================

/// `s` with every character that can move a terminal's cursor, change its
/// colours, reorder the text or hide in it escaped as `\u{XXXX}`:
///
/// - C0 controls (including ESC, CR, LF and TAB), DEL and C1 controls;
/// - the line and paragraph separators (U+2028, U+2029);
/// - every `Default_Ignorable_Code_Point` of Unicode 16.0.0 (the table in
///   [`DEFAULT_IGNORABLE`]): among them the bidirectional embedding,
///   override and isolate controls and the direction marks, zero-width
///   spaces and joiners, invisible operators, U+FEFF, variation selectors,
///   fillers and the tag characters (U+E0000–U+E0FFF);
/// - every noncharacter (U+FDD0–U+FDEF, and U+xFFFE and U+xFFFF of every
///   plane) — valid in a record (spec §2 rule 1), but nothing a name
///   should show.
///
/// A backslash is doubled, so the escaping is unambiguous. Everything else —
/// letters of every script, accents, symbols, emoji — is kept as it is.
pub fn display_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_unsafe(c) {
            out.push_str(&format!("\\u{{{:04x}}}", u32::from(c)));
        } else if c == '\\' {
            out.push_str("\\\\");
        } else {
            out.push(c);
        }
    }
    out
}

/// `Default_Ignorable_Code_Point`, Unicode 16.0.0 (DerivedCoreProperties.txt;
/// 4 174 code points), as inclusive ranges. Hard-coded so the verifier needs
/// no Unicode-table dependency. It contains every bidi control and direction
/// mark the escaping covered before (U+061C, U+200E–U+200F, U+202A–U+202E,
/// U+2066–U+2069).
const DEFAULT_IGNORABLE: [(u32, u32); 17] = [
    (0x00AD, 0x00AD),   // SOFT HYPHEN
    (0x034F, 0x034F),   // COMBINING GRAPHEME JOINER
    (0x061C, 0x061C),   // ARABIC LETTER MARK
    (0x115F, 0x1160),   // HANGUL CHOSEONG / JUNGSEONG FILLER
    (0x17B4, 0x17B5),   // KHMER VOWEL INHERENT AQ, AA
    (0x180B, 0x180F),   // MONGOLIAN FREE VARIATION SELECTORS, VOWEL SEPARATOR
    (0x200B, 0x200F),   // ZERO WIDTH SPACE .. RIGHT-TO-LEFT MARK
    (0x202A, 0x202E),   // LEFT-TO-RIGHT EMBEDDING .. RIGHT-TO-LEFT OVERRIDE
    (0x2060, 0x206F),   // WORD JOINER, INVISIBLE OPERATORS, ISOLATES, ...
    (0x3164, 0x3164),   // HANGUL FILLER
    (0xFE00, 0xFE0F),   // VARIATION SELECTOR-1 .. -16
    (0xFEFF, 0xFEFF),   // ZERO WIDTH NO-BREAK SPACE (byte order mark)
    (0xFFA0, 0xFFA0),   // HALFWIDTH HANGUL FILLER
    (0xFFF0, 0xFFF8),   // reserved
    (0x1BCA0, 0x1BCA3), // SHORTHAND FORMAT CONTROLS
    (0x1D173, 0x1D17A), // MUSICAL SYMBOL BEGIN BEAM .. END PHRASE
    (0xE0000, 0xE0FFF), // TAG CHARACTERS, VARIATION SELECTOR-17 .. -256, reserved
];

/// Whether `code` is a noncharacter: U+FDD0–U+FDEF, or the last two code
/// points of any plane (U+xFFFE, U+xFFFF).
fn is_noncharacter(code: u32) -> bool {
    (0xFDD0..=0xFDEF).contains(&code) || code & 0xFFFE == 0xFFFE
}

/// Whether `c` is one of the characters [`display_safe`] escapes.
fn is_unsafe(c: char) -> bool {
    let code = u32::from(c);
    code < 0x20
        || (0x7f..=0x9f).contains(&code)
        || matches!(code, 0x2028 | 0x2029)
        || DEFAULT_IGNORABLE.iter().any(|&(lo, hi)| (lo..=hi).contains(&code))
        || is_noncharacter(code)
}

/// `text` made terminal-safe as a last line of defence: the characters
/// [`display_safe`] escapes are escaped as `\u{XXXX}` (the same table), and
/// nothing else changes — backslashes are left as they are.
///
/// For text that is already a message: a report detail, a loader error, a
/// command-line error. Such text may hold values [`display_safe`] has
/// escaped already, and this escapes nothing twice: its output, like
/// [`display_safe`]'s, holds none of the characters it escapes, so applying
/// it again changes nothing (idempotent). Every report detail and every
/// trust-store error detail passes here; `vmr` passes every error message it
/// prints. For a raw value, use [`display_safe`]: its doubled backslash
/// keeps the escaping unambiguous.
pub fn escape_controls(text: String) -> String {
    if !text.chars().any(is_unsafe) {
        return text;
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_unsafe(c) {
            out.push_str(&format!("\\u{{{:04x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// `json` — text serde_json wrote — with every character [`display_safe`]
/// escapes that serde_json leaves raw (DEL, C1 controls, U+2028/U+2029, the
/// Default_Ignorable code points, noncharacters) written as a JSON `\u`
/// escape: `\uXXXX`, or a UTF-16 surrogate pair beyond U+FFFF (RFC 8259
/// §7). serde_json already escapes the C0 controls, `"` and `\`, and writes
/// only ASCII between tokens, so each such character sits inside a string:
/// the JSON stays valid and parses to exactly the same values. Public so
/// that every JSON a terminal shows escapes the same way (`vmr model hash
/// --json`, task 10.13a QA QM-02).
pub fn json_escape_unsafe(json: String) -> String {
    let raw_unsafe = |c: char| c >= '\u{7f}' && is_unsafe(c);
    if !json.chars().any(raw_unsafe) {
        return json;
    }
    let mut out = String::with_capacity(json.len() + 32);
    for c in json.chars() {
        if raw_unsafe(c) {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units).iter() {
                out.push_str(&format!("\\u{:04x}", *unit));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `detail` cut to at most `max_chars` characters (then `…`) and made
/// terminal-safe with [`escape_controls`] — cut first, escaped second, so an
/// escape sequence is never cut in half.
pub(crate) fn cut_then_escape(detail: String, max_chars: usize) -> String {
    let detail = match detail.char_indices().nth(max_chars) {
        Some((at, _)) => {
            let mut cut = detail;
            cut.truncate(at);
            cut.push('…');
            cut
        }
        None => detail,
    };
    escape_controls(detail)
}

/// The most characters of an untrusted value a detail string quotes.
pub(crate) const QUOTE_MAX_CHARS: usize = 64;

/// An untrusted value for a detail string: at most [`QUOTE_MAX_CHARS`]
/// characters (then `…`), made [`display_safe`], in double quotes.
pub(crate) fn quote(value: &str) -> String {
    let mut cut: String = value.chars().take(QUOTE_MAX_CHARS).collect();
    let truncated = cut.len() < value.len();
    cut = display_safe(&cut);
    if truncated {
        cut.push('…');
    }
    format!("\"{cut}\"")
}

/// The most characters of any quoted run in a parser message.
const QUOTED_RUN_MAX: usize = 64;
/// The most characters of a whole parser message.
const MESSAGE_MAX: usize = 320;

/// A serde_json error as a detail: its message with every quoted run (a
/// member name, a value) cut to 64 characters, the whole cut to 320, made
/// terminal-safe, then its position. serde_json's own message quotes a
/// member name or value whole — as long as the input has it.
pub(crate) fn serde_detail(e: &serde_json::Error) -> String {
    let full = e.to_string();
    let position = format!(" at line {} column {}", e.line(), e.column());
    let message = full.strip_suffix(&position).unwrap_or(&full);
    format!("{} (line {}, column {})", bounded(message), e.line(), e.column())
}

/// `message` with quoted runs (between backticks or double quotes) cut to
/// [`QUOTED_RUN_MAX`] characters, the whole cut to [`MESSAGE_MAX`], and
/// made [`display_safe`].
pub(crate) fn bounded(message: &str) -> String {
    let mut out = String::new();
    let mut quote: Option<char> = None;
    let (mut run, mut cut) = (0usize, false);
    for c in message.chars() {
        match quote {
            None => {
                out.push(c);
                if c == '`' || c == '"' {
                    quote = Some(c);
                    run = 0;
                    cut = false;
                }
            }
            Some(q) if c == q => {
                if cut {
                    out.push('…');
                }
                out.push(c);
                quote = None;
            }
            Some(_) => {
                if run < QUOTED_RUN_MAX {
                    out.push(c);
                } else {
                    cut = true;
                }
                run += 1;
            }
        }
    }
    if cut && quote.is_some() {
        out.push('…');
    }
    let mut whole: String = out.chars().take(MESSAGE_MAX).collect();
    if whole.len() < out.len() {
        whole.push('…');
    }
    display_safe(&whole)
}
