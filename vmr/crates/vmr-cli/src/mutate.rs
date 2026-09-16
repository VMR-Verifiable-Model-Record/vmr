//! Deterministic input mutation for the robustness tests (test-only).
// ============================================================================
//  mutate.rs — the CLI's own mutation harness (Law 9, DEV_PLAN §5.7)
//
//  vmr-verify's harness (tests/robustness.rs) hammers the verifier; this one
//  hammers what the CLI adds on top: its readers (manifest, KHALMTRN, brain
//  header, key files, public key files) and its renderers (the verification
//  summary, the inspection). An explicit LCG with a fixed seed per test —
//  no `rand`, no clock — so every run sees the same mutants (Law 1). The
//  oracles: nothing panics, and nothing a renderer prints can move a
//  terminal's cursor or reorder its text.
// ============================================================================

/// Knuth's MMIX LCG: deterministic, seedable, good enough to pick mutations.
pub struct Lcg(u64);

impl Lcg {
    pub fn new(seed: u64) -> Self {
        Lcg(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }

    /// A value in `0..n` (`n > 0`).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Bytes a mutation inserts: raw controls, a quote, a backslash, high
/// bytes, the UTF-8 of a bidi override (valid inside a JSON string), and
/// the JSON escapes of ESC, CSI and a bidi override - which keep a
/// document valid JSON, so the record still parses and its claims get
/// rendered.
const INSERTS: &[&[u8]] = &[
    b"\x00",
    b"\x1b",
    b"\r",
    b"\"",
    b"\\",
    b"\x7f",
    b"\xff",
    b"\xc3",
    "\u{202e}".as_bytes(),
    br"\u001b",
    br"\u009b",
    br"\u202e",
    b"{",
    b"}",
    b"[",
    b"0",
];

/// JSON escapes of characters a terminal must never receive raw: ESC
/// (with a screen-clearing sequence), CSI, RLO, CR and LS. Inside a string
/// value they keep the document valid JSON.
const STRING_ESCAPES: &[&[u8]] = &[
    br"\u001b[2J",
    br"\u009b",
    br"\u202e",
    br"\r",
    br"\u2028",
];

/// One random edit of `input`: a bit flip, a byte overwrite, a truncation,
/// an insertion, a deletion, a duplicated run - or, structure-aware, an
/// escaped control put at the start of a random JSON string value, so the
/// document still parses and the value reaches a renderer.
pub fn mutate(rng: &mut Lcg, input: &[u8]) -> Vec<u8> {
    let mut v = input.to_vec();
    if v.is_empty() {
        return INSERTS[rng.below(INSERTS.len())].to_vec();
    }
    let at = rng.below(v.len());
    match rng.below(7) {
        0 => v[at] ^= 1 << rng.below(8),
        1 => v[at] = rng.next() as u8,
        2 => v.truncate(at),
        3 => {
            let insert = INSERTS[rng.below(INSERTS.len())];
            v.splice(at..at, insert.iter().copied());
        }
        4 => {
            v.remove(at);
        }
        5 => {
            let len = (1 + rng.below(16)).min(v.len() - at);
            let run: Vec<u8> = v[at..at + len].to_vec();
            v.splice(at..at, run);
        }
        _ => {
            // After `": "` or `":"` and the opening quote of a string value.
            let mut starts: Vec<usize> = Vec::new();
            for (i, w) in v.windows(4).enumerate() {
                if w == b"\": \"" {
                    starts.push(i + 4);
                }
            }
            for (i, w) in v.windows(3).enumerate() {
                if w == b"\":\"" {
                    starts.push(i + 3);
                }
            }
            if !starts.is_empty() {
                let at = starts[rng.below(starts.len())];
                let escape = STRING_ESCAPES[rng.below(STRING_ESCAPES.len())];
                v.splice(at..at, escape.iter().copied());
            }
        }
    }
    v
}

/// Whether `s` is safe to print: no control character but the newline, and
/// none of the Unicode direction or separator controls display_safe
/// escapes.
pub fn terminal_safe(s: &str) -> bool {
    !s.chars().any(|c| {
        (c.is_control() && c != '\n')
            || matches!(u32::from(c), 0x202a..=0x202e | 0x2066..=0x2069 | 0x2028 | 0x2029 | 0x200e | 0x200f | 0x061c)
    })
}

/// A file under the repository root, for the tests' seeds.
pub fn repo_file(rel: &str) -> Vec<u8> {
    std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").join(rel)).unwrap()
}
