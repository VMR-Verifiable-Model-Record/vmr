//! Typed refusals: loading, validating and signature-checking a pack.
// ============================================================================
//  error.rs — one variant per way a pack can be refused (P6-9)
//
//  A compliance format must not silently ignore a constraint, so every
//  refusal has a name, a message that says which pack member is at fault,
//  and a test. Nothing here panics and nothing here is a verification
//  result: a bad pack is an operator error, exactly as a bad trust store is
//  in vmr-verify.
// ============================================================================

use crate::refusal::Refusal;
use vmr_record::validate::FormatViolation;

/// Why a policy pack was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The document is larger than [`crate::MAX_PACK_BYTES`].
    #[error("policy pack is {bytes} bytes; at most {limit} are read")]
    PackTooLarge {
        /// The document's size.
        bytes: usize,
        /// The limit.
        limit: usize,
    },

    /// The document is not JSON, or not the shape of a pack: an unknown or
    /// duplicate member, a missing one, a `null`, a wrong JSON type, or a
    /// rule whose `type` this version does not know (P6-9).
    #[error("policy pack parse failed: {detail}")]
    PackParse {
        /// Which refusal of `specs/policy-pack-format-v0.1.md` §3 the text
        /// breaks, decided where the parse failed (`crate::refusal`): 2, 3, 4,
        /// 5, 7 or 12.
        refusal: Refusal,
        /// The parser's message, made terminal-safe.
        detail: String,
    },

    /// A value rule of `specs/policy-pack-schema/v0.1.json` is broken.
    #[error("policy pack schema: {0}")]
    PackSchema(#[from] FormatViolation),

    /// `version` is not [`crate::PACK_FORMAT_VERSION`].
    #[error("unsupported policy pack version {}: this build reads \"0.1\"", quoted(.0))]
    UnsupportedVersion(String),

    /// `rules` is empty: a pack that constrains nothing is not a pack.
    #[error("policy pack has no rules")]
    PackEmpty,

    /// Two rules share a `rule_id`, so a result could not be attributed.
    #[error("duplicate rule_id {}: a result must name exactly one rule", quoted(.0))]
    DuplicateRuleId(String),

    /// A rule states no requirement, so it can never fail: decoration, not
    /// policy (P6-9, and the mirror of P6-3's "always Indeterminate").
    #[error("rule {} states no requirement: {detail}", quoted(.rule_id))]
    RuleWithoutRequirement {
        /// The rule at fault.
        rule_id: String,
        /// Which parameters would have to say something.
        detail: String,
    },

    /// The pack carries no `signature` section, but one was required.
    #[error("policy pack is unsigned: it carries no signature section")]
    PackUnsigned,

    /// The `signature` section is present and wrong.
    #[error("policy pack signature invalid: {0}")]
    PackSignature(String),

    /// The `signature` section states a `signed_payload_hash` that is not the
    /// hash of the pack as received: the pack was changed after it was
    /// signed, or the section belongs to another pack. Step 4 of the format
    /// document's §4, which needs no key (QA Q6-05).
    #[error(
        "policy pack signature invalid: signed_payload_hash {} is not the hash of the pack as received ({})",
        crate::schema::quote(.stated),
        crate::schema::quote(.recomputed)
    )]
    PayloadHashMismatch {
        /// What the section states.
        stated: String,
        /// The pack's payload hash, recomputed.
        recomputed: String,
    },
}

impl Error {
    /// The refusal of `specs/policy-pack-format-v0.1.md` §3 a loader error
    /// is, whichever variant carries it; `None` for the errors of a signature
    /// check, which are not loader refusals (docs/dev/task-6.16.md A16-20).
    pub fn refusal(&self) -> Option<Refusal> {
        match self {
            Error::PackTooLarge { .. } => Some(Refusal::Size),
            Error::PackParse { refusal, .. } => Some(*refusal),
            Error::PackSchema(violation) => Some(schema_refusal(violation)),
            Error::UnsupportedVersion(_) => Some(Refusal::Version),
            Error::PackEmpty => Some(Refusal::EmptyRules),
            Error::DuplicateRuleId(_) => Some(Refusal::DuplicateRuleId),
            Error::RuleWithoutRequirement { .. } => Some(Refusal::NoRequirement),
            Error::PackUnsigned | Error::PackSignature(_) | Error::PayloadHashMismatch { .. } => None,
        }
    }

    /// The stable id of this refusal: [`Refusal::id`] for a loader refusal,
    /// and for a signature check `pack_signature.unsigned`,
    /// `pack_signature.payload_hash` or `pack_signature.invalid`
    /// (docs/dev/task-6.16.md A16-22).
    pub fn refusal_id(&self) -> &'static str {
        match (self.refusal(), self) {
            (Some(refusal), _) => refusal.id(),
            (None, Error::PackUnsigned) => "pack_signature.unsigned",
            (None, Error::PayloadHashMismatch { .. }) => "pack_signature.payload_hash",
            (None, _) => "pack_signature.invalid",
        }
    }
}

/// The refusal a schema value violation is, by where it is: a
/// `minimum_chain_length` above its `maximum` is 5, an `allowed_jurisdictions`
/// entry is 8, and every other value rule is 7.
fn schema_refusal(violation: &FormatViolation) -> Refusal {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let parts: Vec<&str> = violation.pointer.split('/').collect();
    match parts.as_slice() {
        ["", "rules", i, "minimum_chain_length"] if digits(i) && violation.rule == "maximum" => Refusal::IntegerRange,
        ["", "rules", i, "allowed_jurisdictions", j] if digits(i) && digits(j) => Refusal::Jurisdiction,
        _ => Refusal::Value,
    }
}

/// `value` as a refusal quotes it: Rust-escaped in double quotes, then
/// [`escape_unsafe`]d. `{:?}` alone leaves a few invisible letters raw (the
/// Hangul fillers U+115F, U+1160, U+3164, U+FFA0), so no refusal formats pack
/// text with it directly (QA Q6-10).
pub(crate) fn quoted(value: &str) -> String {
    escape_unsafe(&format!("{value:?}"))
}

/// `message` with every character a terminal acts on or hides written as
/// `\u{XXXX}`, and nothing else changed. serde echoes an unknown member name
/// or an unknown word as it was written, and a pack is a stranger's
/// document, so a parse error's text passes here before it becomes
/// [`Error::PackParse`] (QA Q6-10).
///
/// The characters are those of `vmr-verify/src/text.rs` (`display_safe`):
/// the C0 controls (TAB, CR and LF included), DEL, the C1 controls, U+2028
/// and U+2029, every Default_Ignorable code point of Unicode 16.0.0 and every
/// noncharacter. The table is written out again because this crate does not
/// depend on the verifier (P6-10).
pub(crate) fn escape_unsafe(message: &str) -> String {
    if !message.chars().any(is_unsafe) {
        return message.to_string();
    }
    let mut out = String::with_capacity(message.len() + 16);
    for c in message.chars() {
        if is_unsafe(c) {
            out.push_str(&format!("\\u{{{:04x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// `Default_Ignorable_Code_Point`, Unicode 16.0.0, as inclusive ranges: the
/// table of `vmr-verify/src/text.rs`.
const DEFAULT_IGNORABLE: [(u32, u32); 17] = [
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
];

/// Whether [`escape_unsafe`] escapes `c`.
fn is_unsafe(c: char) -> bool {
    let code = u32::from(c);
    code < 0x20
        || (0x7f..=0x9f).contains(&code)
        || matches!(code, 0x2028 | 0x2029)
        || DEFAULT_IGNORABLE.iter().any(|&(lo, hi)| (lo..=hi).contains(&code))
        || (0xFDD0..=0xFDEF).contains(&code)
        || code & 0xFFFE == 0xFFFE
}
