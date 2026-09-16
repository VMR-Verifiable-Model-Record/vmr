//! Names, the member encoding and the named-set digest (spec §7.2; task
//! 10.11b, D11b-2).
// ============================================================================
//  named_set.rs — sets of named byte strings
//
//  A model's files, a general record's components (spec §7.3) and
//  `named-set-v1` training records (§8.2) are sets of named byte strings.
//
//  - A name is one or more segments joined by `/`; no segment is empty, `.`
//    or `..`. Names are compared exactly: no case folding, no normalisation.
//  - A set is written in ascending order of its names' UTF-8 bytes (the order
//    of Unicode scalar values), none repeated.
//  - A member's encoding is u64be(name byte length) || name || SHA-256 of the
//    member. It binds the name: renaming a member and moving content from one
//    name to another give different digests.
//  - The named-set digest is SHA-256 over the encodings, in order. It is
//    computed in one pass: nothing but the previous name is kept.
//
//  No I/O here: walking a directory, following links and reading files are a
//  tool's, which must apply §7.2's file rules.
// ============================================================================

use crate::hash::DIGEST_LEN;
use sha2::{Digest, Sha256};

/// Why a name, or its place in a set, is refused (spec §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// The name is the empty string.
    Empty,
    /// A segment is empty: the name starts or ends with `/`, or holds `//`.
    EmptySegment,
    /// A segment is `.`.
    DotSegment,
    /// A segment is `..`.
    DotDotSegment,
    /// The name does not come after the name before it: the set is out of
    /// order, or repeats a name.
    NotAscending,
}

impl NameError {
    /// What is wrong, in words.
    pub fn reason(self) -> &'static str {
        match self {
            NameError::Empty => "a name is not empty",
            NameError::EmptySegment => "a name has no empty segment (no leading, trailing or double /)",
            NameError::DotSegment => "a name has no . segment",
            NameError::DotDotSegment => "a name has no .. segment",
            NameError::NotAscending => "names ascend by Unicode scalar value, none repeated",
        }
    }
}

impl std::fmt::Display for NameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for NameError {}

/// Check one name against spec §7.2: one or more `/`-separated segments,
/// none of them empty, `.` or `..`.
pub fn validate_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    for segment in name.split('/') {
        match segment {
            "" => return Err(NameError::EmptySegment),
            "." => return Err(NameError::DotSegment),
            ".." => return Err(NameError::DotDotSegment),
            _ => {}
        }
    }
    Ok(())
}

/// Whether `later` may follow `earlier` in a set: its UTF-8 bytes are
/// strictly greater (spec §7.2).
pub fn ascends(earlier: &str, later: &str) -> bool {
    earlier.as_bytes() < later.as_bytes()
}

/// A member's encoding `E(n, b)`: the u64 big-endian byte length of the name,
/// the name's UTF-8 bytes, then the 32 bytes of the member's SHA-256. It is
/// also a `named-set-v1` record's Merkle leaf data (spec §8.2).
pub fn member_encoding(name: &str, digest: &[u8; DIGEST_LEN]) -> Vec<u8> {
    let n = name.as_bytes();
    let mut out = Vec::with_capacity(8 + n.len() + DIGEST_LEN);
    out.extend_from_slice(&(n.len() as u64).to_be_bytes());
    out.extend_from_slice(n);
    out.extend_from_slice(digest);
    out
}

/// The named-set digest, computed one member at a time, in order.
#[derive(Clone)]
pub struct NamedSetDigest {
    hasher: Sha256,
    previous: Option<String>,
    count: u64,
}

impl Default for NamedSetDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl NamedSetDigest {
    /// A digest of no members yet.
    pub fn new() -> Self {
        NamedSetDigest { hasher: Sha256::new(), previous: None, count: 0 }
    }

    /// Add the member named `name` whose SHA-256 is `digest`. Refuses a name
    /// that breaks §7.2, or that does not come after the previous one; a
    /// refused member is not added.
    pub fn push(&mut self, name: &str, digest: &[u8; DIGEST_LEN]) -> Result<(), NameError> {
        validate_name(name)?;
        if self.previous.as_deref().is_some_and(|previous| !ascends(previous, name)) {
            return Err(NameError::NotAscending);
        }
        self.hasher.update((name.len() as u64).to_be_bytes());
        self.hasher.update(name.as_bytes());
        self.hasher.update(digest);
        self.previous = Some(name.to_owned());
        self.count += 1;
        Ok(())
    }

    /// How many members were added.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The digest of the members added, in their order.
    pub fn finish(self) -> [u8; DIGEST_LEN] {
        let out = self.hasher.finalize();
        let mut buf = [0u8; DIGEST_LEN];
        buf.copy_from_slice(&out);
        buf
    }
}

/// The named-set digest of `members`, given in their order. On a refusal,
/// the index of the member refused and why.
pub fn named_set_digest<N: AsRef<str>>(
    members: &[(N, [u8; DIGEST_LEN])],
) -> Result<[u8; DIGEST_LEN], (usize, NameError)> {
    let mut digest = NamedSetDigest::new();
    for (i, (name, hash)) in members.iter().enumerate() {
        digest.push(name.as_ref(), hash).map_err(|e| (i, e))?;
    }
    Ok(digest.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;

    fn hex_digest(members: &[(&str, [u8; DIGEST_LEN])]) -> String {
        hex::encode(named_set_digest(members).unwrap())
    }

    #[test]
    fn the_spec_example_values() {
        // Spec §7.2's example, computed independently with Python's hashlib.
        let config = sha256(b"{}");
        let weights = sha256(&[0u8; 4]);
        assert_eq!(hex::encode(config), "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
        assert_eq!(hex::encode(weights), "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119");
        assert_eq!(
            hex_digest(&[("config.json", config), ("weights.bin", weights)]),
            "bcd9ed61d08e582e69d37afb23dbf37c69b14a3e26d1751a7d6ac6f12803c6d3"
        );
        assert_eq!(
            hex_digest(&[("weights.bin", weights)]),
            "c32b0039edc7ed971446e62f8701b5a835f9c15b3fbac208f318e2626b9650ea"
        );
        assert_eq!(hex_digest(&[]), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(
            hex::encode(member_encoding("weights.bin", &weights)),
            "000000000000000b776569676874732e62696edf3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
        );
    }

    #[test]
    fn a_rename_and_a_swap_give_different_digests() {
        // The reviewer's case (plan §10): {a: X, b: Y} renamed to {b: Y, c: X},
        // and swapped to {a: Y, b: X}. Over content hashes alone both would be
        // SHA-256(Y || X).
        let (x, y) = (sha256(b"X"), sha256(b"Y"));
        let original = hex_digest(&[("a", x), ("b", y)]);
        let renamed = hex_digest(&[("b", y), ("c", x)]);
        let swapped = hex_digest(&[("a", y), ("b", x)]);
        assert_eq!(original, "fef18a2e078e52eb7209c7e438831a1d3af4ee88ec7ccc248987bbd66617b277");
        assert_eq!(renamed, "bdfbb7ad36c0360ae665a90f1aa780a99bef2e8eb711fe1ab075b7a175939f58");
        assert_eq!(swapped, "004d69b6b3440d46f48174541ff4ac3518e2a0845592c287e8c7f1de740c2c39");
        assert_ne!(renamed, swapped);
    }

    #[test]
    fn names_follow_the_segment_rules() {
        for good in ["a", "config.json", "unet/diffusion_pytorch_model.safetensors", ".hidden", "a..b", "...", "a b"] {
            assert_eq!(validate_name(good), Ok(()), "{good:?}");
        }
        for (bad, why) in [
            ("", NameError::Empty),
            ("/a", NameError::EmptySegment),
            ("a/", NameError::EmptySegment),
            ("a//b", NameError::EmptySegment),
            ("/", NameError::EmptySegment),
            (".", NameError::DotSegment),
            ("a/./b", NameError::DotSegment),
            ("..", NameError::DotDotSegment),
            ("a/../b", NameError::DotDotSegment),
        ] {
            assert_eq!(validate_name(bad), Err(why), "{bad:?}");
        }
    }

    #[test]
    fn a_set_ascends_by_scalar_value_not_by_utf16() {
        // U+FF5E (UTF-8 ef bd 9e) comes before U+1F600 (f0 9f 98 80) here;
        // under JCS's UTF-16 order (spec §3) U+1F600 (d83d de00) comes first.
        let h = sha256(b"");
        assert!(named_set_digest(&[("\u{ff5e}", h), ("\u{1f600}", h)]).is_ok());
        assert_eq!(named_set_digest(&[("\u{1f600}", h), ("\u{ff5e}", h)]), Err((1, NameError::NotAscending)));
        assert_eq!(named_set_digest(&[("b", h), ("a", h)]), Err((1, NameError::NotAscending)));
        assert_eq!(named_set_digest(&[("a", h), ("a", h)]), Err((1, NameError::NotAscending)));
        assert_eq!(named_set_digest(&[("a", h), ("a/", h)]), Err((1, NameError::EmptySegment)));
    }

    #[test]
    fn a_refused_member_leaves_the_digest_as_it_was() {
        let h = sha256(b"m");
        let mut d = NamedSetDigest::new();
        d.push("b", &h).unwrap();
        assert_eq!(d.push("a", &h), Err(NameError::NotAscending));
        assert_eq!(d.count(), 1);
        assert_eq!(d.finish(), named_set_digest(&[("b", h)]).unwrap());
    }
}
