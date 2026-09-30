// ============================================================================
//  types.rs — the value types the format reads, and the member types its
//  profiles share (`specs/audit-log-format-v0.1.md` §2, §5.2;
//  `specs/audit-profile-agent-v0.1.md` §2).
//
//  Neither profile owns this module: the core reads its hashes here, and each
//  profile takes the types it states from here, so one profile never builds
//  on another's (a vendor's profile may leave this crate; the general one
//  must not break when it does).
//
//  A hash is lower case only (core §2 rule 7). `vmr_record::hash::parse_hash`
//  decodes any case, as its callers in the record format need no more; this
//  format asks for the canonical spelling, so it reads hashes here.
// ============================================================================

//! The format's value types (core §2) and the member types the profiles
//! share.

use serde_json::Value;
use vmr_record::hash::DIGEST_LEN;

/// 64 lower-case hexadecimal digits: a hash's (core §2 rule 7), and the
/// `vmr.agent` profile's digest's.
pub(crate) fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A hash (core §2 rule 7): `sha256:` and 64 lower-case hexadecimal digits,
/// decoded. Any other spelling, upper or mixed case included, is `None`.
pub(crate) fn parse_hash(text: &str) -> Option<[u8; DIGEST_LEN]> {
    if !text.strip_prefix("sha256:").is_some_and(is_lower_hex_64) {
        return None;
    }
    vmr_record::hash::parse_hash(text).ok()
}

/// Whether `v` is a hash (core §2 rule 7).
pub(crate) fn is_hash(v: &Value) -> bool {
    v.as_str().is_some_and(|s| parse_hash(s).is_some())
}

/// A lower-case canonical UUID URN (core §2 rule 8).
pub(crate) fn is_uuid_urn(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("urn:uuid:") else { return false };
    let groups = [8usize, 4, 4, 4, 12];
    let parts: Vec<&str> = rest.split('-').collect();
    parts.len() == groups.len()
        && parts.iter().zip(groups).all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
}

/// Whether `v` is a UUID URN (core §2 rule 8).
pub(crate) fn is_uuid(v: &Value) -> bool {
    v.as_str().is_some_and(is_uuid_urn)
}

/// A refusal id: `^[a-z_]+\.[a-z_]+$`.
pub(crate) fn is_refusal_id(s: &str) -> bool {
    match s.split_once('.') {
        Some((ns, name)) => {
            !ns.is_empty()
                && !name.is_empty()
                && ns.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        }
        None => false,
    }
}

/// Whether `v` is a refusal id.
pub(crate) fn is_refusal(v: &Value) -> bool {
    v.as_str().is_some_and(is_refusal_id)
}

/// A u64 as text: decimal digits without leading zeros, naming an integer
/// from 0 to 2^64 − 1.
pub(crate) fn is_decimal_u64(s: &str) -> bool {
    if s == "0" {
        return true;
    }
    !s.is_empty() && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u64>().is_ok()
}

/// Whether `v` is a u64 as text.
pub(crate) fn is_u64_string(v: &Value) -> bool {
    v.as_str().is_some_and(is_decimal_u64)
}

/// An integer (core §2 rule 5) of at least 1.
pub(crate) fn is_pos_int(v: &Value) -> bool {
    v.as_u64().is_some_and(|n| (1..=vmr_record::canonical::MAX_SAFE_INTEGER).contains(&n))
}

/// An integer (core §2 rule 5): 0 to 2^53 − 1.
pub(crate) fn is_safe_int(v: &Value) -> bool {
    v.as_u64().is_some_and(|n| n <= vmr_record::canonical::MAX_SAFE_INTEGER)
}
