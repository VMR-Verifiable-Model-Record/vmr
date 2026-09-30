// ============================================================================
//  digest.rs — the keyed digests of the `vmr.agent` profile
//  (`specs/audit-profile-agent-v0.1.md` §3).
//
//  A plain SHA-256 of a short or guessable item is reversed by hashing
//  candidates, so every digest of content in the profile is an HMAC-SHA-256
//  under a key the log never holds: the content secret, a session key derived
//  from it, and an item key per digest member of each entry. HMAC and SHA-256
//  come from the `hmac` and `sha2` crates; nothing here reimplements them
//  (Refusal 4). A secret's bytes never appear in a `Debug` output.
// ============================================================================

//! The keyed digests of §3: [`ContentSecret`] → [`SessionKey`] →
//! [`ItemKey`] → the digest string.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

/// Every key of §3 is 32 bytes.
pub const KEY_LEN: usize = 32;

/// What a digest starts with (§2's digest type).
pub const DIGEST_PREFIX: &str = "hmac-sha256:";

/// HMAC-SHA-256 of `message` under `key`.
fn hmac_sha256(key: &[u8; KEY_LEN], message: &[u8]) -> [u8; KEY_LEN] {
    // HMAC takes a key of any length (RFC 2104 §2), and `hmac` refuses no
    // length in `new_from_slice`: this cannot fail.
    #[allow(clippy::expect_used)]
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// The content secret (§3): 32 bytes a writer draws at random when it starts
/// a log and keeps on the device beside the log's audit key. It is not the
/// audit key, never appears in a log, and belongs to one log. Its `Debug`
/// output does not show its bytes.
#[derive(Clone)]
pub struct ContentSecret([u8; KEY_LEN]);

impl ContentSecret {
    /// The secret whose bytes are `bytes`.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> ContentSecret {
        ContentSecret(bytes)
    }

    /// The secret's bytes, for the writer that keeps it.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// The session key of the session `session_id` (§3):
    /// `HMAC-SHA-256(content secret, session_id)`, over the UTF-8 bytes of the
    /// whole id, `urn:uuid:` included.
    pub fn session_key(&self, session_id: &str) -> SessionKey {
        SessionKey(hmac_sha256(&self.0, session_id.as_bytes()))
    }
}

impl fmt::Debug for ContentSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContentSecret(..)")
    }
}

/// A session's key (§3). It opens every item of its session to guessing, so
/// a holder gives it out only when that is the question. Its `Debug` output
/// does not show its bytes.
#[derive(Clone)]
pub struct SessionKey([u8; KEY_LEN]);

impl SessionKey {
    /// The key whose bytes are `bytes`, as a holder gave it out.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> SessionKey {
        SessionKey(bytes)
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// The item key of the digest member `member` of the entry of kind `kind`
    /// at `index` (§3): `HMAC-SHA-256(session key, label)`, the label
    /// [`label`]'s.
    pub fn item_key(&self, kind: &str, member: &str, index: u64) -> ItemKey {
        ItemKey(hmac_sha256(&self.0, label(kind, member, index).as_bytes()))
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey(..)")
    }
}

/// One digest member's key (§3): what a holder discloses, with the content,
/// to show that the content is what the entry committed to. It reveals
/// nothing about any other item. Its `Debug` output does not show its bytes.
#[derive(Clone)]
pub struct ItemKey([u8; KEY_LEN]);

impl ItemKey {
    /// The key whose bytes are `bytes`, as a holder disclosed it.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> ItemKey {
        ItemKey(bytes)
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// The digest of `content` (§3): `hmac-sha256:` and the lower-case
    /// hexadecimal of `HMAC-SHA-256(item key, content)`. `content` is the
    /// bytes as the runtime received them, or [`json_content`] of a value it
    /// received only parsed.
    pub fn digest(&self, content: &[u8]) -> String {
        format!("{DIGEST_PREFIX}{}", hex::encode(hmac_sha256(&self.0, content)))
    }
}

impl fmt::Debug for ItemKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ItemKey(..)")
    }
}

/// An item key's label (§3): `<kind>/<member>/<index>`, the index in decimal
/// without leading zeros. Example: `call.proposed/arguments_digest/1043`.
pub fn label(kind: &str, member: &str, index: u64) -> String {
    format!("{kind}/{member}/{index}")
}

/// The content of an item the runtime received only as a parsed JSON value
/// (§3): the UTF-8 bytes of its JCS form (RFC 8785).
pub fn json_content(value: &Value) -> Vec<u8> {
    vmr_record::canonical::jcs(value).into_bytes()
}

/// Whether `text` is of §2's digest type: `hmac-sha256:` and 64 lower-case
/// hexadecimal digits.
pub fn is_digest(text: &str) -> bool {
    text.strip_prefix(DIGEST_PREFIX).is_some_and(crate::types::is_lower_hex_64)
}
