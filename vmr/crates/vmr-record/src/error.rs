//! The record format's error type.
// ============================================================================
//  error.rs — record-format errors
//
//  The builder crate (vmr-provenance) wraps these in its own Error, which
//  adds the engine variant, variant for variant with the same messages.
// ============================================================================

/// Every failure the record format code can produce.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// JSON (de)serialization failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// COSE envelope encode/decode failed.
    #[error("cose: {0}")]
    Cose(String),

    /// ECDSA signing or verification failed.
    #[error("signature: {0}")]
    Signature(#[from] p256::ecdsa::Error),

    /// Base64url text was malformed.
    #[error("base64url: {0}")]
    Base64Url(String),

    /// An input is missing or inconsistent.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

// coset's CoseError does not implement std::error::Error, so thiserror's
// #[from] cannot wrap it; convert manually.
impl From<coset::CoseError> for Error {
    fn from(e: coset::CoseError) -> Self {
        Error::Cose(format!("{e}"))
    }
}
