//! The builder's error type.
// ============================================================================
//  error.rs — record-builder errors
//
//  vmr_record::Error's variants, one for one with the same messages: the
//  assembly moved here from vmr-provenance (task 10.13a, B1), whose own Error
//  converts from this one variant for variant, so every refusal of the
//  engine profile's builder reads exactly as it did before the move.
// ============================================================================

/// Every failure the record builder can produce.
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

    /// A builder input is missing or inconsistent.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl From<vmr_record::Error> for Error {
    fn from(e: vmr_record::Error) -> Self {
        match e {
            vmr_record::Error::Json(e) => Error::Json(e),
            vmr_record::Error::Cose(m) => Error::Cose(m),
            vmr_record::Error::Signature(e) => Error::Signature(e),
            vmr_record::Error::Base64Url(m) => Error::Base64Url(m),
            vmr_record::Error::InvalidInput(m) => Error::InvalidInput(m),
        }
    }
}
