use super::ACMEValidationError;
use openssl::error::ErrorStack;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// JWSValidationError is a mostly-internal encapsulation of JWS errors encountered while
/// validating the signature.
#[derive(Clone, Error, Debug, PartialEq, Serialize, Deserialize)]
pub enum JWSValidationError {
    #[error("general JWS handshake error: {0:?}")]
    General(JWSError),
    #[error("base64 error decoding signature")]
    SignatureDecode,
    #[error("openssl internal error managing signature: {0}")]
    OpenSSL(String),
    #[error("error validating ACME payload: {0}")]
    ACMEValidationError(ACMEValidationError),
}

impl From<JWSError> for JWSValidationError {
    fn from(e: JWSError) -> Self {
        Self::General(e)
    }
}

impl From<base64::DecodeError> for JWSValidationError {
    fn from(_: base64::DecodeError) -> Self {
        Self::SignatureDecode
    }
}

impl From<ErrorStack> for JWSValidationError {
    fn from(es: ErrorStack) -> Self {
        let errors = es
            .errors()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        Self::OpenSSL(errors.join("\n"))
    }
}

/// JWSError is like [JWSValidationError] but for more general situations surrounding JWS usage.
#[derive(Clone, Error, Debug, PartialEq, Serialize, Deserialize)]
pub enum JWSError {
    #[error("openssl error: {0}")]
    OpenSSL(String),
    #[error("error encoding JWS component: {0}")]
    Encode(String),
    #[error("serde error decoding JSON: {0}")]
    JSONDecode(String),
    #[error("base64 error decoding payload")]
    PayloadDecode,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("missing JWS")]
    Missing,
    #[error("validation failed")]
    ValidationFailed,
}

impl From<ErrorStack> for JWSError {
    fn from(es: ErrorStack) -> Self {
        let errors = es
            .errors()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        Self::OpenSSL(errors.join("\n"))
    }
}

impl From<base64::DecodeError> for JWSError {
    fn from(_: base64::DecodeError) -> Self {
        Self::PayloadDecode
    }
}

impl From<serde_json::Error> for JWSError {
    fn from(e: serde_json::Error) -> Self {
        Self::JSONDecode(e.to_string())
    }
}
