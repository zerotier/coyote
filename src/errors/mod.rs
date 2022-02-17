use crate::acme::ACMEIdentifier;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use self::db::LoadError;

pub mod acme;
pub mod db;

#[derive(Clone, Debug, Error)]
pub enum HandlerError {
    #[error("generic handler error: {0}")]
    Generic(String),
    #[error("ACME validation error: {0}")]
    ACMEValidationError(ACMEValidationError),
}

impl From<ACMEValidationError> for HandlerError {
    fn from(ave: ACMEValidationError) -> Self {
        HandlerError::ACMEValidationError(ave)
    }
}

impl From<url::ParseError> for HandlerError {
    fn from(upe: url::ParseError) -> Self {
        HandlerError::Generic(upe.to_string())
    }
}

impl From<HandlerError> for Error {
    fn from(he: HandlerError) -> Self {
        match he {
            HandlerError::Generic(he) => Error::new(RFCError::Malformed, &he),
            HandlerError::ACMEValidationError(ave) => Error::from(ave),
        }
    }
}

#[derive(Error, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ACMEValidationError {
    #[error("No key provided")]
    NoKeyProvided,

    #[error("url {0} not equal to protected header value: {1}")]
    URLNotEqual(String, String),

    #[error("alg must be {0}, not {1}")]
    AlgNotEqual(String, String),

    #[error("nonce decode error")]
    NonceDecodeError,

    #[error("could not validate nonce")]
    NonceNotFound,

    #[error("Nonce fetching error: {0}")]
    NonceFetchError(String),

    #[error("Other error: {0}")]
    Other(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid request")]
    InvalidRequest,

    #[error("account does not exist")]
    AccountDoesNotExist,
}

impl ratpack::ToStatus for Error {
    fn to_status(&self) -> ratpack::Error {
        match self.error_type {
            RFCError::BadNonce | RFCError::BadPublicKey | RFCError::BadSignatureAlgorithm => {
                ratpack::Error::StatusCode(StatusCode::BAD_REQUEST, self.detail.clone())
            }
            _ => ratpack::Error::StatusCode(StatusCode::FORBIDDEN, self.detail.clone()),
        }
    }
}

impl ratpack::ToStatus for ACMEValidationError {
    fn to_status(&self) -> ratpack::Error {
        let e: Error = self.clone().into();
        e.to_status()
    }
}

impl From<ACMEValidationError> for Error {
    fn from(ave: ACMEValidationError) -> Self {
        match ave.clone() {
            ACMEValidationError::NoKeyProvided
            | ACMEValidationError::NonceDecodeError
            | ACMEValidationError::InvalidRequest => {
                Self::new(RFCError::Malformed, &ave.to_string())
            }
            ACMEValidationError::Other(_)
            | ACMEValidationError::NonceNotFound
            | ACMEValidationError::NonceFetchError(_)
            | ACMEValidationError::URLNotEqual(_, _)
            | ACMEValidationError::InvalidSignature => {
                Self::new(RFCError::Unauthorized, &ave.to_string())
            }
            ACMEValidationError::AlgNotEqual(_, _) => {
                Self::new(RFCError::BadSignatureAlgorithm, &ave.to_string())
            }
            ACMEValidationError::AccountDoesNotExist => {
                Self::new(RFCError::AccountDoesNotExist, &ave.to_string())
            }
        }
    }
}

impl From<url::ParseError> for LoadError {
    fn from(u: url::ParseError) -> Self {
        LoadError::Generic(u.to_string())
    }
}

impl ratpack::ToStatus for acme::JWSError {
    fn to_status(&self) -> ratpack::Error {
        let e: Error = self.clone().into();
        e.to_status()
    }
}

impl From<acme::JWSError> for Error {
    fn from(jws: acme::JWSError) -> Self {
        match jws {
            acme::JWSError::InvalidPublicKey => Self::new(RFCError::BadPublicKey, &jws.to_string()),
            acme::JWSError::Missing => Self::new(RFCError::Malformed, &jws.to_string()),
            _ => Self::new(
                RFCError::Malformed,
                "malformed content during generation or parsing of JWS envelope",
            ),
        }
    }
}

impl ratpack::ToStatus for acme::JWSValidationError {
    fn to_status(&self) -> ratpack::Error {
        let e: Error = self.clone().into();
        e.to_status()
    }
}

impl From<acme::JWSValidationError> for Error {
    fn from(jve: acme::JWSValidationError) -> Self {
        match jve {
            acme::JWSValidationError::ACMEValidationError(e) => e.into(),
            acme::JWSValidationError::General(e) => e.into(),
            _ => Self::new(
                RFCError::Malformed,
                "malformed content during generation or parsing of JWS envelope",
            ),
        }
    }
}

/// All error return values inherit from the URN below.
const ACME_URN_NAMESPACE: &str = "urn:ietf:params:acme:error:";

/// RFCError is for reporting errors conformant to the ACME RFC.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum RFCError {
    AccountDoesNotExist,
    AlreadyRevoked,
    BadCSR,
    BadNonce,
    BadPublicKey,
    BadRevocationReason,
    BadSignatureAlgorithm,
    CAA,
    Compound,
    Connection,
    DNS,
    ExternalAccountRequired,
    IncorrectResponse,
    InvalidContact,
    Malformed,
    OrderNotReady,
    RateLimited,
    RejectedIdentifier,
    ServerInterval,
    TLS,
    Unauthorized,
    UnsupportedContact,
    UnsupportedIdentifier,
    UserActionRequired,
}

impl RFCError {
    /// to_string converts an enum error into the string you should return to the client.
    fn to_string(self) -> String {
        ACME_URN_NAMESPACE.to_string()
            + match self {
                RFCError::AccountDoesNotExist => "accountDoesNotExist",
                RFCError::AlreadyRevoked => "alreadyRevoked",
                RFCError::BadCSR => "badCSR",
                RFCError::BadNonce => "badNonce",
                RFCError::BadPublicKey => "badPublicKey",
                RFCError::BadRevocationReason => "badRevocationReason",
                RFCError::BadSignatureAlgorithm => "badSignatureAlgorithm",
                RFCError::CAA => "caa",
                RFCError::Compound => "compound",
                RFCError::Connection => "connection",
                RFCError::DNS => "dns",
                RFCError::ExternalAccountRequired => "externalAccountRequired",
                RFCError::IncorrectResponse => "incorrectResponse",
                RFCError::InvalidContact => "invalidContact",
                RFCError::Malformed => "malformed",
                RFCError::OrderNotReady => "orderNotReady",
                RFCError::RateLimited => "rateLimited",
                RFCError::RejectedIdentifier => "rejectedIdentifier",
                RFCError::ServerInterval => "serverInterval",
                RFCError::TLS => "tls",
                RFCError::Unauthorized => "unauthorized",
                RFCError::UnsupportedContact => "unsupportedContact",
                RFCError::UnsupportedIdentifier => "unsupportedIdentifier",
                RFCError::UserActionRequired => "userActionRequired",
            }
    }
}

/// ValidationError are for errors in validation of the .. error. See Error::validate for more
/// information.
#[derive(Debug, PartialEq)]
pub enum ValidationError {
    /// MissingContext is returned when details about a specific error are required, and missing
    MissingContext(&'static str),
    /// This error is returned when critical missing detail about the request's subject is missing
    MissingTarget,
    /// This error is returned when the identifier's subject is parsed invalid.
    InvalidIdentifier,
}

/// Error is the error returned to the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Error {
    #[serde(rename = "type")]
    error_type: RFCError,
    #[serde(skip_serializing_if = "Option::is_none")]
    subproblems: Option<Vec<Error>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identifier: Option<ACMEIdentifier>,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_account_binding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_action_instance: Option<String>,
}

impl Error {
    /// new constructs a new error struct. Use methods like subproblems() and identifier() to build
    /// a fully validate()able struct from parts.
    pub fn new(error_type: RFCError, detail: &str) -> Self {
        Self {
            error_type,
            detail: detail.to_string(),
            subproblems: None,
            identifier: None,
            user_action_instance: None,
            external_account_binding: None,
        }
    }

    /// validate the error. For an error to be valid it must:
    /// - have an identifier, or subproblems, and all its subproblems must validate.
    /// - For RFCError::ExternalAccountRequired, external_account_binding() must be called to set data.
    /// - For RFCError::UserActionRequired, user_action_instance() must be called to set data.
    /// - For RFCError::Compound, subproblems must exist.
    pub fn validate(self) -> Result<(), ValidationError> {
        match self.error_type {
            RFCError::ExternalAccountRequired => {
                if self.external_account_binding.is_none() {
                    return Err(ValidationError::MissingContext(
                        "missing external_account_binding",
                    ));
                }
            }
            RFCError::UserActionRequired => {
                if self.user_action_instance.is_none() {
                    return Err(ValidationError::MissingContext(
                        "missing user_action_instance",
                    ));
                }
            }
            RFCError::Compound => {
                if self.subproblems.is_none() {
                    return Err(ValidationError::MissingContext(
                        "missing subproblems in compound error",
                    ));
                }
            }
            _ => {}
        }

        let sp = self.subproblems;

        if self.identifier.is_none() && sp.is_none()
            || (sp.is_some() && sp.clone().unwrap().is_empty())
        {
            return Err(ValidationError::MissingTarget);
        }

        if sp.is_some() {
            for prob in sp.unwrap() {
                if let Err(r) = prob.validate() {
                    return Err(r);
                }
            }
        }

        if self.identifier.is_some() {
            match self.identifier.unwrap() {
                ACMEIdentifier::DNS(name) => {
                    if name.0.is_empty()
                        || name.0.is_root()
                        || name.0.is_localhost()
                        || name.0.is_wildcard()
                        // no TLDs
                        || name.0.num_labels() < 2
                    {
                        return Err(ValidationError::InvalidIdentifier);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn subproblems(mut self, problems: Vec<Error>) -> Self {
        self.subproblems = Some(problems);
        self
    }

    pub fn identifier(mut self, identifier: ACMEIdentifier) -> Self {
        self.identifier = Some(identifier);
        self
    }

    pub fn user_action_instance(mut self, user_action_instance: String) -> Self {
        self.user_action_instance = Some(user_action_instance);
        self
    }

    pub fn external_account_binding(mut self, external_account_binding: String) -> Self {
        self.external_account_binding = Some(external_account_binding);
        self
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

mod tests {
    #[test]
    fn test_validate() {
        use super::{Error, RFCError, ValidationError};
        use crate::acme::{dns::DNSName, ACMEIdentifier};
        use spectral::prelude::*;

        assert_that!(Error::new(RFCError::AccountDoesNotExist, "these are the details").validate())
            .is_err_containing(ValidationError::MissingTarget);

        assert_that!(
            Error::new(RFCError::AccountDoesNotExist, "these are the details")
                .identifier(ACMEIdentifier::DNS(DNSName::from_str("foo.com").unwrap()))
                .validate()
        )
        .is_ok();

        assert_that!(
            Error::new(RFCError::AccountDoesNotExist, "these are the details")
                .subproblems(vec![])
                .validate()
        )
        .is_err_containing(ValidationError::MissingTarget);

        assert_that!(
            Error::new(RFCError::AccountDoesNotExist, "these are the details")
                .subproblems(vec![Error::new(
                    RFCError::AccountDoesNotExist,
                    "these are the details"
                )
                .identifier(ACMEIdentifier::DNS(DNSName::from_str("foo.com").unwrap()))])
                .validate()
        )
        .is_ok();

        let bad_names = vec!["*.foo.com", ".", "yodawg", "localhost"];

        for name in bad_names {
            assert_that!(
                Error::new(RFCError::AccountDoesNotExist, "these are the details")
                    .subproblems(vec![Error::new(
                        RFCError::AccountDoesNotExist,
                        "these are the details"
                    )
                    .identifier(ACMEIdentifier::DNS(DNSName::from_str(name).unwrap()))])
                    .validate()
            )
            .named(name)
            .is_err_containing(ValidationError::InvalidIdentifier);
        }

        assert_that!(
            Error::new(RFCError::AccountDoesNotExist, "these are the details")
                .subproblems(vec![Error::new(
                    RFCError::AccountDoesNotExist,
                    "these are the details"
                )])
                .validate()
        )
        .is_err_containing(ValidationError::MissingTarget);

        assert_that!(
            Error::new(RFCError::ExternalAccountRequired, "these are the details").validate()
        )
        .is_err_containing(ValidationError::MissingContext(
            "missing external_account_binding",
        ));

        assert_that!(Error::new(RFCError::UserActionRequired, "these are the details").validate())
            .is_err_containing(ValidationError::MissingContext(
                "missing user_action_instance",
            ));

        assert_that!(Error::new(RFCError::Compound, "these are the details").validate())
            .is_err_containing(ValidationError::MissingContext(
                "missing subproblems in compound error",
            ));
    }

    #[test]
    fn test_to_string() {
        use super::RFCError;
        use spectral::prelude::*;

        assert_that!(RFCError::AccountDoesNotExist.to_string())
            .is_equal_to("urn:ietf:params:acme:error:accountDoesNotExist".to_string());
        assert_that!(RFCError::AlreadyRevoked.to_string())
            .is_equal_to("urn:ietf:params:acme:error:alreadyRevoked".to_string());
        assert_that!(RFCError::BadCSR.to_string())
            .is_equal_to("urn:ietf:params:acme:error:badCSR".to_string());
        assert_that!(RFCError::BadNonce.to_string())
            .is_equal_to("urn:ietf:params:acme:error:badNonce".to_string());
        assert_that!(RFCError::BadPublicKey.to_string())
            .is_equal_to("urn:ietf:params:acme:error:badPublicKey".to_string());
        assert_that!(RFCError::BadRevocationReason.to_string())
            .is_equal_to("urn:ietf:params:acme:error:badRevocationReason".to_string());
        assert_that!(RFCError::BadSignatureAlgorithm.to_string())
            .is_equal_to("urn:ietf:params:acme:error:badSignatureAlgorithm".to_string());
        assert_that!(RFCError::CAA.to_string())
            .is_equal_to("urn:ietf:params:acme:error:caa".to_string());
        assert_that!(RFCError::Compound.to_string())
            .is_equal_to("urn:ietf:params:acme:error:compound".to_string());
        assert_that!(RFCError::Connection.to_string())
            .is_equal_to("urn:ietf:params:acme:error:connection".to_string());
        assert_that!(RFCError::DNS.to_string())
            .is_equal_to("urn:ietf:params:acme:error:dns".to_string());
        assert_that!(RFCError::ExternalAccountRequired.to_string())
            .is_equal_to("urn:ietf:params:acme:error:externalAccountRequired".to_string());
        assert_that!(RFCError::IncorrectResponse.to_string())
            .is_equal_to("urn:ietf:params:acme:error:incorrectResponse".to_string());
        assert_that!(RFCError::InvalidContact.to_string())
            .is_equal_to("urn:ietf:params:acme:error:invalidContact".to_string());
        assert_that!(RFCError::Malformed.to_string())
            .is_equal_to("urn:ietf:params:acme:error:malformed".to_string());
        assert_that!(RFCError::OrderNotReady.to_string())
            .is_equal_to("urn:ietf:params:acme:error:orderNotReady".to_string());
        assert_that!(RFCError::RateLimited.to_string())
            .is_equal_to("urn:ietf:params:acme:error:rateLimited".to_string());
        assert_that!(RFCError::RejectedIdentifier.to_string())
            .is_equal_to("urn:ietf:params:acme:error:rejectedIdentifier".to_string());
        assert_that!(RFCError::ServerInterval.to_string())
            .is_equal_to("urn:ietf:params:acme:error:serverInterval".to_string());
        assert_that!(RFCError::TLS.to_string())
            .is_equal_to("urn:ietf:params:acme:error:tls".to_string());
        assert_that!(RFCError::Unauthorized.to_string())
            .is_equal_to("urn:ietf:params:acme:error:unauthorized".to_string());
        assert_that!(RFCError::UnsupportedContact.to_string())
            .is_equal_to("urn:ietf:params:acme:error:unsupportedContact".to_string());
        assert_that!(RFCError::UnsupportedIdentifier.to_string())
            .is_equal_to("urn:ietf:params:acme:error:unsupportedIdentifier".to_string());
        assert_that!(RFCError::UserActionRequired.to_string())
            .is_equal_to("urn:ietf:params:acme:error:userActionRequired".to_string());
    }
}
