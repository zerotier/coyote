/// Certificate Authority functionality
pub mod ca;
/// Challenge management, including supervisory handlers.
pub mod challenge;
/// Types for managing DNS records
pub mod dns;
/// ACME HTTP handlers
pub mod handlers;
/// ACME JOSE implementation
pub mod jose;

use std::{collections::HashSet, convert::TryFrom, sync::Arc};

use hyper::Body;
use tokio::sync::Mutex;

use async_trait::async_trait;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use crate::{
    errors::{
        db::{LoadError, SaveError},
        ACMEValidationError,
    },
    models::{nonce::Nonce, Postgres, Record},
    util::make_nonce,
};

use self::dns::DNSName;

lazy_static! {
    /// List of supported algorithms, with the ACME preferred one first; in our case this is
    /// "ES256".
    pub static ref ACME_EXPECTED_ALGS: [String; 2] = ["ES256".to_string(), "RS256".to_string()];
}

/// A Result<> that calls can return to trampoline through ratpack handlers swiftly by triggering HTTP
/// "problem documents" (RFC7807) to be returned immediately from ratpack's routing framework.
#[must_use]
pub enum ACMEResult {
    Ok(hyper::Response<Body>),
    Err(crate::errors::Error),
}

impl Into<Result<hyper::Response<Body>, serde_json::Error>> for ACMEResult {
    fn into(self) -> Result<hyper::Response<Body>, serde_json::Error> {
        match self {
            ACMEResult::Ok(res) => Ok(res),
            ACMEResult::Err(e) => {
                return Ok(hyper::Response::builder()
                    .status(500)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&e)?))
                    .unwrap())
            }
        }
    }
}

impl From<crate::errors::Error> for ACMEResult {
    fn from(e: crate::errors::Error) -> Self {
        return ACMEResult::Err(e);
    }
}

/// Defines the notion of an "identifier" from the ACME specification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")] // NOTE: other identifier types as they are added may break this
#[serde(tag = "type", content = "value")]
pub enum ACMEIdentifier {
    DNS(dns::DNSName), // NOTE: DNS names cannot be wildcards.
}

impl TryFrom<String> for ACMEIdentifier {
    type Error = LoadError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match DNSName::from_str(&value) {
            Ok(x) => Ok(ACMEIdentifier::DNS(x)),
            Err(e) => Err(LoadError::Generic(e.to_string())),
        }
    }
}

impl ACMEIdentifier {
    pub fn to_string(self) -> String {
        match self {
            ACMEIdentifier::DNS(name) => name.to_string(),
        }
    }
}

#[async_trait]
/// NonceValidator is a storage trait that controls the generation and validation of nonces, used
/// heavily in ACME and especially in the `Replay-Nonce` HTTP header present in all calls, and the
/// `nonce` field in ACME protected headers.
pub trait NonceValidator {
    /// This function must mutate the underlying storage to prune the nonce it's validating after a
    /// successful fetch. One may use ACMEValidationError::NonceFetchError to specify errors with
    /// fetching the Nonce. Likewise, ACMEValidationError::NonceNotFound is expected to be returned
    /// when the nonce cannot be located (validation error).
    async fn validate(&self, nonce: &str) -> Result<(), ACMEValidationError>;

    /// This function is expected to always make & store a new nonce; if it fails to add because it already
    /// exists, it should return error.
    async fn make(&self) -> Result<String, SaveError>;
}

/// Defines a basic (very basic) Nonce validation system
#[derive(Debug, Clone)]
pub struct SetValidator(Arc<Mutex<HashSet<String>>>);

impl Default for SetValidator {
    fn default() -> Self {
        SetValidator(Arc::new(Mutex::new(HashSet::new())))
    }
}

#[async_trait]
impl NonceValidator for SetValidator {
    async fn validate(&self, nonce: &str) -> Result<(), ACMEValidationError> {
        if self.0.lock().await.remove(nonce) {
            Ok(())
        } else {
            Err(ACMEValidationError::NonceNotFound)
        }
    }

    async fn make(&self) -> Result<String, SaveError> {
        let nonce = make_nonce(None);

        if !self.0.lock().await.insert(nonce.clone()) {
            return Err(SaveError::Generic("could not persist nonce".to_string()));
        }

        Ok(nonce)
    }
}

#[derive(Clone)]
/// Defines a PostgreSQL-backed nonce validator
pub struct PostgresNonceValidator(crate::models::Postgres);

impl PostgresNonceValidator {
    pub fn new(pg: Postgres) -> Self {
        Self(pg)
    }
}

#[async_trait]
impl NonceValidator for PostgresNonceValidator {
    async fn validate(&self, nonce: &str) -> Result<(), ACMEValidationError> {
        let nonce = match Nonce::find(nonce.to_string(), self.0.clone()).await {
            Ok(nonce) => nonce,
            Err(_) => return Err(ACMEValidationError::NonceNotFound),
        };

        if let Err(_) = nonce.delete(self.0.clone()).await {
            return Err(ACMEValidationError::NonceNotFound);
        }

        Ok(())
    }

    async fn make(&self) -> Result<String, SaveError> {
        let mut nonce = Nonce::new();
        nonce.create(self.0.clone()).await?;
        Ok(nonce.id().unwrap().unwrap())
    }
}
