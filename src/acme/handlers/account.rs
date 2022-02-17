use std::convert::{TryFrom, TryInto};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use ratpack::prelude::*;

use super::{uri_to_url, HandlerState, ServiceState};
use crate::{
    errors::{acme::JWSError, ACMEValidationError},
    models::{
        account::{new_accounts, JWK},
        Record,
    },
};

/// RFC8555 7.1.2
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    status: AccountStatus,
    contact: Option<Vec<AccountUrl>>,
    terms_of_service_agreed: Option<bool>,
    external_account_binding: Option<ExternalBinding>,
    orders: Option<Url>,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            status: AccountStatus::Revoked,
            contact: None,
            terms_of_service_agreed: None,
            external_account_binding: None,
            orders: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountUrl(Url);

#[derive(Debug, Clone, Error)]
pub enum AccountUrlError {
    #[error("invalid url scheme for account")]
    InvalidScheme,
    #[error("unknown error: {0}")]
    Other(String),
}

impl TryFrom<&str> for AccountUrl {
    type Error = AccountUrlError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match Url::parse(s) {
            Ok(url) => url.try_into(),
            Err(e) => Err(AccountUrlError::Other(e.to_string())),
        }
    }
}

impl TryFrom<Url> for AccountUrl {
    type Error = AccountUrlError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        // RFC8555 7.3
        if url.scheme() != "mailto" {
            return Err(AccountUrlError::InvalidScheme);
        }

        Ok(Self(url))
    }
}

impl Into<String> for AccountUrl {
    fn into(self) -> String {
        self.0.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalBinding {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccount {
    pub contact: Option<Vec<AccountUrl>>,
    pub terms_of_service_agreed: Option<bool>,
    pub only_return_existing: Option<bool>,
    pub external_account_binding: Option<ExternalBinding>,
}

impl NewAccount {
    pub fn contacts(&self) -> Option<Vec<AccountUrl>> {
        self.contact.clone()
    }

    pub fn is_deleted(&self) -> bool {
        self.contact.is_none() || self.contact.as_ref().unwrap().is_empty()
    }

    pub fn to_account(&self) -> Account {
        Account {
            status: AccountStatus::Valid,
            contact: self.contact.clone(),
            terms_of_service_agreed: self.terms_of_service_agreed,
            external_account_binding: None,
            orders: None, // FIXME needs to be populated with a slug for user orders
        }
    }
}

impl Default for NewAccount {
    fn default() -> Self {
        Self {
            contact: None,
            terms_of_service_agreed: None,
            only_return_existing: None,
            external_account_binding: None,
        }
    }
}

pub(crate) async fn new_account(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    _params: Params,
    app: App<ServiceState, HandlerState>,
    state: HandlerState,
) -> HTTPResult<HandlerState> {
    let appstate_opt = app.state().await.clone().unwrap();
    let appstate = appstate_opt.lock().await;

    match state.clone().jws {
        Some(mut jws) => {
            let newacct = jws.clone().payload::<NewAccount>()?;
            let uri = req.uri().clone();
            let url = uri_to_url(appstate.clone().baseurl, uri).await?;

            let protected = jws.protected()?;

            if protected.kid().is_some() && newacct.only_return_existing.unwrap_or_default() {
                let rec =
                    match JWK::find_by_kid(protected.kid().unwrap(), appstate.db.clone()).await {
                        Ok(rec) => rec,
                        Err(_) => return Err(ACMEValidationError::AccountDoesNotExist.to_status()),
                    };

                let resp = state
                    .decorate_response(url.clone(), Response::builder())?
                    .status(StatusCode::OK)
                    .header(
                        "Location",
                        url.clone()
                            .join(&format!("./account/{}", &rec.clone().nonce_key()))?
                            .to_string(),
                    )
                    .body(Body::from(serde_json::to_string(&rec)?))
                    .unwrap();
                return Ok((req, Some(resp), state));
            } else {
                let mut jwk = jws.into_db_jwk()?;

                jwk.create(appstate.db.clone()).await?;

                let mut acct = new_accounts(newacct.clone(), jwk.clone(), appstate.db.clone())?;
                acct.create(appstate.db.clone()).await?;

                let resp = state
                    .decorate_response(url.clone(), Response::builder())?
                    .status(StatusCode::CREATED)
                    .header(
                        "Location",
                        url.join(&format!("./account/{}", &jwk.nonce_key()))?
                            .to_string(),
                    )
                    .body(Body::from(serde_json::to_string(&newacct.to_account())?))
                    .unwrap();
                return Ok((req, Some(resp), state));
            }
        }
        None => {
            return Err(ratpack::Error::StatusCode(
                StatusCode::NOT_FOUND,
                String::default(),
            ))
        }
    }
}

pub(crate) async fn post_account(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    _params: Params,
    app: App<ServiceState, HandlerState>,
    state: HandlerState,
) -> HTTPResult<HandlerState> {
    let appstate_opt = app.state().await.clone().unwrap();
    let appstate = appstate_opt.lock().await;

    // FIXME this still needs code to update contact lists; see 7.3.2.
    match state.clone().jws {
        Some(mut jws) => {
            let acct: Account = jws.payload()?;

            match acct.status {
                AccountStatus::Deactivated => {
                    let aph = jws.protected()?;
                    let kid = aph.kid();

                    if kid.is_none() {
                        return Err(JWSError::InvalidPublicKey.to_status());
                    }

                    let kid = kid.unwrap();
                    let target = JWK::find_by_kid(kid, appstate.db.clone()).await?;
                    let target_jwk: crate::acme::jose::JWK = target.clone().try_into()?;

                    match target_jwk.try_into() {
                        Ok(key) => match jws.verify(key) {
                            Ok(b) => {
                                if !b {
                                    return Err(ACMEValidationError::InvalidSignature.to_status());
                                }
                            }
                            Err(e) => return Err(e.into()),
                        },
                        Err(e) => return Err(e.into()),
                    }

                    target.delete(appstate.db.clone()).await?;
                    let url = uri_to_url(appstate.clone().baseurl, req.uri().clone()).await?;

                    return Ok((
                        req,
                        Some(
                            state
                                .decorate_response(url.clone(), Response::builder())?
                                .status(StatusCode::OK)
                                .body(Body::from(serde_json::to_string(&target)?))
                                .unwrap(),
                        ),
                        state,
                    ));
                }
                _ => {}
            }
        }
        None => {
            return Err(ratpack::Error::StatusCode(
                StatusCode::NOT_FOUND,
                String::default(),
            ))
        }
    }

    return Err(ACMEValidationError::InvalidRequest.to_status());
}

mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn new_account_failures() {
        use crate::test::TestService;
        use http::StatusCode;
        use hyper::Body;
        use spectral::prelude::*;

        let srv = TestService::new("new_account_failures").await;
        let res = srv.clone().app.get("/account").await;
        assert_that!(res.status()).is_equal_to(StatusCode::METHOD_NOT_ALLOWED);

        let res = srv.clone().app.post("/account", Body::default()).await;
        assert_that!(res.status()).is_equal_to(StatusCode::FORBIDDEN);

        let res = srv.clone().app.post("/account/herp", Body::default()).await;
        assert_that!(res.status()).is_equal_to(StatusCode::FORBIDDEN);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn account_register_with_certbot() {
        use crate::test::TestService;
        use spectral::prelude::*;

        let srv = TestService::new("account_register_with_certbot").await;

        for _ in 0..10 {
            let res = srv
                .clone()
                .certbot(
                    None,
                    "register -m 'erik@hollensbe.org' --agree-tos".to_string(),
                )
                .await;
            assert_that!(res).is_ok();

            let dir = res.unwrap();

            let res = srv
                .clone()
                .certbot(
                    Some(dir.clone()),
                    "unregister -m 'erik@hollensbe.org'".to_string(),
                )
                .await;
            assert_that!(res).is_ok();
        }
    }
}
