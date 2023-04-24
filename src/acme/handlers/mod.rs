use std::convert::TryInto;

use crate::{
    acme::{
        ca::CACollector,
        challenge::Challenger,
        handlers::{
            account::{new_account, post_account},
            directory::directory,
            nonce::{new_nonce_get, new_nonce_head},
            order::{
                existing_order, finalize_order, get_certificate, new_order, post_authz,
                post_challenge,
            },
        },
        jose::{ACMEKey, JWK},
        NonceValidator, PostgresNonceValidator,
    },
    errors::{acme::JWSError, ACMEValidationError, Error, HandlerError},
    models::Postgres,
};
use http::response::Builder;
use ratpack::prelude::*;

pub(crate) mod account;
pub(crate) mod directory;
pub(crate) mod nonce;
pub(crate) mod order;

const REPLAY_NONCE_HEADER: &str = "Replay-Nonce";
const ACME_CONTENT_TYPE: &str = "application/json";

/// ServiceState is the carried state globally for the application. It contains many items the
/// handlers need to function.
#[derive(Clone)]
pub struct ServiceState {
    baseurl: url::Url,
    db: Postgres,
    c: Challenger,
    ca: CACollector,
    pnv: PostgresNonceValidator,
}

impl ServiceState {
    /// constructor for the service state
    pub fn new(
        baseurl: String,
        db: Postgres,
        c: Challenger,
        ca: CACollector,
        pnv: PostgresNonceValidator,
    ) -> Result<Self, url::ParseError> {
        Ok(Self {
            baseurl: baseurl.parse()?,
            db,
            c,
            ca,
            pnv,
        })
    }
}

/// HandlerState is the state carried between each request handler for a single request.
#[derive(Clone)]
pub struct HandlerState {
    jws: Option<crate::acme::jose::JWS>,
    nonce: Option<String>,
}

impl HandlerState {
    pub(crate) fn decorate_response(
        &self,
        url: url::Url,
        builder: Builder,
    ) -> Result<Builder, HandlerError> {
        if self.nonce.is_none() {
            return Err(ACMEValidationError::NonceNotFound.into());
        }

        Ok(builder
            .header("content-type", ACME_CONTENT_TYPE)
            .header(REPLAY_NONCE_HEADER, self.clone().nonce.unwrap())
            .header(
                "Link",
                format!(r#"<{}>;rel="index""#, url.join("./")?.to_string()),
            ))
    }
}

impl TransientState for HandlerState {
    fn initial() -> Self {
        Self {
            jws: None,
            nonce: None,
        }
    }
}

pub(crate) async fn uri_to_url(
    baseurl: url::Url,
    uri: http::Uri,
) -> Result<url::Url, url::ParseError> {
    baseurl.join(&uri.to_string())
}

async fn handle_nonce(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    _params: Params,
    app: App<ServiceState, HandlerState>,
    mut state: HandlerState,
) -> HTTPResult<HandlerState> {
    state.nonce = Some(app.state().await.unwrap().lock().await.pnv.make().await?);
    Ok((req, None, state))
}

async fn handle_jws(
    mut req: Request<Body>,
    _resp: Option<Response<Body>>,
    _params: Params,
    app: App<ServiceState, HandlerState>,
    mut state: HandlerState,
) -> HTTPResult<HandlerState> {
    let jws: Result<crate::acme::jose::JWS, _> =
        serde_json::from_slice(&hyper::body::to_bytes(req.body_mut()).await?);

    // what a mess.
    if let Ok(jws) = jws {
        let uri = req.uri().clone();
        let appstate_opt = app.state().await.clone().unwrap();
        let appstate = appstate_opt.lock().await;

        match jws.clone().protected() {
            Ok(mut protected) => {
                if let Err(e) = protected
                    .validate(
                        uri_to_url(appstate.baseurl.clone(), uri).await?,
                        appstate.pnv.clone(),
                    )
                    .await
                {
                    return Err(e.to_status());
                } else {
                    let key: Result<Option<ACMEKey>, Error> = if let Some(jwk) = protected.jwk() {
                        Ok(Some(jwk.try_into()?))
                    } else if let Some(kid) = protected.kid() {
                        let jwk =
                            crate::models::account::JWK::find_by_kid(kid, appstate.db.clone())
                                .await?;

                        let localjwk: Result<JWK, JWSError> = jwk.try_into();
                        match localjwk {
                            Ok(mut localjwk) => match (&mut localjwk).try_into() {
                                Ok(x) => Ok(Some(x)),
                                Err(e) => Err(e.into()),
                            },
                            Err(e) => Err(e.into()),
                        }
                    } else {
                        Ok(None)
                    };

                    match key {
                        Err(e) => return Err(e.to_status()),
                        Ok(Some(key)) => match jws.verify(key) {
                            Ok(result) => {
                                if result {
                                    state.jws = Some(jws);
                                    return Ok((req, None, state));
                                }

                                return Err(JWSError::ValidationFailed.to_status());
                            }
                            Err(e) => return Err(e.to_status()),
                        },
                        Ok(None) => return Err(JWSError::Missing.to_status()),
                    }
                }
            }
            Err(e) => return Err(e.to_status()),
        }
    }

    Err(ratpack::Error::StatusCode(
        StatusCode::FORBIDDEN,
        String::default(),
    ))
}

macro_rules! jws_handler {
    ($($x:path)*) => {
        compose_handler!(handle_nonce, handle_jws, $($x)*)
    };
}

/// configure_routes sets up the application's routing framework. It needs to be called before
/// serving the application over TCP.
pub fn configure_routes(app: &mut App<ServiceState, HandlerState>, rootpath: Option<&str>) {
    let rootpath = rootpath.unwrap_or("/").to_string();

    app.get(
        &(rootpath.clone()),
        compose_handler!(handle_nonce, directory),
    );

    app.head(
        &(rootpath.clone() + "nonce"),
        compose_handler!(handle_nonce, new_nonce_head),
    );
    app.get(
        &(rootpath.clone() + "nonce"),
        compose_handler!(handle_nonce, new_nonce_get),
    );

    app.post(&(rootpath.clone() + "account"), jws_handler!(new_account));
    app.post(
        &(rootpath.clone() + "account/:key_id"),
        jws_handler!(post_account),
    );

    app.post(&(rootpath.clone() + "order"), jws_handler!(new_order));
    app.post(
        &(rootpath.clone() + "order/:order_id"),
        jws_handler!(existing_order),
    );
    app.post(
        &(rootpath.clone() + "order/:order_id/finalize"),
        jws_handler!(finalize_order),
    );
    app.post(
        &(rootpath.clone() + "order/:order_id/certificate"),
        jws_handler!(get_certificate),
    );
    app.post(
        &(rootpath.clone() + "authz/:auth_id"),
        jws_handler!(post_authz),
    );
    app.post(
        &(rootpath.clone() + "chall/:challenge_id"),
        jws_handler!(post_challenge),
    );
}
