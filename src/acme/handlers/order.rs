use http::HeaderValue;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    net::IpAddr,
};
use tokio_postgres::Transaction;
use url::Url;
use x509_parser::prelude::*;

use ratpack::prelude::*;

use crate::{
    acme::{challenge::ChallengeType, ACMEIdentifier},
    errors::{db::LoadError, ACMEValidationError},
    models::{order::Challenge, Record},
};

use super::{uri_to_url, HandlerState, ServiceState, REPLAY_NONCE_HEADER};

/// RFC8555 7.1.3. Detailed read.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(skip_deserializing)]
    pub status: Option<OrderStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<chrono::DateTime<chrono::Local>>, // required for pending and valid states
    pub identifiers: Vec<crate::acme::ACMEIdentifier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<chrono::DateTime<chrono::Local>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<chrono::DateTime<chrono::Local>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<crate::errors::Error>,
    // read 7.1.3's missive on this + section 7.5
    #[serde(skip_deserializing)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorizations: Option<Vec<Url>>,
    #[serde(skip_deserializing)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalize: Option<Url>,
    #[serde(skip_deserializing)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Url>,
}

/// RFC8555 7.1.3 & 7.1.6
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

impl ToString for OrderStatus {
    fn to_string(&self) -> String {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Processing => "processing",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
        .to_string()
    }
}

impl TryFrom<String> for OrderStatus {
    type Error = crate::errors::db::LoadError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl TryFrom<&str> for OrderStatus {
    type Error = crate::errors::db::LoadError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(match s {
            "pending" => Self::Pending,
            "ready" => Self::Ready,
            "processing" => Self::Processing,
            "valid" => Self::Valid,
            "invalid" => Self::Invalid,
            _ => return Err(LoadError::InvalidEnum),
        })
    }
}

pub(crate) async fn new_order(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    _params: Params,
    app: App<ServiceState, HandlerState>,
    state: HandlerState,
) -> HTTPResult<HandlerState> {
    let appstate_opt = app.state().await.clone().unwrap();
    let appstate = appstate_opt.lock().await;

    match state.clone().jws {
        Some(jws) => {
            let order: Order = jws.payload()?;

            let mut o = crate::models::order::Order::new(
                order.not_before.map_or(None, |f| Some(f.into())),
                order.not_after.map_or(None, |f| Some(f.into())),
            );
            o.create(appstate.db.clone()).await?;

            for id in order.identifiers {
                let mut authz = crate::models::order::Authorization::default();
                authz.identifier = Some(id.clone().to_string());
                authz.order_id = o.order_id.clone();
                authz.create(appstate.db.clone()).await?;

                // for now at least, schedule one http-01 and dns-01 per name

                let ip = req.extensions().get::<IpAddr>().unwrap();
                for chall in vec![ChallengeType::DNS01, ChallengeType::HTTP01] {
                    let mut c = Challenge::new(
                        o.order_id.clone(),
                        authz.reference.clone(),
                        chall,
                        id.clone().to_string(),
                        ip.to_string(),
                        OrderStatus::Pending,
                    );

                    c.create(appstate.db.clone()).await?;
                }
            }

            let url = appstate.clone().baseurl;

            let order: Order =
                crate::models::order::Order::find(o.id()?.unwrap(), appstate.db.clone())
                    .await?
                    .into_handler_order(url.clone())?;

            return Ok((
                req,
                Some(
                    state
                        .decorate_response(url.clone(), Response::builder())?
                        .status(StatusCode::CREATED)
                        .header(
                            "Location",
                            url.join(&format!("./order/{}", o.order_id))?.to_string(),
                        )
                        .body(Body::from(serde_json::to_string(&order)?))
                        .unwrap(),
                ),
                state,
            ));
        }
        None => {}
    }

    return Err(ACMEValidationError::InvalidRequest.into());
}

pub(crate) async fn existing_order(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    params: Params,
    app: App<ServiceState, HandlerState>,
    state: HandlerState,
) -> HTTPResult<HandlerState> {
    let appstate_opt = app.state().await.clone().unwrap();
    let appstate = appstate_opt.lock().await;

    match state.clone().jws {
        Some(_jws) => {
            let order_id = params.get("order_id").unwrap();

            let o = crate::models::order::Order::find_by_reference(
                order_id.to_string(),
                appstate.db.clone(),
            )
            .await?;

            let url = appstate.clone().baseurl;
            let h_order = serde_json::to_string(&o.clone().into_handler_order(url.clone())?)?;

            return Ok((
                req,
                Some(
                    state
                        .decorate_response(url.clone(), Response::builder())?
                        .status(StatusCode::OK)
                        .header(
                            "Location",
                            url.join(&format!("./order/{}", o.order_id))?.to_string(),
                        )
                        .body(Body::from(h_order))
                        .unwrap(),
                ),
                state,
            ));
        }
        None => {}
    }

    return Err(ACMEValidationError::InvalidRequest.into());
}

/// RFC8555 7.4.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizeOrderRequest {
    csr: String,
}

pub(crate) async fn finalize_order(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    params: Params,
    app: App<ServiceState, HandlerState>,
    state: HandlerState,
) -> HTTPResult<HandlerState> {
    let appstate_opt = app.state().await.clone().unwrap();
    let appstate = appstate_opt.lock().await;

    match state.clone().jws {
        Some(jws) => {
            let finalize_order: FinalizeOrderRequest = jws.payload()?;

            let order_id = params.get("order_id").unwrap();

            let order = crate::models::order::Order::find_by_reference(
                order_id.to_string(),
                appstate.db.clone(),
            )
            .await?;

            if order.authorizations.is_none() {
                return Err(ACMEValidationError::InvalidRequest.into());
            }

            // this code yields to the x509-parser crate to reap and check the subjectAltName
            // extensions. This is necessary because rust-openssl does not support this
            // functionality.
            //
            // relevant topic on github:
            // https://github.com/sfackler/rust-openssl/pull/1095#issuecomment-636279332
            //
            // commonName is not checked as it should not be validated in a typical situation
            // involving TLS and subjectAltName components, but this may be something to revisit
            // later.
            //
            // Later, the csr is handed back to rust-openssl to complete the CA signing process.

            let decoded =
                &base64::decode_config(finalize_order.csr.clone(), base64::URL_SAFE_NO_PAD)?;

            let (_, csr) = X509CertificationRequest::from_der(decoded)?;
            csr.verify_signature()?;

            let mut mapping = HashSet::new();

            for id in order.authorizations.clone().unwrap() {
                for id in id.identifier {
                    mapping.insert(id);
                }
            }

            if let Some(extensions) = csr.requested_extensions() {
                for extension in extensions {
                    match extension {
                        ParsedExtension::SubjectAlternativeName(name) => {
                            for val in name.general_names.iter() {
                                match val {
                                    GeneralName::DNSName(val) => {
                                        if mapping.contains(&val.to_string()) {
                                            mapping.remove(&val.to_string());
                                        } else {
                                            return Err(ACMEValidationError::Other(
                                                "CSR contains invalid names".to_string(),
                                            )
                                            .into());
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            if !mapping.is_empty() {
                return Err(
                    ACMEValidationError::Other("CSR contains invalid names".to_string()).into(),
                );
            }

            if order.not_before.is_none() {
                return Err(ACMEValidationError::Other(
                    "not_before missing in order cadence".to_string(),
                )
                .into());
            }

            if order.not_after.is_none() {
                return Err(ACMEValidationError::Other(
                    "not_after missing in order cadence".to_string(),
                )
                .into());
            }

            let csr = openssl::x509::X509Req::from_der(decoded)?;

            let res = appstate
                .ca
                .clone()
                .sign(
                    csr,
                    order.clone().not_before.unwrap().into(),
                    order.clone().not_after.unwrap().into(),
                )
                .await;

            match res {
                Ok(cert) => order.record_certificate(cert, appstate.db.clone()).await?,
                Err(e) => return Err(ACMEValidationError::Other(e.to_string()).into()),
            };

            let url = appstate.clone().baseurl;
            let h_order = serde_json::to_string(&order.clone().into_handler_order(url.clone())?)?;

            return Ok((
                req,
                Some(
                    state
                        .decorate_response(url.clone(), Response::builder())?
                        .status(StatusCode::OK)
                        .header(
                            "Location",
                            url.join(&format!("./order/{}", order.order_id))?
                                .to_string(),
                        )
                        .body(Body::from(h_order))
                        .unwrap(),
                ),
                state,
            ));
        }
        None => {}
    }

    return Err(ACMEValidationError::InvalidRequest.into());
}

pub(crate) async fn get_certificate(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    params: Params,
    app: App<ServiceState, HandlerState>,
    state: HandlerState,
) -> HTTPResult<HandlerState> {
    let appstate_opt = app.state().await.clone().unwrap();
    let appstate = appstate_opt.lock().await;

    match state.clone().jws {
        Some(_jws) => {
            let order_id = params.get("order_id").unwrap();

            let order = crate::models::order::Order::find_by_reference(
                order_id.to_string(),
                appstate.db.clone(),
            )
            .await?;

            let cert = order.certificate(appstate.db.clone()).await?;
            let mut cacert = appstate
                .ca
                .clone()
                .ca()
                .read()
                .await
                .clone()
                .unwrap()
                .certificate()
                .to_pem()?;

            let mut chain = cert.certificate;
            chain.append(&mut cacert);

            return Ok((
                req,
                Some(
                    Response::builder()
                        .header("content-type", "application/pem-certificate-chain")
                        .header(REPLAY_NONCE_HEADER, state.nonce.clone().unwrap())
                        .status(StatusCode::OK)
                        .body(Body::from(chain))
                        .unwrap(),
                ),
                state,
            ));
        }
        None => {}
    }

    return Err(ACMEValidationError::InvalidRequest.into());
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    identifier: ACMEIdentifier,
    status: AuthStatus,
    expires: chrono::DateTime<chrono::Local>,
    challenges: Vec<ChallengeAuthorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wildcard: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthStatus {
    Pending,
    Valid,
    Deactivated,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeAuthorization {
    #[serde(rename = "type")]
    typ: ChallengeType,
    url: Url,
    token: String,
    status: OrderStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    validated: Option<chrono::DateTime<chrono::Local>>,
}

impl ChallengeAuthorization {
    fn from_challenge(c: &Challenge, url: Url) -> Result<Self, LoadError> {
        Ok(Self {
            typ: c.challenge_type.clone(),
            url,
            token: c.token.clone(),
            status: c.status.clone(),
            validated: c.validated.map(|t| t.into()),
        })
    }
}

impl Authorization {
    async fn from_authorization_id(
        auth_id: &str,
        url: Url,
        tx: &Transaction<'_>,
    ) -> Result<Self, LoadError> {
        let auth = crate::models::order::Authorization::find_by_reference(auth_id, &tx).await?;
        let challenges = auth.challenges(&tx).await?;

        let chs = challenges
            .iter()
            .map(|c| ChallengeAuthorization::from_challenge(c, c.into_url(url.clone())))
            .collect::<Vec<Result<ChallengeAuthorization, LoadError>>>();

        if let Some(Err(error)) = chs.iter().find(|p| p.is_err()) {
            return Err(LoadError::Generic(error.to_string()));
        }

        let chs = chs
            .iter()
            .map(|c| c.as_ref().unwrap().clone())
            .collect::<Vec<ChallengeAuthorization>>();

        Ok(Self {
            expires: auth.expires.into(),
            status: if auth.deleted_at.is_some() {
                AuthStatus::Deactivated
            } else {
                if chs.iter().any(|ca| ca.status == OrderStatus::Valid) {
                    AuthStatus::Valid
                } else if chs
                    .iter()
                    .all(|ca| ca.status != OrderStatus::Valid && ca.status != OrderStatus::Invalid)
                {
                    AuthStatus::Pending
                } else {
                    AuthStatus::Revoked
                }
            },
            identifier: auth.identifier.unwrap().try_into()?,
            challenges: chs,
            wildcard: None, // FIXME wtf? re-check spec
        })
    }
}

pub(crate) async fn post_authz(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    params: Params,
    app: App<ServiceState, HandlerState>,
    state: HandlerState,
) -> HTTPResult<HandlerState> {
    let appstate_opt = app.state().await.clone().unwrap();
    let appstate = appstate_opt.lock().await;

    match state.clone().jws {
        Some(_jws) => {
            let auth_id = params.get("auth_id").unwrap();

            let db = appstate.db.clone();
            let mut lockeddb = db.client().await?;
            let tx = lockeddb.transaction().await?;

            let mut statuscode = StatusCode::CREATED;

            let authz =
                Authorization::from_authorization_id(auth_id, appstate.clone().baseurl, &tx)
                    .await?;
            for chall in authz.clone().challenges {
                if chall.status == OrderStatus::Valid {
                    statuscode = StatusCode::OK;
                    break;
                }
            }

            let url = uri_to_url(appstate.clone().baseurl, req.uri().clone()).await?;
            let builder = state
                .decorate_response(url.clone(), Response::builder())?
                .header(
                    "Link",
                    HeaderValue::from_str(&format!(r#"<{}>;rel="up""#, url.clone()))?,
                );

            let out = serde_json::to_string(&authz)?;
            return Ok((
                req,
                Some(builder.status(statuscode).body(Body::from(out)).unwrap()),
                state,
            ));
        }
        None => {}
    }

    return Err(ACMEValidationError::InvalidRequest.into());
}

pub(crate) async fn post_challenge(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    params: Params,
    app: App<ServiceState, HandlerState>,
    state: HandlerState,
) -> HTTPResult<HandlerState> {
    let appstate_opt = app.state().await.clone().unwrap();
    let appstate = appstate_opt.lock().await;

    match state.clone().jws {
        Some(_jws) => {
            let challenge_id = params.get("challenge_id").unwrap();

            let db = appstate.db.clone();
            let mut lockeddb = db.client().await?;
            let tx = lockeddb.transaction().await?;

            let mut ch = Challenge::find_by_reference(challenge_id.to_string(), &tx).await?;
            if ch.status == OrderStatus::Pending {
                ch.status = OrderStatus::Processing;
                ch.persist_status(&tx).await?;
                appstate.c.schedule(ch.clone()).await;
            }

            let authz = ch.authorization(&tx).await?;
            tx.commit().await?;

            let url = uri_to_url(appstate.clone().baseurl, req.uri().clone()).await?;

            // FIXME 7.5.1 indicates a Retry-After header can be sent to feed the client hints on how
            // often to retry here... we can use the polling value fed to the challenger for this
            // value.
            let builder = state
                .decorate_response(url.clone(), Response::builder())?
                .status(StatusCode::OK)
                .header(
                    "Link",
                    HeaderValue::from_str(&format!(
                        r#"<{}>;rel="up""#,
                        authz.into_url(url.clone())
                    ))?,
                );

            return Ok((
                req,
                Some(
                    builder
                        .body(Body::from(serde_json::to_string(
                            &ChallengeAuthorization::from_challenge(
                                &ch,
                                ch.into_url(appstate.clone().baseurl),
                            )?,
                        )?))
                        .unwrap(),
                ),
                state,
            ));
        }
        None => {}
    }

    return Err(ACMEValidationError::InvalidRequest.into());
}

mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn test_order_flow_single_domain() {
        use crate::test::TestService;
        use spectral::prelude::*;
        use std::sync::Arc;
        use tempfile::TempDir;

        let srv = TestService::new("test_order_flow_single_domain").await;

        let dir = Arc::new(TempDir::new().unwrap());

        for _ in 0..10 {
            let res = srv.clone().certbot(
                Some(dir.clone()),
                format!("certonly --http-01-port {} --standalone -d 'foo.com' -m 'erik@hollensbe.org' --agree-tos", 
                    rand::random::<u16>() % 10000 + 1024)
                    .to_string(),
            )
            .await;

            assert_that!(res).is_ok();

            let res = srv
                .clone()
                .certbot(Some(dir.clone()), "update_symlinks".to_string())
                .await;

            assert_that!(res).is_ok();

            let mut root = dir.path().to_path_buf();
            root.push("live/foo.com");

            for filename in vec!["fullchain", "cert", "chain", "privkey"] {
                let mut path = root.clone();
                path.push(filename.to_string() + ".pem");
                let res = path.metadata();
                assert_that!(res).is_ok();
            }

            assert_that!(srv.zlint("foo.com", dir.clone()).await).is_ok();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_order_flow_multi_domain() {
        use crate::test::TestService;
        use spectral::prelude::*;
        use std::sync::Arc;
        use tempfile::TempDir;

        let srv = TestService::new("test_order_flow_multi_domain").await;

        let dir = Arc::new(TempDir::new().unwrap());

        for domain in vec!["foo.com", "bar.com", "example.org", "example.com"] {
            let res = srv.clone().certbot(
                Some(dir.clone()),
                format!(
                    "certonly --http-01-port {} --standalone -d '{}' -m 'erik@hollensbe.org' --agree-tos",
                    rand::random::<u16>() % 10000 + 1024,
                    domain
                ),
            )
            .await;

            assert_that!(res).is_ok();

            let res = srv
                .clone()
                .certbot(Some(dir.clone()), "update_symlinks".to_string())
                .await;

            assert_that!(res).is_ok();

            let mut root = dir.path().to_path_buf();
            root.push(format!("live/{}", domain));

            for filename in vec!["fullchain", "cert", "chain", "privkey"] {
                let mut path = root.clone();
                path.push(filename.to_string() + ".pem");
                let res = path.metadata();
                assert_that!(res).is_ok();
            }

            assert_that!(srv.zlint(domain, dir.clone()).await).is_ok();
        }
    }
}
