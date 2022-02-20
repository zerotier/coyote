use super::{uri_to_url, HandlerState, ServiceState, REPLAY_NONCE_HEADER};
use ratpack::prelude::*;
use serde::{Deserialize, Serialize};

/// See 7.1.1 of RFC8555
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    terms_of_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    caa_identities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_account_required: Option<bool>,
}

impl Default for DirectoryMeta {
    fn default() -> Self {
        Self {
            terms_of_service: None,
            website: None,
            caa_identities: None,
            external_account_required: None,
        }
    }
}

/// See 7.1.1 of RFC8555
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    new_nonce: url::Url,
    new_account: url::Url,
    new_order: url::Url,
    new_authz: url::Url,
    revoke_cert: url::Url,
    key_change: url::Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<DirectoryMeta>,
}

pub(crate) async fn directory(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    _params: Params,
    app: App<ServiceState, HandlerState>,
    state: HandlerState,
) -> HTTPResult<HandlerState> {
    let uri = req.uri().clone();
    let url = uri_to_url(app.state().await.unwrap().lock().await.baseurl.clone(), uri).await?;

    let dir = Directory {
        new_nonce: url.join("./nonce")?,
        new_account: url.join("./account")?,
        new_order: url.join("./order")?,
        new_authz: url.join("./authz")?,
        revoke_cert: url.join("./revoke")?,
        key_change: url.join("./key")?,
        meta: None,
    };

    Ok((
        req,
        Some(
            Response::builder()
                .header("content-type", "application/json")
                .header(REPLAY_NONCE_HEADER, state.nonce.clone().unwrap())
                .status(StatusCode::OK)
                .body(Body::from(serde_json::to_string(&dir)?))
                .unwrap(),
        ),
        state,
    ))
}

mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn test_basic_directory() {
        use super::{super::*, Directory};
        use crate::test::PGTest;
        use ratpack::app::TestApp;
        use spectral::prelude::*;
        use std::time::Duration;

        let pg = PGTest::new("test_basic_directory").await.unwrap();
        let c = Challenger::new(Some(chrono::Duration::seconds(1)));
        let mut app = App::with_state(
            ServiceState::new(
                "http://example.com".to_string(),
                pg.db(),
                c.clone(),
                CACollector::new(Duration::MAX),
                PostgresNonceValidator::new(pg.db()),
            )
            .unwrap(),
        );
        configure_routes(&mut app, None);

        let app = TestApp::new(app);

        let mut res = app.get("/").await;

        let res = hyper::body::to_bytes(res.body_mut()).await.unwrap();
        let res = serde_json::from_slice::<Directory>(&res).unwrap();

        assert_that!(res).is_equal_to(Directory {
            new_nonce: "http://example.com/nonce".parse().unwrap(),
            new_account: "http://example.com/account".parse().unwrap(),
            new_order: "http://example.com/order".parse().unwrap(),
            new_authz: "http://example.com/authz".parse().unwrap(),
            revoke_cert: "http://example.com/revoke".parse().unwrap(),
            key_change: "http://example.com/key".parse().unwrap(),
            meta: None,
        });

        let mut app = App::with_state(
            ServiceState::new(
                "http://example.com/acme".to_string(),
                pg.db(),
                c,
                CACollector::new(Duration::MAX),
                PostgresNonceValidator::new(pg.db()),
            )
            .unwrap(),
        );

        configure_routes(&mut app, Some("/acme"));

        let app = TestApp::new(app);
        let mut res = app.get("/acme/").await;

        let res = hyper::body::to_bytes(res.body_mut()).await.unwrap();
        let res = serde_json::from_slice::<Directory>(&res).unwrap();

        assert_that!(res).is_equal_to(Directory {
            new_nonce: "http://example.com/acme/nonce".parse().unwrap(),
            new_account: "http://example.com/acme/account".parse().unwrap(),
            new_order: "http://example.com/acme/order".parse().unwrap(),
            new_authz: "http://example.com/acme/authz".parse().unwrap(),
            revoke_cert: "http://example.com/acme/revoke".parse().unwrap(),
            key_change: "http://example.com/acme/key".parse().unwrap(),
            meta: None,
        });
    }
}
