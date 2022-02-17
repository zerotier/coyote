// nonces are covered in RFC8555 section 7.2 mostly. They're also a critical part of the JOSE usage
// in this library.

use super::{uri_to_url, HandlerState, ServiceState};
use ratpack::prelude::*;

pub(crate) async fn new_nonce_head(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    _params: Params,
    app: App<ServiceState, HandlerState>,
    state: HandlerState,
) -> HTTPResult<HandlerState> {
    let uri = req.uri().clone();

    Ok((
        req,
        Some(
            state
                .decorate_response(
                    uri_to_url(app.state().await.unwrap().lock().await.baseurl.clone(), uri)
                        .await?,
                    Response::builder(),
                )?
                .status(StatusCode::OK)
                .header("Cache-Control", "no-store") // last para of 7.2
                .body(Body::default())
                .unwrap(),
        ),
        state,
    ))
}

pub(crate) async fn new_nonce_get(
    req: Request<Body>,
    _resp: Option<Response<Body>>,
    _params: Params,
    app: App<ServiceState, HandlerState>,
    state: HandlerState,
) -> HTTPResult<HandlerState> {
    let uri = req.uri().clone();

    Ok((
        req,
        Some(
            state
                .decorate_response(
                    uri_to_url(app.state().await.unwrap().lock().await.baseurl.clone(), uri)
                        .await?,
                    Response::builder(),
                )?
                .status(StatusCode::CREATED)
                .header("Cache-Control", "no-store") // last para of 7.2
                .body(Body::default())
                .unwrap(),
        ),
        state,
    ))
}

mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn test_basic_head() {
        use super::super::*;
        use crate::test::PGTest;
        use ratpack::app::TestApp;
        use spectral::prelude::*;
        use std::time::Duration;

        let pg = PGTest::new("test_basic_head").await.unwrap();
        let c = Challenger::new(Some(chrono::Duration::seconds(1)));
        let mut app = App::with_state(
            ServiceState::new(
                "http://127.0.0.1:8000".to_string(),
                pg.db(),
                c,
                CACollector::new(Duration::MAX),
                PostgresNonceValidator::new(pg.db()),
            )
            .unwrap(),
        );

        configure_routes(&mut app, None);

        let app: TestApp<ServiceState, HandlerState> = TestApp::new(app);

        let res = app.head("/nonce").await;
        let headers = res.headers();
        let nonce = headers.get(REPLAY_NONCE_HEADER).unwrap().clone();
        assert_that!(nonce.is_empty()).is_false();
        drop(headers);

        let mut handles = Vec::new();
        for _ in 0..10000 {
            let nonce = nonce.clone();
            let app = app.clone();
            let handle = tokio::spawn(async move {
                let res = app.head("/nonce").await;
                assert_that!(res.status()).is_equal_to(StatusCode::OK);

                let nonce2 = res
                    .headers()
                    .get(REPLAY_NONCE_HEADER)
                    .unwrap()
                    .to_str()
                    .unwrap();

                assert!(!nonce2.is_empty());

                assert_ne!(nonce, nonce2);
            });

            handles.push(handle);
        }
        for handle in handles {
            handle.await.unwrap()
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_basic_get() {
        use super::super::*;
        use crate::test::PGTest;
        use ratpack::app::TestApp;
        use spectral::prelude::*;
        use std::time::Duration;

        let pg = PGTest::new("test_basic_get").await.unwrap();
        let c = Challenger::new(Some(chrono::Duration::seconds(1)));
        let mut app = App::with_state(
            ServiceState::new(
                "http://127.0.0.1:8000".to_string(),
                pg.db(),
                c,
                CACollector::new(Duration::MAX),
                PostgresNonceValidator::new(pg.db()),
            )
            .unwrap(),
        );

        configure_routes(&mut app, None);

        let app: TestApp<ServiceState, HandlerState> = TestApp::new(app);

        let res = app.get("/nonce").await;
        let headers = res.headers();
        let nonce = headers.get(REPLAY_NONCE_HEADER).unwrap().clone();
        assert_that!(nonce.is_empty()).is_false();
        drop(headers);

        let mut handles = Vec::new();
        for _ in 0..10000 {
            let nonce = nonce.clone();
            let app = app.clone();
            let handle = tokio::spawn(async move {
                let res = app.get("/nonce").await;
                let headers = res.headers();
                let nonce2 = headers.get(REPLAY_NONCE_HEADER).unwrap().clone();
                assert_that!(nonce.is_empty()).is_false();
                drop(headers);

                assert!(!nonce2.is_empty());

                assert_ne!(nonce, nonce2);
            });

            handles.push(handle);
        }
        for handle in handles {
            handle.await.unwrap()
        }
    }
}
