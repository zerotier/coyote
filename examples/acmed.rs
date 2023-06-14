use std::time::Duration;

use openssl::error::ErrorStack;

use coyote::{
    acme::{
        ca::{CACollector, CA},
        challenge::Challenger,
        handlers::{configure_routes, ServiceState},
        PostgresNonceValidator,
    },
    models::Postgres,
};

use ratpack::prelude::*;

const CHALLENGE_EXPIRATION: i64 = 600;

#[tokio::main]
async fn main() -> Result<(), ServerError> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    //
    // to start a database to work with me:
    //
    // make postgres
    //
    let pg = Postgres::new("host=localhost dbname=coyote user=postgres", 10)
        .await
        .unwrap();
    pg.migrate().await.unwrap();

    let c = Challenger::new(Some(chrono::Duration::seconds(CHALLENGE_EXPIRATION)));
    let ca = CACollector::new(Duration::MAX);

    let pg2 = pg.clone();
    let c2 = c.clone();

    // FIXME probably need something magical with signals here to manage shutdown that I don't want to think about yet
    tokio::spawn(async move {
        loop {
            // FIXME whitelist all challenge requests. This is not how ACME is supposed to work. You have to write this.
            c2.tick(|_c| async { Some(()) }).await;
            // NOTE this will explode violently if it unwraps to error, e.g. if the db goes down.
            c2.reconcile(pg2.clone()).await.unwrap();

            tokio::time::sleep(Duration::new(1, 0)).await;
        }
    });

    let mut ca2 = ca.clone();
    let test_ca = CA::new_test_ca().unwrap();

    tokio::spawn(async move {
        ca2.spawn_collector(|| -> Result<CA, ErrorStack> { Ok(test_ca.clone()) })
            .await
    });

    let validator = PostgresNonceValidator::new(pg.clone());
    let ss = ServiceState::new(
        "http://127.0.0.1:8000".to_string(),
        pg.clone(),
        c,
        ca,
        validator,
    )?;
    let mut app = App::with_state(ss);

    configure_routes(&mut app, None);

    Ok(app.serve("127.0.0.1:8000").await?)
}
