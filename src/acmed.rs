use std::{
    io::Write,
    ops::Add,
    time::{Duration, SystemTime},
};

use openssl::{
    error::ErrorStack,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509Extension, X509Name, X509Req},
};

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
    // set HOSTNAME in your environment to something your webserver or certbot can hit; otherwise
    // it will be 'localhost'. a cert will be generated with this name to serve the service with.
    // This is really important.
    let dnsname = &std::env::var("HOSTNAME").unwrap_or("localhost".to_string());

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
            c2.tick(|_c| Some(())).await;
            // NOTE this will explode violently if it unwraps to error, e.g. if the db goes down.
            c2.reconcile(pg2.clone()).await.unwrap();

            tokio::time::sleep(Duration::new(1, 0)).await;
        }
    });

    let mut ca2 = ca.clone();
    let (csr, key) = generate_csr(dnsname)?;

    let test_ca = CA::new_test_ca().unwrap();
    let cert = test_ca.generate_and_sign_cert(
        csr,
        SystemTime::now(),
        SystemTime::now().add(Duration::from_secs(365 * 24 * 60 * 60)),
    )?;

    let test_ca2 = test_ca.clone();

    tokio::spawn(async move {
        // after CA generation, write out the key and certificate
        let mut buf = std::fs::File::create("ca.key").unwrap();
        let private = test_ca
            .clone()
            .private_key()
            .private_key_to_pem_pkcs8()
            .unwrap();
        buf.write(&private).unwrap();

        let mut buf = std::fs::File::create("ca.pem").unwrap();
        let cert = test_ca.clone().certificate().to_pem().unwrap();
        buf.write(&cert).unwrap();

        ca2.spawn_collector(|| -> Result<CA, ErrorStack> { Ok(test_ca.clone()) })
            .await
    });

    let validator = PostgresNonceValidator::new(pg.clone());
    let ss = ServiceState::new(
        format!("https://{}:8000", dnsname),
        pg.clone(),
        c,
        ca,
        validator,
    )?;
    let mut app = App::with_state(ss);

    configure_routes(&mut app, None);

    let key = key.private_key_to_der()?;

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                rustls::Certificate(cert.to_der()?),
                rustls::Certificate(test_ca2.certificate().to_der()?),
            ],
            rustls::PrivateKey(key),
        )?;

    Ok(app.serve_tls("0.0.0.0:8000", config).await?)
}

fn generate_csr(dnsname: &str) -> Result<(X509Req, Rsa<Private>), ErrorStack> {
    log::info!("hostname: {}", dnsname);
    let mut namebuilder = X509Name::builder().unwrap();
    namebuilder.append_entry_by_text("CN", dnsname).unwrap();
    let mut req = X509Req::builder().unwrap();
    req.set_subject_name(&namebuilder.build()).unwrap();
    let mut extensions = openssl::stack::Stack::new()?;
    extensions.push(X509Extension::new(
        None,
        Some(&req.x509v3_context(None)),
        "subjectAltName",
        &format!("DNS:{}", dnsname),
    )?)?;
    req.add_extensions(&extensions)?;
    req.set_version(2)?;

    let key = Rsa::generate(4096).unwrap();
    // FIXME there has to be a much better way of doing this!
    let pubkey = PKey::public_key_from_pem(&key.public_key_to_pem().unwrap()).unwrap();

    req.set_pubkey(&pubkey).unwrap();
    Ok((req.build(), key))
}
