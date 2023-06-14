#![cfg(test)]

use std::collections::{HashMap, HashSet};
use std::process::Stdio;
use std::sync::Once;
use std::{sync::Arc, time::Duration};

use crate::acme::ca::{CACollector, CA};
use crate::acme::challenge::Challenger;
use crate::acme::handlers::{configure_routes, HandlerState, ServiceState};
use crate::acme::PostgresNonceValidator;
use crate::errors::db::MigrationError;
use crate::models::Postgres;
use crate::util::make_nonce;

use bollard::container::{LogsOptions, StartContainerOptions};
use openssl::error::ErrorStack;
use ratpack::app::TestApp;
use ratpack::prelude::*;

use bollard::{
    container::{Config, WaitContainerOptions},
    models::HostConfig,
    Docker,
};
use eggshell::EggShell;
use futures::TryStreamExt;
use lazy_static::lazy_static;
use openssl::sha::sha256;
use tempfile::{tempdir, TempDir};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use url::Url;

const DEBUG_VAR: &str = "DEBUG";
const ZLINT_WARN_VAR: &str = "ZLINT_WARN";

const HBA_CONFIG_PATH: &str = "hack/pg_hba.conf";

static INIT: Once = Once::new();

lazy_static! {
    static ref ZLINT_WARN: bool = !std::env::var(ZLINT_WARN_VAR).unwrap_or_default().is_empty();
    static ref DEBUG: bool = !std::env::var(DEBUG_VAR).unwrap_or_default().is_empty();
    static ref IMAGES: Vec<&'static str> = vec![
        "certbot/certbot:latest",
        "postgres:latest",
        "zerotier/zlint:latest",
    ];
}

impl From<MigrationError> for eggshell::Error {
    fn from(me: MigrationError) -> Self {
        Self::Generic(me.to_string())
    }
}

#[derive(Clone)]
pub struct PGTest {
    gs: Arc<Mutex<EggShell>>,
    postgres: Postgres,
    docker: Arc<Mutex<Docker>>,
    // NOTE: the only reason we keep this is to ensure it lives the same lifetime as the PGTest
    // struct; otherwise the temporary directory is removed prematurely.
    _temp: Arc<Mutex<TempDir>>,
}

fn pull_images(images: Vec<&str>) -> () {
    // bollard doesn't let you pull images. sadly, this is what I came up with until I can patch
    // it.

    for image in images {
        let mut cmd = &mut std::process::Command::new("docker");
        if !*DEBUG {
            cmd = cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }

        let stat = cmd.args(vec!["pull", image]).status().unwrap();
        if !stat.success() {
            panic!("could not pull images");
        }
    }
}

async fn wait_for_images(images: Vec<&str>) -> () {
    let docker = Docker::connect_with_local_defaults().unwrap();

    for image in images {
        loop {
            match docker.inspect_image(image).await {
                Ok(_) => break,
                Err(_) => {
                    tokio::time::sleep(Duration::new(0, 200)).await;
                }
            }
        }
    }
}

impl PGTest {
    pub async fn new(name: &str) -> Result<Self, eggshell::Error> {
        INIT.call_once(|| {
            let mut builder = &mut env_logger::builder();
            if *DEBUG {
                builder = builder.filter_level(log::LevelFilter::Info)
            }
            builder.init();
            pull_images(IMAGES.to_vec());
        });

        wait_for_images(IMAGES.to_vec()).await;

        let pwd = std::env::current_dir().unwrap();
        let hbapath = pwd.join(HBA_CONFIG_PATH);

        let temp = tempdir().unwrap();

        let docker = Arc::new(Mutex::new(Docker::connect_with_local_defaults().unwrap()));
        let mut gs = EggShell::new(docker.clone()).await?;

        if *DEBUG {
            gs.set_debug(true)
        }

        log::info!("launching postgres instance: {}", name);

        gs.launch(
            name,
            bollard::container::Config {
                image: Some("postgres:latest".to_string()),
                env: Some(
                    vec!["POSTGRES_PASSWORD=dummy", "POSTGRES_DB=coyote"]
                        .iter()
                        .map(|x| x.to_string())
                        .collect(),
                ),
                host_config: Some(HostConfig {
                    binds: Some(vec![
                        format!(
                            "{}:{}",
                            hbapath.to_string_lossy().to_string(),
                            "/etc/postgresql/pg_hba.conf"
                        ),
                        format!("{}:{}", temp.path().display(), "/var/run/postgresql"),
                    ]),
                    ..Default::default()
                }),
                cmd: Some(
                    vec![
                        "-c",
                        "shared_buffers=512MB",
                        "-c",
                        "max_connections=200",
                        "-c",
                        "unix_socket_permissions=0777",
                    ]
                    .iter()
                    .map(|x| x.to_string())
                    .collect(),
                ),
                ..Default::default()
            },
            None,
        )
        .await?;

        log::info!("waiting for postgres instance: {}", name);

        let mut postgres: Option<Postgres> = None;
        let config = format!("host={} dbname=coyote user=postgres", temp.path().display());

        while postgres.is_none() {
            let pg = Postgres::connect_one(&config).await;

            match pg {
                Ok(_) => postgres = Some(Postgres::new(&config, 200).await.unwrap()),
                Err(_) => tokio::time::sleep(Duration::new(1, 0)).await,
            }
        }

        log::info!("connected to postgres instance: {}", name);

        let postgres = postgres.unwrap();
        postgres.migrate().await?;

        Ok(Self {
            docker,
            gs: Arc::new(Mutex::new(gs)),
            postgres,
            _temp: Arc::new(Mutex::new(temp)),
        })
    }

    pub fn db(&self) -> Postgres {
        self.postgres.clone()
    }

    pub fn eggshell(self) -> Arc<Mutex<EggShell>> {
        self.gs
    }
}

#[derive(Debug, Clone, Error)]
pub(crate) enum ContainerError {
    #[error("Unknown error encountered: {0}")]
    Generic(String),

    #[error("container failed with exit status: {0}: {1}")]
    Failed(i64, String),

    #[error("zlint failures follow: {0:?}")]
    ZLint(HashSet<String>),
}

fn short_hash(s: String) -> String {
    String::from(
        &sha256(s.as_bytes())
            .iter()
            .map(|c| format!("{:x}", c))
            .take(10)
            .collect::<Vec<String>>()
            .join("")[0..10],
    )
}

#[derive(Clone)]
pub(crate) struct TestService {
    pub pg: Box<PGTest>,
    pub app: ratpack::app::TestApp<ServiceState, HandlerState>,
    pub url: String,
}

impl TestService {
    pub(crate) async fn new(name: &str) -> Self {
        let pg = PGTest::new(name).await.unwrap();
        let c = Challenger::new(Some(chrono::Duration::seconds(60)));
        let validator = PostgresNonceValidator::new(pg.db().clone());

        let c2 = c.clone();
        let pg2 = pg.db().clone();

        tokio::spawn(async move {
            loop {
                c2.tick(|_c| async { Some(()) }).await;
                c2.reconcile(pg2.clone()).await.unwrap();

                tokio::time::sleep(Duration::new(0, 250)).await;
            }
        });

        let ca = CACollector::new(Duration::new(0, 250));
        let mut ca2 = ca.clone();

        tokio::spawn(async move {
            let ca = CA::new_test_ca().unwrap();
            ca2.spawn_collector(|| -> Result<CA, ErrorStack> { Ok(ca.clone()) })
                .await
        });

        let lis = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = lis.local_addr().unwrap();
        let url = format!("http://{}", addr);
        drop(lis);

        let mut app = App::with_state(
            ServiceState::new(url.clone(), pg.db(), c, ca, validator.clone()).unwrap(),
        );

        configure_routes(&mut app, None);

        let a = app.clone();

        tokio::spawn(async move {
            a.serve(&addr.clone().to_string()).await.unwrap();
        });

        Self {
            pg: Box::new(pg),
            app: TestApp::new(app),
            url,
        }
    }

    pub(crate) async fn zlint(
        &self,
        domain: &str,
        certs: Arc<TempDir>,
    ) -> Result<(), ContainerError> {
        log::info!("letsencrypt dir: {}", certs.path().display());
        let name = &format!("zlint-{}", short_hash(make_nonce(None)));

        let res = self
            .launch(
                name,
                Config {
                    attach_stdout: Some(true),
                    attach_stderr: Some(*DEBUG),
                    image: Some("zerotier/zlint:latest".to_string()),
                    entrypoint: Some(
                        vec!["/bin/sh", "-c"]
                            .iter()
                            .map(|c| c.to_string())
                            .collect::<Vec<String>>(),
                    ),
                    cmd: Some(vec![format!(
                        "zlint /etc/letsencrypt/live/{}/fullchain.pem",
                        domain
                    )]),
                    host_config: Some(HostConfig {
                        binds: Some(vec![format!(
                            "{}:{}",
                            certs.path().to_string_lossy(),
                            "/etc/letsencrypt"
                        )]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                None,
            )
            .await;

        if let Err(e) = res {
            return Err(ContainerError::Generic(e.to_string()));
        }

        let res = self.wait(name, true).await?;
        let m: HashMap<String, HashMap<String, String>> =
            serde_json::from_str(&res.unwrap()).unwrap();

        let mut s = HashSet::new();

        for (key, result) in m {
            for (_, result) in result {
                match result.as_str() {
                    "fail" => {
                        let key = key.clone();
                        s.insert(key);
                    }
                    "warn" => {
                        if *ZLINT_WARN {
                            let key = key.clone();
                            s.insert(key);
                        }
                    }
                    _ => {}
                };
            }
        }

        if !s.is_empty() {
            return Err(ContainerError::ZLint(s));
        }

        return Ok(());
    }

    pub(crate) async fn certbot(
        &self,
        certs: Option<Arc<TempDir>>,
        command: String,
    ) -> Result<Arc<TempDir>, ContainerError> {
        let server_url = Url::parse(&self.url).unwrap();
        let server_url_hash = short_hash(server_url.to_string());
        let certs: Arc<tempfile::TempDir> = match certs {
            Some(certs) => certs,
            None => Arc::new(tempdir().unwrap()),
        };

        log::info!("letsencrypt dir: {}", certs.path().display());

        let name = &format!(
            "certbot-{}-{}",
            server_url_hash,
            short_hash(make_nonce(None))
        );

        let res = self
            .launch(
                name,
                Config {
                    image: Some("certbot/certbot:latest".to_string()),
                    entrypoint: Some(
                        vec!["/bin/sh", "-c"]
                            .iter()
                            .map(|c| c.to_string())
                            .collect::<Vec<String>>(),
                    ),
                    cmd: Some(vec![format!(
                    // this 755 set is a hack around containers running as root and the
                    // test launching them running as a user.
                    "certbot --non-interactive --logs-dir '/etc/letsencrypt/logs' --server '{}' {} && chmod -R 755 /etc/letsencrypt",
                    server_url, command
                )]),
                    host_config: Some(HostConfig {
                        network_mode: Some("host".to_string()),
                        binds: Some(vec![format!(
                            "{}:{}",
                            certs.path().to_string_lossy(),
                            "/etc/letsencrypt"
                        )]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                None,
            )
            .await;

        if let Err(e) = res {
            return Err(ContainerError::Generic(e.to_string()));
        }

        self.wait(name, false).await?;
        return Ok(certs);
    }

    async fn launch(
        &self,
        name: &str,
        config: Config<String>,
        start_opts: Option<StartContainerOptions<String>>,
    ) -> Result<(), eggshell::Error> {
        self.pg.clone().eggshell().lock().await.set_debug(*DEBUG);

        self.pg
            .clone()
            .eggshell()
            .lock()
            .await
            .launch(name, config, start_opts)
            .await
    }

    async fn wait(&self, name: &str, pass_stdout: bool) -> Result<Option<String>, ContainerError> {
        loop {
            tokio::time::sleep(Duration::new(1, 0)).await;

            let locked = self.pg.docker.lock().await;
            let waitres = locked
                .wait_container::<String>(
                    name,
                    Some(WaitContainerOptions {
                        condition: "not-running".to_string(),
                    }),
                )
                .try_next()
                .await;

            if let Ok(Some(res)) = waitres {
                if res.status_code != 0 || res.error.is_some() {
                    let mut error = res.error.unwrap_or_default().message;

                    let logs = locked
                        .logs::<String>(
                            name,
                            Some(LogsOptions::<String> {
                                stderr: *DEBUG,
                                stdout: *DEBUG,
                                ..Default::default()
                            }),
                        )
                        .try_next()
                        .await;
                    if let Ok(Some(logs)) = logs {
                        error = Some(format!("{}", logs));
                        let logs = logs.into_bytes();
                        if logs.len() > 50 && *DEBUG {
                            std::fs::write("error.log", logs).unwrap();
                            error = Some("error too long: error written to error.log".to_string())
                        }
                    }

                    return Err(ContainerError::Failed(
                        res.status_code,
                        error.unwrap_or_default(),
                    ));
                } else if pass_stdout {
                    let logs = locked
                        .logs::<String>(
                            name,
                            Some(LogsOptions::<String> {
                                stdout: true,
                                ..Default::default()
                            }),
                        )
                        .try_next()
                        .await;

                    if let Ok(Some(logs)) = logs {
                        return Ok(Some(logs.to_string()));
                    } else {
                        return Err(ContainerError::Generic("no logs returned".to_string()));
                    }
                } else {
                    return Ok(None);
                }
            }
        }
    }
}

mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn pgtest_basic() {
        use super::PGTest;
        use spectral::prelude::*;

        let res = PGTest::new("pgtest_basic").await;
        assert_that!(res.is_ok()).is_true();
    }
}
