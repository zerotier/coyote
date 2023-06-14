use futures_core::Future;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryFrom, ops::Add, sync::Arc};
use tokio::sync::Mutex;

use crate::{
    errors::db::{LoadError, SaveError},
    models::{order::Challenge, Postgres},
};

use super::handlers::order::OrderStatus;

// most of this is RFC8555 section 8
// read RFC8555 7.1.6 on state transitions between different parts of the challenge

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(into = "String")]
/// ChallengeType is an enum describing the challenge types coyote supports. Currently tls-alpn is
/// unsupported.
pub enum ChallengeType {
    /// dns-01 challenge type
    DNS01,
    /// http-01 challenge type
    HTTP01,
}

impl TryFrom<&str> for ChallengeType {
    type Error = LoadError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "dns-01" => Ok(ChallengeType::DNS01),
            "http-01" => Ok(ChallengeType::HTTP01),
            _ => Err(LoadError::InvalidEnum),
        }
    }
}

impl Into<String> for ChallengeType {
    fn into(self) -> String {
        match self {
            ChallengeType::DNS01 => "dns-01",
            ChallengeType::HTTP01 => "http-01",
        }
        .to_string()
    }
}

impl ChallengeType {
    pub(crate) fn to_string(self) -> String {
        self.into()
    }
}

#[derive(Clone)]
/// Challenger is an async supervisor used to perform challenges on demand. This is a simple
/// monitored queue with expiration applied at every loop iteration.
pub struct Challenger {
    list: Arc<Mutex<HashMap<String, Challenge>>>,
    expiration: Option<chrono::Duration>,
}

impl Challenger {
    /// Construct a new challenger; challenges will last as long as `expiriation` is set to, or
    /// forever if Option::None.
    pub fn new(expiration: Option<chrono::Duration>) -> Self {
        Self {
            list: Arc::new(Mutex::new(HashMap::new())),
            expiration,
        }
    }

    pub(crate) async fn schedule(&self, c: Challenge) {
        self.list.lock().await.insert(c.reference.clone(), c);
    }

    /// tick should be called in a loop in its own async routine with an interval between
    /// iterations. This performs each challenge in the queue and invalidates any expired
    /// challenges. To commit to storage, call reconcile.
    pub async fn tick<T, F>(&self, ticker: T)
    where
        T: Fn(Challenge) -> F,
        F: Future<Output = Option<()>>,
    {
        let mut lock = self.list.lock().await;
        let mut ch = HashMap::new();
        let mut sv = Vec::new();
        let mut iv = Vec::new();

        for (s, c) in lock.iter_mut() {
            if let OrderStatus::Processing = c.status {
                ch.insert(s.clone(), c.clone());
            }
        }

        drop(lock);

        let expires = self.expiration.is_some();
        let now = chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now());

        for (s, c) in ch {
            if expires && c.created_at.add(self.expiration.unwrap()) < now {
                iv.push(s.clone());
                continue;
            }

            match ticker(c.clone()).await {
                Some(_) => {
                    sv.push(s.clone());
                }
                None => {}
            }
        }

        let mut lock = self.list.lock().await;

        for s in sv {
            match lock.get_mut(&s) {
                Some(i) => i.status = OrderStatus::Valid,
                None => {}
            }
        }

        for s in iv {
            match lock.get_mut(&s) {
                Some(i) => i.status = OrderStatus::Invalid,
                None => {}
            }
        }
    }

    /// reconcile should be called after tick. This actually commits the challenge results to the
    /// backing storage.
    pub async fn reconcile(&self, db: Postgres) -> Result<(), SaveError> {
        let mut lock = self.list.lock().await;
        let mut db_lock = db.client().await?;
        let tx = db_lock.transaction().await?;
        let mut sv = Vec::new();

        // FIXME needs to manage challenge statuses, or that needs to move up a level
        for (s, c) in lock.iter_mut() {
            match c.status {
                OrderStatus::Pending | OrderStatus::Processing => {}
                _ => {
                    let mut c: crate::models::order::Challenge = c.clone().into();
                    c.persist_status(&tx).await?;
                    sv.push(s.clone());
                }
            }
        }

        for s in sv {
            lock.remove(&s);
        }

        tx.commit().await?;

        Ok(())
    }
}

mod tests {

    #[tokio::test(flavor = "multi_thread")]
    async fn test_challenge_scheduler_basic_with_expiration() {
        use super::{ChallengeType, Challenger};
        use crate::acme::handlers::order::OrderStatus;
        use crate::models::order::{Authorization, Challenge, Order};
        use crate::models::Record;
        use crate::test::PGTest;
        use crate::util::make_nonce;
        use spectral::prelude::*;
        use std::time::Duration;

        let pg = PGTest::new("test_challenge_scheduler_basic_with_expiration")
            .await
            .unwrap();
        let c = Challenger::new(Some(chrono::Duration::seconds(1)));

        let mut order = Order::default();
        order.create(pg.db()).await.unwrap();

        let mut authz = Authorization::default();
        authz.order_id = order.order_id.clone();
        authz.identifier = Some("example.com".to_string());
        authz.create(pg.db().clone()).await.unwrap();

        // FIXME some of this shit needs to be in default()
        let mut challenge = Challenge {
            id: None,
            order_id: order.order_id.clone(),
            authorization_id: authz.reference.clone(),
            identifier: "example.com".to_string(),
            challenge_type: ChallengeType::DNS01,
            reference: make_nonce(None),
            token: make_nonce(None),
            status: OrderStatus::Processing,
            issuing_address: "127.0.0.1".to_string(),
            created_at: chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now()),
            deleted_at: None,
            validated: None,
        };

        challenge.create(pg.db()).await.unwrap();

        c.schedule(challenge.clone()).await;
        c.tick(|_c| async { Some(()) }).await;
        c.reconcile(pg.db()).await.unwrap();

        let challenges = order
            .challenges(&pg.db().client().await.unwrap().transaction().await.unwrap())
            .await
            .unwrap();

        assert_that!(challenges.len()).is_equal_to(1);
        assert_that!(challenges[0].id).is_equal_to(challenge.id);
        assert_that!(challenges[0].status).is_equal_to(OrderStatus::Valid);
        assert_that!(challenges[0].validated).is_some();

        let mut challenge = Challenge {
            id: None,
            order_id: order.order_id.clone(),
            authorization_id: authz.reference.clone(),
            identifier: "example.com".to_string(),
            challenge_type: ChallengeType::DNS01,
            reference: make_nonce(None),
            token: make_nonce(None),
            status: OrderStatus::Processing,
            issuing_address: "127.0.0.1".to_string(),
            created_at: chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now()),
            deleted_at: None,
            validated: None,
        };

        challenge.create(pg.db()).await.unwrap();

        // wait for the challenge to expire
        tokio::time::sleep(Duration::new(2, 0)).await;

        c.schedule(challenge.clone()).await;
        c.tick(|_c| async { None }).await;
        c.reconcile(pg.db()).await.unwrap();

        let challenges = order
            .challenges(&pg.db().client().await.unwrap().transaction().await.unwrap())
            .await
            .unwrap();

        assert_that!(challenges.len()).is_equal_to(2);
        assert_that!(challenges[1].id).is_equal_to(challenge.id);
        assert_that!(challenges[1].status).is_equal_to(OrderStatus::Invalid);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_challenge_scheduler_async() {
        use super::{ChallengeType, Challenger};
        use crate::acme::handlers::order::OrderStatus;
        use crate::models::order::{Authorization, Challenge, Order};
        use crate::models::Record;
        use crate::test::PGTest;
        use crate::util::make_nonce;
        use spectral::prelude::*;
        use std::time::Duration;
        use tokio::sync::mpsc;

        let pg = PGTest::new("test_challenge_scheduler_async").await.unwrap();
        let c = Challenger::new(Some(chrono::Duration::seconds(1)));
        let db = pg.db();

        let (s, mut r) = mpsc::unbounded_channel();
        let mut handles = Vec::new();

        let c2 = c.clone();
        let db2 = db.clone();
        let supervisor = tokio::spawn(async move {
            loop {
                c2.tick(|_c| async { Some(()) }).await;
                c2.reconcile(db2.clone()).await.unwrap();
                tokio::time::sleep(Duration::new(1, 0)).await;
            }
        });

        for _ in 0..10 {
            let c = c.clone();
            let mut order = Order::default();
            order.create(db.clone()).await.unwrap();
            let mut authz = Authorization::default();
            authz.identifier = Some("example.com".to_string());
            authz.order_id = order.order_id.clone();
            authz.create(db.clone()).await.unwrap();
            let s = s.clone();
            let db2 = db.clone();

            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    let mut challenge = Challenge {
                        id: None,
                        order_id: order.order_id.clone(),
                        authorization_id: authz.reference.clone(),
                        identifier: "example.com".to_string(),
                        token: make_nonce(None),
                        reference: make_nonce(None),
                        challenge_type: ChallengeType::DNS01,
                        status: OrderStatus::Pending,
                        issuing_address: "127.0.0.1".to_string(),
                        created_at: chrono::DateTime::<chrono::Local>::from(
                            std::time::SystemTime::now(),
                        ),
                        deleted_at: None,
                        validated: None,
                    };

                    challenge.create(db2.clone()).await.unwrap();
                    c.schedule(challenge.clone()).await;
                    s.send((order.clone(), challenge.id.unwrap())).unwrap();
                }
            }));
        }

        drop(s);
        tokio::time::sleep(Duration::new(2, 0)).await; // give the supervisor an opp to wake up

        loop {
            if let Some((order, challenge_id)) = r.recv().await {
                let mut lockeddb = db.clone().client().await.unwrap();
                let tx = lockeddb.transaction().await.unwrap();

                let ch = order.challenges(&tx).await.unwrap();
                assert_that!(ch
                    .iter()
                    .find(|x| x.id.is_some() && x.id.unwrap() == challenge_id))
                .is_some();
            } else {
                break;
            }
        }

        supervisor.abort();
    }
}
