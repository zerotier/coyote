use std::convert::{TryFrom, TryInto};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_postgres::{Row, Transaction};
use url::Url;

use crate::{
    acme::{handlers::account::NewAccount, jose},
    errors::acme::JWSError,
    util::make_nonce,
};

use super::{LoadError, Postgres, Record, SaveError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Account {
    pub id: Option<i32>,
    jwk_id: i32,
    orders_nonce: String,
    contacts: Vec<String>,
    created_at: chrono::DateTime<chrono::Local>,
    deleted_at: Option<chrono::DateTime<chrono::Local>>,
}

pub(crate) fn new_accounts(
    account: NewAccount,
    jwk: JWK,
    _db: Postgres,
) -> Result<Account, LoadError> {
    let jwk_id = jwk.id()?;

    if jwk_id.is_none() {
        return Err(LoadError::Generic(
            "missing JWK in account save".to_string(),
        ));
    }

    let contacts = account.contacts();
    let contacts = contacts.unwrap();
    let jwk_id = jwk_id.unwrap();

    Ok(Account::new(
        jwk_id,
        contacts
            .iter()
            .map(|c| c.to_owned().into())
            .collect::<Vec<String>>(),
    ))
}

pub async fn get_contacts_for_account(
    id: i32,
    tx: &Transaction<'_>,
) -> Result<Vec<String>, LoadError> {
    let mut contacts = Vec::new();

    let rows = tx
        .query("select contact from contacts where account_id=$1", &[&id])
        .await?;
    for row in rows {
        contacts.push(row.get("contact"));
    }

    Ok(contacts)
}

impl Account {
    pub fn new(jwk_id: i32, contacts: Vec<String>) -> Self {
        Self {
            jwk_id,
            contacts,
            orders_nonce: make_nonce(super::NONCE_KEY_SIZE),
            id: None,
            created_at: chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now()),
            deleted_at: None,
        }
    }

    pub async fn find_by_kid(jwk_id: i32, db: Postgres) -> Result<Self, LoadError> {
        let mut lockeddb = db.client().await?;
        let tx = lockeddb.transaction().await?;

        let res = tx
            .query_one("select * from accounts where jwk_id=$1", &[&jwk_id])
            .await?;

        Self::new_from_row(&res, &tx).await
    }

    pub async fn find_deleted(id: i32, db: Postgres) -> Result<Self, LoadError> {
        let mut lockeddb = db.client().await?;
        let tx = lockeddb.transaction().await?;

        let res = tx
            .query_one("select * from accounts where id=$1", &[&id])
            .await?;

        Self::new_from_row(&res, &tx).await
    }
}

#[async_trait]
impl Record<i32> for Account {
    async fn new_from_row(row: &Row, tx: &Transaction<'_>) -> Result<Self, LoadError> {
        Ok(Self {
            id: Some(row.get("id")),
            jwk_id: row.get("jwk_id"),
            orders_nonce: row.get("orders_nonce"),
            contacts: get_contacts_for_account(row.get("id"), tx).await?,
            created_at: row.get("created_at"),
            deleted_at: row.get("deleted_at"),
        })
    }

    async fn find(id: i32, db: Postgres) -> Result<Self, LoadError> {
        let mut lockeddb = db.client().await?;
        let tx = lockeddb.transaction().await?;

        let res = tx
            .query_one(
                "select * from accounts where id=$1 and deleted_at is null",
                &[&id],
            )
            .await?;

        Self::new_from_row(&res, &tx).await
    }

    fn id(&self) -> Result<Option<i32>, LoadError> {
        Ok(self.id)
    }

    async fn create(&mut self, db: Postgres) -> Result<i32, SaveError> {
        let mut db = db.client().await?;
        let tx = db.transaction().await?;

        let res = tx
            .query_one(
                "
                    insert into accounts (jwk_id, orders_nonce) values ($1, $2)
                    returning id, created_at
                ",
                &[&self.jwk_id, &self.orders_nonce],
            )
            .await?;

        let id = res.get("id");
        let created_at = res.get("created_at");

        self.id = Some(id);
        self.created_at = created_at;

        for contact in &self.contacts {
            tx.query_one(
                "
                        insert into contacts (account_id, contact) values ($1, $2)
                        returning id, created_at
                    ",
                &[&id, &contact],
            )
            .await?;
        }

        tx.commit().await?;

        return Ok(id);
    }

    async fn delete(&self, db: Postgres) -> Result<(), SaveError> {
        if self.id.is_none() {
            return Err(SaveError::Generic(
                "this JWK record was never saved".to_string(),
            ));
        }

        let mut db = db.client().await?;
        let tx = db.transaction().await?;
        let res = tx
            .execute(
                "update accounts set deleted_at=CURRENT_TIMESTAMP where id=$1 and deleted_at is null",
                &[&self.id.unwrap()],
            )
            .await?;

        if res == 0 {
            // FIXME this should probably be a log warning later
            return Err(SaveError::Generic(
                "db did not delete primary key; was already removed".to_string(),
            ));
        }

        Ok(tx.commit().await?)
    }

    async fn update(&self, _db: Postgres) -> Result<(), SaveError> {
        Err(SaveError::Generic(
            "accounts may not be updated".to_string(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JWK {
    pub id: Option<i32>,
    pub nonce_key: String,
    pub alg: String,
    pub n: Option<String>,
    pub e: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    pub created_at: chrono::DateTime<chrono::Local>,
    pub deleted_at: Option<chrono::DateTime<chrono::Local>>,
}

impl JWK {
    pub fn new_rs256(n: String, e: String) -> Self {
        Self {
            id: None,
            nonce_key: make_nonce(super::NONCE_KEY_SIZE),
            n: Some(n),
            e: Some(e),
            alg: "RS256".into(),
            x: None,
            y: None,
            created_at: chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now()),
            deleted_at: None,
        }
    }

    pub fn new_es256(x: String, y: String) -> Self {
        Self {
            id: None,
            nonce_key: make_nonce(super::NONCE_KEY_SIZE),
            x: Some(x),
            y: Some(y),
            alg: "ES256".into(),
            e: None,
            n: None,
            created_at: chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now()),
            deleted_at: None,
        }
    }

    pub async fn find_deleted(id: i32, db: Postgres) -> Result<Self, LoadError> {
        let mut db = db.client().await?;
        let tx = db.transaction().await?;

        let res = tx
            .query_one("select * from jwks where id=$1", &[&id])
            .await?;

        Self::new_from_row(&res, &tx).await
    }

    pub async fn find_by_nonce(nonce_key: String, db: Postgres) -> Result<Self, LoadError> {
        let res = db
            .clone()
            .client()
            .await?
            .query_one(
                "select id from jwks where nonce_key=$1 and deleted_at is null",
                &[&nonce_key],
            )
            .await;

        match res {
            Ok(row) => {
                let id: i32 = row.get(0);
                Self::find(id, db).await
            }

            Err(_) => Err(LoadError::NotFound),
        }
    }

    pub async fn find_by_kid(url: Url, db: Postgres) -> Result<Self, LoadError> {
        if url.path_segments().is_none() {
            return Err(LoadError::NotFound);
        }

        if url.path_segments().unwrap().last().is_none() {
            return Err(LoadError::NotFound);
        }

        Self::find_by_nonce(url.path_segments().unwrap().last().unwrap().to_string(), db).await
    }

    pub fn nonce_key(&self) -> String {
        self.nonce_key.clone()
    }
}

impl TryFrom<&mut jose::JWK> for JWK {
    type Error = JWSError;

    fn try_from(jwk: &mut jose::JWK) -> Result<Self, Self::Error> {
        let (alg, n, e, x, y) = jwk.params();

        let alg = match alg {
            Some(alg) => alg,
            None => return Err(JWSError::InvalidPublicKey),
        };

        Ok(JWK {
            nonce_key: make_nonce(super::NONCE_KEY_SIZE),
            n,
            e,
            x,
            y,
            alg,
            id: None,
            created_at: chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now()),
            deleted_at: None,
        })
    }
}

impl TryInto<jose::JWK> for JWK {
    type Error = JWSError;

    fn try_into(self) -> Result<jose::JWK, Self::Error> {
        let mut crv = None;

        if self.x.is_some() && self.y.is_some() {
            // NOTE once more algos are supported this will need to change
            crv = Some("P-256".to_string())
        }

        Ok(jose::JWK {
            _use: None,
            kty: match self.alg.as_str() {
                "ES256" => "ECDSA",
                "RS256" => "RSA",
                _ => "you should really be validating this field",
            }
            .to_string(),
            crv,
            n: self.n,
            e: self.e,
            x: self.x,
            y: self.y,
            alg: Some(self.alg),
        })
    }
}

#[async_trait]
impl Record<i32> for JWK {
    async fn new_from_row(row: &Row, _tx: &Transaction<'_>) -> Result<Self, LoadError> {
        Ok(Self {
            id: Some(row.get("id")),
            nonce_key: row.get("nonce_key"),
            n: row.get("n"),
            e: row.get("e"),
            alg: row.get("alg"),
            x: row.get("x"),
            y: row.get("y"),
            created_at: row.get("created_at"),
            deleted_at: row.get("deleted_at"),
        })
    }

    async fn find(id: i32, db: Postgres) -> Result<Self, LoadError> {
        let mut db = db.client().await?;
        let tx = db.transaction().await?;

        let res = tx
            .query_one(
                "select * from jwks where id=$1 and deleted_at is null",
                &[&id],
            )
            .await?;

        Self::new_from_row(&res, &tx).await
    }

    fn id(&self) -> Result<Option<i32>, LoadError> {
        Ok(self.id)
    }

    async fn create(&mut self, db: Postgres) -> Result<i32, SaveError> {
        let mut db = db.client().await?;
        let tx = db.transaction().await?;

        let res = tx
            .query_one(
                "
        insert into jwks (nonce_key, n, e, alg, x, y) values ($1, $2, $3, $4, $5, $6)
        returning id, created_at
        ",
                &[
                    &self.nonce_key,
                    &self.n,
                    &self.e,
                    &self.alg,
                    &self.x,
                    &self.y,
                ],
            )
            .await?;

        tx.commit().await?;

        let id = res.get("id");
        let created_at = res.get("created_at");
        self.id = Some(id);
        self.created_at = created_at;

        return Ok(id);
    }

    async fn delete(&self, db: Postgres) -> Result<(), SaveError> {
        if self.id.is_none() {
            return Err(SaveError::Generic(
                "this JWK record was never saved".to_string(),
            ));
        }

        let mut db = db.client().await?;
        let tx = db.transaction().await?;
        let res = tx
            .execute(
                "update jwks set deleted_at=CURRENT_TIMESTAMP where id=$1 and deleted_at is null",
                &[&self.id.unwrap()],
            )
            .await?;

        if res == 0 {
            // FIXME this should probably be a log warning later
            return Err(SaveError::Generic(
                "db did not delete primary key; was already removed".to_string(),
            ));
        }

        Ok(tx.commit().await?)
    }

    async fn update(&self, _db: Postgres) -> Result<(), SaveError> {
        Err(SaveError::Generic("JWKs may not be updated".to_string()))
    }
}

mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn account_crud_single_contact() {
        use spectral::prelude::*;

        use super::{Account, JWK};
        use crate::acme::handlers::account::NewAccount;
        use crate::models::Record;
        use crate::test::PGTest;
        use std::convert::TryInto;

        let pg = PGTest::new("account_crud_single_contact").await.unwrap();

        let mut acct = NewAccount::default();
        acct.contact = Some(vec!["mailto:erik@hollensbe.org".try_into().unwrap()]);

        let mut jwk = JWK::new_es256("x".to_string(), "y".to_string());
        jwk.create(pg.db()).await.unwrap();
        let acct = super::new_accounts(acct, jwk, pg.db());
        assert_that!(acct).is_ok();
        let mut acct = acct.unwrap();
        assert_that!(acct.create(pg.db()).await).is_ok();
        let id = acct.id();
        assert_that!(id).is_ok();
        let id = id.unwrap();
        assert_that!(id).is_some();
        assert_that!(id.unwrap()).is_not_equal_to(0);
        let id = id.unwrap();

        let newacct = Account::find(id, pg.db()).await.unwrap();
        assert_that!(acct).is_equal_to(newacct);

        assert_that!(acct.delete(pg.db()).await).is_ok();
        assert_that!(acct.delete(pg.db()).await).is_err();

        let oldacct = Account::find_deleted(id, pg.db()).await.unwrap();

        acct.deleted_at = oldacct.deleted_at;

        assert_that!(acct).is_equal_to(oldacct);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn jwk_check_constraint() {
        use spectral::prelude::*;

        // this test ensures that n & e and x & y are sticky to each other. other validation is performed outside
        // the db, but this is good for keeping the db hygenic.
        use crate::test::PGTest;
        use tokio_postgres::types::ToSql;

        let pg = PGTest::new("jwk_check_constraint").await.unwrap();

        let bad: &[(&str, &[&(dyn ToSql + Sync)])] = &[
            (
                "insert into jwks (nonce_key, n, x, alg) values ($1, $2, $3, $4)",
                &[
                    &"firstbad".to_string(),
                    &"aaaa".to_string(),
                    &"bbbb".to_string(),
                    &"alg".to_string(),
                ],
            ),
            (
                "insert into jwks (nonce_key, e, y, alg) values ($1, $2, $3, $4)",
                &[
                    &"secondbad".to_string(),
                    &"aaaa".to_string(),
                    &"bbbb".to_string(),
                    &"alg".to_string(),
                ],
            ),
        ];

        for args in bad.iter() {
            let res = pg
                .db()
                .client()
                .await
                .unwrap()
                .execute(args.0, args.1)
                .await;
            assert_that!(res).is_err();
        }

        let good: &[(&str, &[&(dyn ToSql + Sync)])] = &[
            (
                "insert into jwks (nonce_key, n, e, alg) values ($1, $2, $3, $4)",
                &[
                    &"firstgood".to_string(),
                    &"aaaa".to_string(),
                    &"bbbb".to_string(),
                    &"alg".to_string(),
                ],
            ),
            (
                "insert into jwks (nonce_key, x, y, alg) values ($1, $2, $3, $4)",
                &[
                    &"secondgood".to_string(),
                    &"aaaa".to_string(),
                    &"bbbb".to_string(),
                    &"alg".to_string(),
                ],
            ),
        ];

        for args in good.iter() {
            let res = pg
                .db()
                .client()
                .await
                .unwrap()
                .execute(args.0, args.1)
                .await;
            assert_that!(res).is_ok();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn jwk_find_nonexistent_nonce() {
        use spectral::prelude::*;

        use super::JWK;
        use crate::errors::db::LoadError;
        use crate::test::PGTest;

        let pg = PGTest::new("jwk_find_nonexistent_nonce").await.unwrap();

        let res = JWK::find_by_nonce("abcdef".to_string(), pg.db()).await;
        assert_that!(res).is_err();
        assert_that!(res.unwrap_err()).matches(|e| match e {
            // ugh!
            &LoadError::NotFound => true,
            _ => false,
        });
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn jwk_create_delete_find() {
        use spectral::prelude::*;

        use super::JWK;
        use crate::models::Record;
        use crate::test::PGTest;

        let pg = PGTest::new("jwk_create_delete_find").await.unwrap();

        let jwks = &mut [
            JWK::new_rs256("aaaaaa".to_string(), "bbbb".to_string()),
            JWK::new_es256("aaaaaa".to_string(), "bbbb".to_string()),
        ];

        for origjwk in jwks.iter_mut() {
            let res = origjwk.create(pg.db()).await;
            assert_that!(res).is_ok();

            let res = JWK::find(origjwk.id().unwrap().unwrap(), pg.db()).await;
            assert_that!(res).is_ok();

            let jwk = res.unwrap();

            assert_that!(jwk).is_equal_to(origjwk.clone());

            let res = JWK::find_by_nonce(origjwk.nonce_key(), pg.db()).await;
            assert_that!(res).is_ok();

            let jwk = res.unwrap();

            assert_that!(jwk).is_equal_to(origjwk.clone());

            let res = origjwk.delete(pg.db()).await;
            assert_that!(res).is_ok();

            let res = origjwk.delete(pg.db()).await;
            assert_that!(res).is_err();

            let res = JWK::find(origjwk.id().unwrap().unwrap(), pg.db()).await;
            assert_that!(res).is_err();

            let res = JWK::find_by_nonce(origjwk.nonce_key(), pg.db()).await;
            assert_that!(res).is_err();

            let res = JWK::find_deleted(origjwk.id().unwrap().unwrap(), pg.db()).await;
            assert_that!(res).is_ok();

            let jwk = res.unwrap();
            origjwk.deleted_at = jwk.deleted_at;

            assert_that!(jwk).is_equal_to(origjwk.clone());
        }
    }
}
