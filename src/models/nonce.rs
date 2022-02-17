use super::{LoadError, Record, Postgres, SaveError};
use crate::util::make_nonce;
use async_trait::async_trait;
use tokio_postgres::{Row, Transaction};

#[derive(Clone)]
pub struct Nonce {
    nonce: String,
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.nonce)
    }
}

impl PartialEq for Nonce {
    fn eq(&self, other: &Self) -> bool {
        self.nonce.eq(&other.nonce)
    }
}

impl Nonce {
    pub fn new() -> Self {
        Self {
            nonce: make_nonce(None),
        }
    }
}

#[async_trait]
impl Record<String> for Nonce {
    async fn new_from_row(row: &Row, _tx: &Transaction<'_>) -> Result<Self, LoadError> {
        if row.len() > 0 {
            Ok(Self {
                nonce: row.get("nonce"),
            })
        } else {
            Err(LoadError::NotFound)
        }
    }

    fn id(&self) -> Result<Option<String>, LoadError> {
        return Ok(Some(self.nonce.clone()));
    }

    async fn find(id: String, db: Postgres) -> Result<Self, LoadError> {
        let mut db = db.client().await?;
        let row = db
            .query_one("select nonce from nonces where nonce = $1", &[&id])
            .await?;

        let tx = db.transaction().await?;

        Self::new_from_row(&row, &tx).await
    }

    async fn create(&mut self, db: Postgres) -> Result<String, SaveError> {
        let mut db = db.client().await?;
        let tx = db.transaction().await?;
        tx.execute("insert into nonces (nonce) values ($1)", &[&self.nonce])
            .await?;
        tx.commit().await?;

        Ok(self.nonce.clone())
    }

    async fn delete(&self, db: Postgres) -> Result<(), SaveError> {
        let mut db = db.client().await?;
        let tx = db.transaction().await?;
        let res = tx
            .execute("delete from nonces where nonce = $1", &[&self.nonce])
            .await?;
        tx.commit().await?;

        if res == 0 {
            return Err(SaveError::Generic("nonce was already removed".to_string()));
        }

        Ok(())
    }

    async fn update(&self, _: Postgres) -> Result<(), SaveError> {
        Err(SaveError::Generic("cannot update a nonce".to_string()))
    }
}

mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn nonce_crud_test() {
        use spectral::prelude::*;

        use super::Nonce;
        use crate::models::Record;
        use crate::test::PGTest;

        let pg = PGTest::new("nonce_crud_test").await.unwrap();
        let db = pg.db();

        let mut nonce = Nonce::new();
        nonce.create(db.clone()).await.unwrap();

        let found = Nonce::find(nonce.id().unwrap().unwrap(), db.clone())
            .await
            .unwrap();

        assert_that!(nonce).is_equal_to(found.clone());

        let res = found.delete(db.clone()).await;
        assert_that!(res).is_ok();
        let res = found.delete(db.clone()).await;
        assert_that!(res).is_err();

        let res = Nonce::find(found.id().unwrap().unwrap(), db.clone()).await;
        assert_that!(res).is_err();
    }
}
