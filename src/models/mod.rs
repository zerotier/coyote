use std::str::FromStr;

use crate::errors::db::*;
use async_trait::async_trait;
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool};
use refinery::Report;
use tokio_postgres::{Config, NoTls, Row, Transaction};

/// these are the actual migrations that will be executed. this module is automatically generated.
pub mod migrations {
    use refinery::embed_migrations;
    embed_migrations!("migrations");
}

/// account operations
pub mod account;
/// operations related to nonce management
pub mod nonce;
/// order operations
pub mod order;

pub(crate) const NONCE_KEY_SIZE: Option<usize> = Some(32);

/// Postgres is our (currently only) implementation of backing storage. It uses a
/// [deadpool_postgres] Pool and migrates automatically with [refinery].
#[derive(Clone)]
pub struct Postgres {
    pool: Pool,
    config: String,
}

impl Postgres {
    /// This function only makes one connection with [tokio_postgres] and just returns that client. It does not use a pool.
    /// This makes some situations easier, notably migrations.
    pub async fn connect_one(config: &str) -> Result<tokio_postgres::Client, ConnectionError> {
        let (client, conn) = tokio_postgres::connect(config, NoTls).await?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                log::error!("postgresql connection error: {}", e)
            }
        });

        Ok(client)
    }

    /// This function initializes Postgres with a pool size of `pool_size` and connection
    /// configuration `config`. The `config` string is a standard PostgreSQL DSN, e.g.:
    ///
    ///
    /// `user=foo hostname=localhost password=quux`
    pub async fn new(config: &str, pool_size: usize) -> Result<Self, ConnectionError> {
        let pg_config = Config::from_str(config)?;
        let mgr_config = ManagerConfig::default();
        let mgr = Manager::from_config(pg_config, NoTls, mgr_config);
        // FIXME deadpool's error here is in a private package, so we can't apply Try
        //       operations
        let pool = Pool::builder(mgr).max_size(pool_size).build().unwrap();

        Ok(Self {
            pool,
            config: config.to_string(),
        })
    }

    /// client returns the db client.
    pub async fn client(self) -> Result<Object, ConnectionError> {
        Ok(self.pool.get().await?)
    }

    /// migrate the database. The migration implementation is refinery and the migrations live in
    /// `migrations/` off the root of the repository, but are otherwise compiled into the library.
    pub async fn migrate(&self) -> Result<Report, MigrationError> {
        let mut c = Self::connect_one(&self.config).await?;
        let report = migrations::migrations::runner().run_async(&mut c).await?;
        Ok(report)
    }

    /// resets the database, destroying all data in the public schema.
    /// useful for tests.
    #[cfg(test)]
    pub(crate) async fn reset(&self) -> Result<(), SaveError> {
        let c = Self::connect_one(&self.config).await?;
        c.execute("drop schema public cascade", &[]).await?;
        c.execute("create schema public", &[]).await?;
        Ok(())
    }
}

/// This trait encapsulates a record with a typed primary key (PK). Each record is capable of a
/// number of operations on itself provided by the trait members, but a the database handle must be
/// passed, and it needs to be kept under lock inside many of the functions.
#[async_trait]
pub trait Record<PK>
where
    Self: Sized + Sync + Clone + Send + 'static,
{
    /// new_from_row converts a row in the database to the appropriate struct. This method is async
    /// so it can make other database calls, etc.
    async fn new_from_row(row: &Row, db: &Transaction<'_>) -> Result<Self, LoadError>;

    /// find a record by the PK, requires a database handle.
    async fn find(id: PK, db: Postgres) -> Result<Self, LoadError>;

    /// Get the ID (if available) of the primary key.
    fn id(&self) -> Result<Option<PK>, LoadError>;

    /// Create the record; mutates the record, returns the PK.
    async fn create(&mut self, db: Postgres) -> Result<PK, SaveError>;
    /// Update the record.
    async fn update(&self, db: Postgres) -> Result<(), SaveError>;
    /// Delete the record.
    async fn delete(&self, db: Postgres) -> Result<(), SaveError>;
}

/// This trait encapuslates a list of Records. Some set operations are supplied that work on a
/// transaction handle. FK is a typed foreign key against the join table.
#[async_trait]
pub trait RecordList<FK>
where
    Self: Sized + Sync + Clone + Send + 'static,
{
    /// Fetch the collection by its related foreign key
    async fn collect(id: FK, tx: &Transaction<'_>) -> Result<Vec<Self>, LoadError>;
    /// Get the latest record for a given collection
    async fn latest(id: FK, tx: &Transaction<'_>) -> Result<Self, LoadError>;
    /// append a record to this collection. Returns the new collection.
    async fn append(&self, id: FK, tx: &Transaction<'_>) -> Result<Vec<Self>, SaveError>;
    /// remove a record from this collection. You must re-call collect to get an updated list.
    async fn remove(&self, id: FK, tx: &Transaction<'_>) -> Result<(), SaveError>;
    /// Determine if a record exists in this collection.
    async fn exists(&self, id: FK, tx: &Transaction<'_>) -> Result<bool, LoadError>;
}

mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn test_migrate() {
        use crate::test::PGTest;
        use spectral::prelude::*;

        let pg = PGTest::new("test_migrate").await.unwrap();
        let db = pg.db();
        db.reset().await.unwrap();
        let report = db.migrate().await.unwrap();
        assert_that!(report.applied_migrations().len()).is_greater_than(0);

        let report = db.migrate().await.unwrap();
        assert_that!(report.applied_migrations().len()).is_equal_to(0);
    }
}
