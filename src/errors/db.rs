use deadpool_postgres::PoolError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("Unspecified connection error: {0}")]
    Generic(String),
    #[error("Database error: {0}")]
    DB(tokio_postgres::Error),
    #[error("Connection pool error: {0}")]
    Pool(PoolError),
    #[error("Migration run error: {0}")]
    Migrations(MigrationError),
}

impl From<tokio_postgres::Error> for ConnectionError {
    fn from(tp: tokio_postgres::Error) -> Self {
        Self::DB(tp)
    }
}

impl From<MigrationError> for ConnectionError {
    fn from(me: MigrationError) -> Self {
        Self::Migrations(me)
    }
}

impl From<PoolError> for ConnectionError {
    fn from(pe: PoolError) -> Self {
        Self::Pool(pe)
    }
}

#[derive(Debug, Error)]
pub enum SaveError {
    #[error("error while saving: {0}")]
    Generic(String),
    #[error("database error while saving: {0}")]
    DBError(tokio_postgres::Error),
    #[error("error while encoding json: {0}")]
    JSONCodecError(String),
    #[error("error while refreshing results after write: {0}")]
    ReloadError(LoadError),
    #[error("db connection error: {0}")]
    ConnectionError(ConnectionError),
}

impl From<ConnectionError> for SaveError {
    fn from(e: ConnectionError) -> Self {
        Self::ConnectionError(e)
    }
}

impl From<LoadError> for SaveError {
    fn from(e: LoadError) -> Self {
        return Self::JSONCodecError(e.to_string());
    }
}

impl From<serde_json::Error> for SaveError {
    fn from(e: serde_json::Error) -> Self {
        return Self::JSONCodecError(e.to_string());
    }
}

impl From<tokio_postgres::Error> for SaveError {
    fn from(tp: tokio_postgres::Error) -> Self {
        Self::DBError(tp)
    }
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("error while loading: {0}")]
    Generic(String),
    #[error("database error while loading: {0}")]
    DBError(tokio_postgres::Error),
    #[error("error while decoding json: {0}")]
    JSONCodecError(String),
    #[error("error while connecting to database: {0}")]
    ConnectionError(ConnectionError),
    #[error("invalid token in enum translation")]
    InvalidEnum,
    #[error("key not found")]
    NotFound,
}

impl From<ConnectionError> for LoadError {
    fn from(ce: ConnectionError) -> Self {
        Self::ConnectionError(ce)
    }
}

impl From<serde_json::Error> for LoadError {
    fn from(e: serde_json::Error) -> Self {
        return Self::JSONCodecError(e.to_string());
    }
}

impl From<tokio_postgres::Error> for LoadError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::DBError(e)
    }
}

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("Unspecified migration error: {0}")]
    Generic(String),
    #[error("Database error: {0}")]
    DBError(tokio_postgres::Error),
    #[error("migration error: {0}")]
    Error(refinery::Error),
}

impl From<tokio_postgres::Error> for MigrationError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::DBError(e)
    }
}

impl From<refinery::Error> for MigrationError {
    fn from(e: refinery::Error) -> Self {
        Self::Error(e)
    }
}

impl From<ConnectionError> for MigrationError {
    fn from(e: ConnectionError) -> Self {
        Self::Generic(e.to_string())
    }
}
