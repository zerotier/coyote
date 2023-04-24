use std::convert::{TryFrom, TryInto};
use std::ops::Add;

use async_trait::async_trait;
use openssl::x509::X509;
use tokio_postgres::{Row, Transaction};
use url::Url;

use super::{Postgres, Record, RecordList};
use crate::acme::challenge::ChallengeType;
use crate::acme::ACMEIdentifier;
use crate::{
    acme::{dns::DNSName, handlers::order::OrderStatus},
    errors::db::{LoadError, SaveError},
    util::make_nonce,
};

#[derive(Debug, Clone, PartialEq)]
pub struct Order {
    id: Option<i32>,
    pub order_id: String,
    pub error: Option<crate::errors::Error>,
    pub status: OrderStatus,
    pub created_at: chrono::DateTime<chrono::Local>,
    pub authorizations: Option<Vec<Authorization>>,
    pub not_before: Option<chrono::DateTime<chrono::Local>>,
    pub not_after: Option<chrono::DateTime<chrono::Local>>,
    expires: Option<chrono::DateTime<chrono::Local>>,
    finalized: bool,
    deleted_at: Option<chrono::DateTime<chrono::Local>>,
}

impl Default for Order {
    fn default() -> Self {
        Self {
            id: None,
            order_id: make_nonce(super::NONCE_KEY_SIZE),
            finalized: false,
            expires: None,
            not_before: None,
            not_after: None,
            error: None,
            status: OrderStatus::Pending,
            authorizations: None,
            created_at: chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now()),
            deleted_at: None,
        }
    }
}

impl Order {
    pub(crate) fn new(
        not_before: Option<chrono::DateTime<chrono::Local>>,
        not_after: Option<chrono::DateTime<chrono::Local>>,
    ) -> Order {
        Order {
            not_before,
            not_after,
            ..Default::default()
        }
    }

    pub(crate) async fn find_by_reference(
        order_id: String,
        db: Postgres,
    ) -> Result<Self, LoadError> {
        let mut client = db.clone().client().await?;
        let tx = client.transaction().await?;
        let res = tx
            .query_one("select id from orders where order_id = $1", &[&order_id])
            .await;

        match res {
            Ok(row) => {
                let id = row.get(0);
                drop(tx);
                Self::find(id, db).await
            }
            Err(_) => Err(LoadError::NotFound),
        }
    }

    pub(crate) fn into_handler_order(
        self,
        url: Url,
    ) -> Result<crate::acme::handlers::order::Order, LoadError> {
        let auths = self.authorizations;

        let mut dt_expires: Option<chrono::DateTime<chrono::Local>> = None;
        let mut dt_notbefore: Option<chrono::DateTime<chrono::Local>> = None;
        let mut dt_notafter: Option<chrono::DateTime<chrono::Local>> = None;

        if let Some(expires) = self.expires {
            dt_expires = Some(expires.into())
        }

        if let Some(notbefore) = self.not_before {
            dt_notbefore = Some(notbefore.into())
        }

        if let Some(notafter) = self.not_after {
            dt_notafter = Some(notafter.into())
        }

        let o = crate::acme::handlers::order::Order {
            status: Some(self.status.clone()),
            expires: dt_expires,
            identifiers: if auths.clone().is_some() {
                auths
                    .clone()
                    .unwrap()
                    .iter()
                    // FIXME remove these unwraps
                    .map(|a| {
                        ACMEIdentifier::DNS(
                            DNSName::from_str(&a.identifier.clone().unwrap()).unwrap(),
                        )
                    })
                    .collect::<Vec<ACMEIdentifier>>()
            } else {
                Vec::new()
            },
            not_after: dt_notafter,
            not_before: dt_notbefore,
            error: self.error,
            authorizations: if auths.clone().is_some() {
                Some(
                    auths
                        .clone()
                        .unwrap()
                        .iter()
                        .map(|x: &Authorization| x.into_url(url.clone()))
                        .collect::<Vec<url::Url>>(),
                )
            } else {
                None
            },
            finalize: Some(
                url.join(&format!("./order/{}/finalize", self.order_id))
                    .unwrap(),
            ),
            // FIXME this needs to be at a unique location, not related to the order id
            certificate: Some(
                url.join(&format!("./order/{}/certificate", self.order_id))
                    .unwrap(),
            ),
        };

        Ok(o)
    }

    // FIXME this is only used in tests rn
    #[cfg(test)]
    pub(crate) async fn challenges(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<Vec<Challenge>, LoadError> {
        Challenge::collect(self.order_id.clone(), tx).await
    }

    pub(crate) async fn record_certificate(
        &self,
        certificate: X509,
        db: Postgres,
    ) -> Result<i32, SaveError> {
        let mut cert = Certificate::default();
        cert.order_id = self.order_id.clone();
        let pem = match certificate.to_pem() {
            Ok(pem) => pem,
            Err(e) => return Err(SaveError::Generic(e.to_string())),
        };

        cert.certificate = pem;
        cert.create(db).await
    }

    pub(crate) async fn certificate(&self, db: Postgres) -> Result<Certificate, LoadError> {
        Certificate::find_by_order_id(self.order_id.clone(), db).await
    }
}

#[async_trait]
impl Record<i32> for Order {
    async fn new_from_row(_row: &Row, _tx: &Transaction<'_>) -> Result<Self, LoadError> {
        Err(LoadError::Generic("unimplemented".to_string()))
    }

    async fn find(id: i32, db: super::Postgres) -> Result<Self, crate::errors::db::LoadError> {
        let mut client = db.client().await?;
        let tx = client.transaction().await?;

        let order_row = tx
            .query_one(
                "select * from orders where id=$1 and deleted_at is null",
                &[&id],
            )
            .await?;

        let order_id: String = order_row.get("order_id");
        let mut status = OrderStatus::Pending;
        let authorizations = Authorization::collect(order_id.clone(), &tx).await?;

        // ensure all at least one challenge has passed for each identifier (carried in the
        // authorization)
        //
        // FIXME test the shit out of this later
        let mut valid = false;
        for authz in &authorizations {
            if authz.identifier.is_none() {
                // FIXME this should never happen and we should do something here
                break;
            }

            valid = false;

            // any invalids breaks it.
            for chall in authz.challenges(&tx).await? {
                if chall.status == OrderStatus::Invalid {
                    status = OrderStatus::Invalid;
                    break;
                } else if chall.status == OrderStatus::Valid {
                    valid = true
                }
            }

            // escape hatch for invalid status
            if status == OrderStatus::Invalid || !valid {
                break;
            }
        }

        if valid {
            status = OrderStatus::Valid;
        }

        let error: Option<String> = order_row.get("error");

        Ok(Order {
            id: order_row.get("id"),
            order_id: order_row.get("order_id"),
            expires: order_row.get("expires"),
            not_before: order_row.get("not_before"),
            not_after: order_row.get("not_after"),
            error: if error.is_some() {
                serde_json::from_str(&error.unwrap())?
            } else {
                None
            },
            finalized: order_row.get("finalized"),
            deleted_at: order_row.get("deleted_at"),
            created_at: order_row.get("created_at"),
            status: status.into(),
            authorizations: Some(authorizations),
        })
    }

    fn id(&self) -> Result<Option<i32>, LoadError> {
        Ok(self.id)
    }

    async fn create(&mut self, db: super::Postgres) -> Result<i32, crate::errors::db::SaveError> {
        let mut client = db.client().await?;
        let tx = client.transaction().await?;

        let mut error = None;

        if self.error.is_some() {
            error = Some(serde_json::to_string(&self.error)?)
        }

        let res = tx
            .query_one(
                "
            insert into orders
                (order_id, expires, not_before, not_after, error, finalized)
            values 
                ($1, $2, $3, $4, $5, $6)
            returning 
                id, created_at
        ",
                &[
                    &self.order_id,
                    &self.expires,
                    &self
                        .not_before
                        .unwrap_or(chrono::DateTime::<chrono::Local>::from(
                            std::time::SystemTime::now(),
                        )),
                    &self.clone().not_after.unwrap_or(
                        chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now())
                            .add(chrono::Duration::days(365)),
                    ),
                    &error,
                    &self.finalized,
                ],
            )
            .await?;

        let id = res.get("id");
        self.id = Some(id);
        self.created_at = res.get("created_at");

        tx.commit().await?;

        return Ok(id);
    }

    async fn update(&self, db: super::Postgres) -> Result<(), SaveError> {
        if self.id.is_none() {
            return Err(SaveError::Generic(
                "record was not saved and updates were requested".to_string(),
            ));
        }

        let mut client = db.client().await?;
        let tx = client.transaction().await?;

        let mut error = None;

        if self.error.is_some() {
            error = Some(serde_json::to_string(&self.error)?)
        }

        let res = tx
            .execute(
                "update orders set deleted_at=$1, expires=$2, error=$3 where id=$4 and deleted_at is null",
                &[&self.deleted_at, &self.expires, &error, &self.id.unwrap()],
            )
            .await?;

        if res != 1 {
            return Err(SaveError::Generic("row could not be deleted".to_string()));
        }

        // FIXME update authz and certs
        Ok(tx.commit().await?)
    }

    async fn delete(&self, db: super::Postgres) -> Result<(), SaveError> {
        if self.id.is_none() {
            return Err(SaveError::Generic(
                "record was not saved and deletion was requested".to_string(),
            ));
        }

        let mut client = db.client().await?;
        let tx = client.transaction().await?;

        let res = tx
            .execute(
                "update orders set deleted_at=CURRENT_TIMESTAMP where id=$1 and deleted_at is null",
                &[&self.id.unwrap()],
            )
            .await?;

        if res != 1 {
            return Err(SaveError::Generic("row could not be deleted".to_string()));
        }

        Ok(tx.commit().await?)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Challenge {
    pub id: Option<i32>,
    pub order_id: String,
    pub challenge_type: ChallengeType,
    pub identifier: String,
    pub token: String,
    pub reference: String,
    pub issuing_address: String,
    pub status: OrderStatus,
    pub validated: Option<chrono::DateTime<chrono::Local>>,
    pub created_at: chrono::DateTime<chrono::Local>,
    pub deleted_at: Option<chrono::DateTime<chrono::Local>>,
    pub authorization_id: String,
}

impl Challenge {
    pub fn new(
        order_id: String,
        authorization_id: String,
        challenge_type: ChallengeType,
        identifier: String,
        issuing_address: String,
        status: OrderStatus,
    ) -> Self {
        Self {
            id: None,
            order_id,
            authorization_id,
            challenge_type,
            identifier,
            token: make_nonce(None),
            reference: make_nonce(None),
            issuing_address,
            status,
            validated: None,
            created_at: chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now()),
            deleted_at: None,
        }
    }

    pub(crate) async fn find_by_reference(
        challenge_id: String,
        tx: &Transaction<'_>,
    ) -> Result<Self, LoadError> {
        let row = tx
            .query_one(
                "select * from orders_challenges where reference=$1",
                &[&challenge_id],
            )
            .await?;

        Self::new_from_row(&row)
    }

    pub(crate) async fn find_by_authorization(
        authorization: String,
        tx: &Transaction<'_>,
    ) -> Result<Vec<Self>, LoadError> {
        let rows = tx
            .query(
                "select * from orders_challenges where authorization_id = $1 order by created_at DESC",
                &[&authorization],
            )
            .await?;

        let mut ret = Vec::new();

        for row in rows {
            ret.push(Self::new_from_row(&row)?)
        }

        Ok(ret)
    }

    pub(crate) async fn authorization(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<Authorization, LoadError> {
        Authorization::find_by_reference(&self.authorization_id, tx).await
    }

    pub(crate) fn into_url(&self, url: url::Url) -> url::Url {
        url.join(&format!("./chall/{}", self.reference)).unwrap()
    }

    fn new_from_row(result: &Row) -> Result<Self, LoadError> {
        let ct: ChallengeType = result.get::<_, &str>("challenge_type").try_into()?;
        let id = result.get::<_, &str>("identifier");

        Ok(Self {
            id: result.get("id"),
            order_id: result.get("order_id"),
            authorization_id: result.get("authorization_id"),
            challenge_type: ct.clone(),
            identifier: id.to_string(),
            issuing_address: result.get("issuing_address"),
            validated: result.get("validated"),
            reference: result.get("reference"),
            token: result.get("token"),
            status: OrderStatus::try_from(result.get::<_, String>("status"))?,
            created_at: result.get("created_at"),
            deleted_at: result.get("deleted_at"),
        })
    }

    pub async fn create(&mut self, db: Postgres) -> Result<i32, SaveError> {
        let mut client = db.client().await?;
        let tx = client.transaction().await?;
        let res = tx.query_one(
            "insert into orders_challenges (order_id, authorization_id, challenge_type, issuing_address, identifier, token, reference, status, created_at, deleted_at) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) returning id",
            &[&self.order_id.clone(), &self.authorization_id.clone(), &self.challenge_type.clone().to_string(), &self.issuing_address, &self.identifier.clone().to_string(), &self.token.clone(), &self.reference.clone(), &self.status.clone().to_string(), &self.created_at, &self.deleted_at],
            ).await?;

        let id = res.get("id");
        tx.commit().await?;

        self.id = Some(id);

        Ok(id)
    }

    pub async fn persist_status(&mut self, tx: &Transaction<'_>) -> Result<(), SaveError> {
        match self.id {
            None => return Err(SaveError::Generic("save this record first".to_string())),
            _ => {}
        }

        if self.status == OrderStatus::Valid {
            self.validated = Some(chrono::DateTime::<chrono::Local>::from(
                std::time::SystemTime::now(),
            ))
        }

        tx.execute(
            "update orders_challenges set status=$1, validated=$2 where authorization_id=$3 and id=$4",
            &[
                &self.status.clone().to_string(),
                &self.validated,
                &self.authorization_id.clone(),
                &self.id.unwrap(),
            ],
        )
        .await?;
        Ok(())
    }
}

#[async_trait]
impl RecordList<String> for Challenge {
    async fn collect(order_id: String, tx: &Transaction<'_>) -> Result<Vec<Self>, LoadError> {
        let mut ret = Vec::new();

        let results = tx
            .query(
                "select * from orders_challenges where order_id = $1 order by created_at ASC",
                &[&order_id],
            )
            .await?;

        for result in results.iter() {
            ret.push(Self::new_from_row(result)?);
        }

        Ok(ret)
    }

    async fn latest(_order_id: String, _tx: &Transaction<'_>) -> Result<Self, LoadError> {
        return Err(LoadError::Generic("unimplemented".to_string()));
    }

    async fn append(&self, order_id: String, tx: &Transaction<'_>) -> Result<Vec<Self>, SaveError> {
        tx.execute(
            "insert into orders_challenges (order_id, authorization_id, challenge_type, issuing_address, token, reference, status, created_at, deleted_at) values ($1, $2, $3, $4, $5, $6, $7, $8, $9) returning id",
            &[&order_id, &self.authorization_id.clone(), &self.challenge_type.clone().to_string(), &self.issuing_address, &self.token.clone(), &self.reference.clone(), &self.status.clone().to_string(), &self.created_at, &self.deleted_at],
            ).await?;
        Ok(Self::collect(order_id, tx).await?)
    }

    async fn remove(&self, _: String, _tx: &Transaction<'_>) -> Result<(), SaveError> {
        return Err(SaveError::Generic("unimplemented".to_string()));
    }

    async fn exists(&self, _order_id: String, _tx: &Transaction<'_>) -> Result<bool, LoadError> {
        return Err(LoadError::Generic("unimplemented".to_string()));
    }
}

// XXX this and authorizations are awful similar and it drives me nuts
#[derive(Debug, Clone, PartialEq)]
pub struct Certificate {
    id: Option<i32>,
    order_id: String,
    reference: String,
    pub certificate: Vec<u8>,
    created_at: chrono::DateTime<chrono::Local>,
    deleted_at: Option<chrono::DateTime<chrono::Local>>,
}

impl Default for Certificate {
    fn default() -> Self {
        Self {
            id: None,
            order_id: "".to_string(),
            reference: make_nonce(None),
            certificate: Vec::new(),
            created_at: chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now()),
            deleted_at: None,
        }
    }
}

impl Into<String> for Certificate {
    fn into(self) -> String {
        self.reference
    }
}

impl Certificate {
    pub(crate) async fn find_by_order_id(
        order_id: String,
        db: Postgres,
    ) -> Result<Self, LoadError> {
        let mut client = db.client().await?;
        let tx = client.transaction().await?;

        let result = tx
            .query_one(
                "select * from orders_certificate where order_id = $1 and deleted_at is null limit 1",
                &[&order_id],
            )
            .await?;

        Self::new_from_row(&result, &tx).await
    }
}

#[async_trait]
impl Record<i32> for Certificate {
    async fn new_from_row(row: &Row, _tx: &Transaction<'_>) -> Result<Self, LoadError> {
        Ok(Self {
            id: row.get("id"),
            order_id: row.get("order_id"),
            reference: row.get("reference"),
            certificate: row.get("certificate"),
            created_at: row.get("created_at"),
            deleted_at: row.get("deleted_at"),
        })
    }

    async fn find(id: i32, db: super::Postgres) -> Result<Self, LoadError> {
        let mut client = db.client().await?;
        let tx = client.transaction().await?;

        let result = tx
            .query_one(
                "select * from orders_certificate where id = $1 and deleted_at is null",
                &[&id],
            )
            .await?;

        Self::new_from_row(&result, &tx).await
    }

    fn id(&self) -> Result<Option<i32>, LoadError> {
        Ok(self.id)
    }

    async fn create(&mut self, db: super::Postgres) -> Result<i32, crate::errors::db::SaveError> {
        let mut client = db.client().await?;
        let tx = client.transaction().await?;

        let ret = tx.query_one(
            "insert into orders_certificate (order_id, reference, certificate) values ($1, $2, $3) returning id, created_at",
            &[&self.order_id, &self.reference, &self.certificate]
        ).await?;

        self.id = Some(ret.get("id"));
        self.created_at = ret.get("created_at");

        tx.commit().await?;

        Ok(self.id.unwrap())
    }

    async fn delete(&self, db: super::Postgres) -> Result<(), SaveError> {
        if self.id.is_none() {
            return Err(SaveError::Generic(
                "record was not saved and deletion was requested".to_string(),
            ));
        }

        let mut client = db.client().await?;
        let tx = client.transaction().await?;

        let res = tx.execute(
            "update orders_certificate set deleted_at=CURRENT_TIMESTAMP where id=$1 and deleted_at is null",
            &[&self.id.unwrap()],
        )
        .await?;

        if res != 1 {
            return Err(SaveError::Generic("row could not be deleted".to_string()));
        }

        Ok(tx.commit().await?)
    }

    async fn update(&self, _db: super::Postgres) -> Result<(), SaveError> {
        Err(SaveError::Generic(
            "update is not implemented for order certificates".to_string(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Authorization {
    id: Option<i32>,
    // FIXME make this Option<> to guard against writing an empty string
    pub order_id: String,
    pub reference: String,
    pub expires: chrono::DateTime<chrono::Local>,
    pub identifier: Option<String>,
    created_at: chrono::DateTime<chrono::Local>,
    pub deleted_at: Option<chrono::DateTime<chrono::Local>>,
}

impl Default for Authorization {
    fn default() -> Self {
        Self {
            id: None,
            order_id: "".to_string(),
            identifier: None,
            expires: chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now()),
            reference: make_nonce(None),
            created_at: chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now()),
            deleted_at: None,
        }
    }
}

impl ToString for Authorization {
    fn to_string(&self) -> String {
        self.reference.clone()
    }
}

impl Authorization {
    pub(crate) async fn find_by_reference(
        reference: &str,
        tx: &Transaction<'_>,
    ) -> Result<Self, LoadError> {
        let res = tx
            .query_one(
                "select * from orders_authorizations where reference = $1",
                &[&reference],
            )
            .await?;

        Ok(Self::new_from_row(&res, tx).await?)
    }

    pub(crate) async fn challenges(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<Vec<Challenge>, LoadError> {
        Challenge::find_by_authorization(self.reference.clone(), tx).await
    }

    pub fn into_url(&self, baseurl: Url) -> Url {
        baseurl
            .join(&format!("./authz/{}", self.reference))
            .unwrap()
    }
}

#[async_trait]
impl RecordList<String> for Authorization {
    async fn collect(order_id: String, tx: &Transaction<'_>) -> Result<Vec<Self>, LoadError> {
        let mut ret = Vec::new();

        let results = tx
            .query(
                "select * from orders_authorizations where order_id = $1 order by created_at ASC",
                &[&order_id],
            )
            .await?;

        for result in results.iter() {
            ret.push(Self::new_from_row(result, tx).await?);
        }

        Ok(ret)
    }

    async fn latest(order_id: String, tx: &Transaction<'_>) -> Result<Self, LoadError> {
        let row = tx
            .query_one(
                "select * from orders_authorizations where order_id = $1 order by created_at ASC limit 1",
                &[&order_id],
            )
            .await?;

        Ok(Self::new_from_row(&row, &tx).await?)
    }

    async fn append(&self, order_id: String, tx: &Transaction<'_>) -> Result<Vec<Self>, SaveError> {
        if self.identifier.is_none() {
            return Err(SaveError::Generic(
                "cannot insert an authorization without an identifier".to_string(),
            ));
        }

        tx.execute("insert into orders_authorizations (order_id, expires, identifier, reference, created_at, deleted_at) values ($1, $2, $3, $4, $5, $6)", &[&order_id, &self.expires, &self.identifier.clone().unwrap(),&self.reference, &self.created_at, &self.deleted_at]).await?;
        Ok(Self::collect(order_id, tx).await?)
    }

    async fn remove(&self, order_id: String, tx: &Transaction<'_>) -> Result<(), SaveError> {
        tx.execute(
            "delete from orders_authorizations where id=$1 and order_id=$2",
            &[&self.id()?, &order_id],
        )
        .await?;
        Ok(())
    }

    async fn exists(&self, order_id: String, tx: &Transaction<'_>) -> Result<bool, LoadError> {
        let res = tx
            .query_one(
                "select count(*)::integer as count from orders_authorizations where id=$1 and order_id=$2",
                &[&self.id()?, &order_id],
            )
            .await?;

        Ok(res.get::<_, i32>(0) == 1)
    }
}

#[async_trait]
impl Record<i32> for Authorization {
    async fn new_from_row(row: &Row, _tx: &Transaction<'_>) -> Result<Self, LoadError> {
        Ok(Self {
            id: row.get("id"),
            order_id: row.get("order_id"),
            identifier: Some(row.get::<_, String>("identifier")),
            reference: row.get("reference"),
            expires: row.get("expires"),
            created_at: row.get("created_at"),
            deleted_at: row.get("deleted_at"),
        })
    }

    async fn find(id: i32, db: super::Postgres) -> Result<Self, LoadError> {
        let mut client = db.client().await?;
        let tx = client.transaction().await?;

        let result = tx
            .query_one(
                "select * from orders_authorizations where id = $1 and deleted_at is null",
                &[&id],
            )
            .await?;

        Self::new_from_row(&result, &tx).await
    }

    fn id(&self) -> Result<Option<i32>, LoadError> {
        Ok(self.id)
    }

    async fn create(&mut self, db: super::Postgres) -> Result<i32, SaveError> {
        if self.identifier.is_none() {
            return Err(SaveError::Generic(
                "cannot insert an authorization without an identifier".to_string(),
            ));
        }

        let mut client = db.client().await?;
        let tx = client.transaction().await?;

        let ret = tx.query_one("insert into orders_authorizations (order_id, expires, reference, identifier) values ($1, $2, $3, $4) returning id, created_at", &[&self.order_id, &self.expires, &self.reference, &self.identifier]).await?;

        self.id = Some(ret.get("id"));
        self.created_at = ret.get("created_at");

        tx.commit().await?;

        Ok(self.id.unwrap())
    }

    async fn delete(&self, db: super::Postgres) -> Result<(), SaveError> {
        if self.id.is_none() {
            return Err(SaveError::Generic(
                "record was not saved and deletion was requested".to_string(),
            ));
        }

        let mut client = db.client().await?;
        let tx = client.transaction().await?;

        let res = tx.execute(
            "update orders_authorizations set deleted_at=CURRENT_TIMESTAMP where id=$1 and deleted_at is null",
            &[&self.id.unwrap()],
        )
        .await?;

        if res != 1 {
            return Err(SaveError::Generic("row could not be deleted".to_string()));
        }

        Ok(tx.commit().await?)
    }

    async fn update(&self, _db: super::Postgres) -> Result<(), SaveError> {
        Err(SaveError::Generic(
            "update is not implemented for order authorizations".to_string(),
        ))
    }
}

mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn test_order_certificate() {
        use super::Certificate;
        use crate::models::Record;
        use crate::test::PGTest;
        use crate::util::make_nonce;
        use spectral::prelude::*;

        let pg = PGTest::new("test_order_certificate").await.unwrap();

        let good = vec![Certificate {
            order_id: make_nonce(None),
            ..Default::default()
        }];

        for mut item in good {
            assert_that!(item.create(pg.db()).await).is_ok();
            assert_that!(item.id()).is_ok();
            assert_that!(item.id().unwrap()).is_some();
            assert_that!(item.id().unwrap().unwrap()).is_not_equal_to(0);

            assert_that!(item.order_id).is_not_equal_to("".to_string());
            assert_that!(item.reference).is_not_equal_to("".to_string());

            let s: String = item.clone().into();
            assert_that!(&s).is_equal_to(&item.reference);

            let new = Certificate::find(item.id().unwrap().unwrap(), pg.db()).await;
            assert_that!(new).is_ok();

            let new = new.unwrap();

            assert_that!(&new).is_equal_to(&item);

            assert_that!(item.update(pg.db()).await).is_err();

            assert_that!(item.delete(pg.db()).await).is_ok();

            let new = Certificate::find(item.id().unwrap().unwrap(), pg.db()).await;
            assert_that!(new).is_err();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_order_authorization() {
        use super::Authorization;
        use crate::models::{Record, RecordList};
        use crate::test::PGTest;
        use crate::util::make_nonce;

        use spectral::prelude::*;

        let pg = PGTest::new("test_order_authorization").await.unwrap();

        let mut bad = Authorization::default();

        assert_that!(bad.create(pg.db()).await).is_err();
        bad.order_id = make_nonce(None);
        assert_that!(bad.create(pg.db()).await).is_err();
        bad.identifier = Some("example.com".to_string());
        assert_that!(bad.create(pg.db()).await).is_ok();

        let good = vec![Authorization {
            order_id: make_nonce(None),
            identifier: Some("example.com".to_string()),
            ..Default::default()
        }];

        for mut item in good {
            assert_that!(item.create(pg.db()).await).is_ok();
            assert_that!(item.id()).is_ok();
            assert_that!(item.id().unwrap()).is_some();
            assert_that!(item.id().unwrap().unwrap()).is_not_equal_to(0);

            assert_that!(item.order_id).is_not_equal_to("".to_string());
            assert_that!(item.reference).is_not_equal_to("".to_string());

            let s: String = item.to_string();
            assert_that!(&s).is_equal_to(&item.reference);

            let new = Authorization::find(item.id().unwrap().unwrap(), pg.db()).await;
            assert_that!(new).is_ok();

            let mut new = new.unwrap();
            new.expires = chrono::DateTime::<chrono::Local>::from(std::time::SystemTime::now());
            item.expires = new.expires;

            assert_that!(&new).is_equal_to(&item);

            assert_that!(item.update(pg.db()).await).is_err();

            assert_that!(item.delete(pg.db()).await).is_ok();

            let new = Authorization::find(item.id().unwrap().unwrap(), pg.db()).await;
            assert_that!(new).is_err();
        }

        for _ in 0..10 {
            let mut obj = Authorization {
                order_id: "special".to_string(),
                identifier: Some("example.com".to_string()),
                ..Default::default()
            };

            assert_that!(obj.create(pg.db()).await).is_ok();
        }

        let auths = Authorization::collect(
            "special".to_string(),
            &pg.db().client().await.unwrap().transaction().await.unwrap(),
        )
        .await;
        assert_that!(auths).is_ok();
        let auths = auths.unwrap();

        assert_that!(auths.len()).is_equal_to(10);

        let mut bad2 = Authorization::default();

        let good2 = Authorization {
            order_id: "special".to_string(),
            identifier: Some("example.com".to_string()),
            ..Default::default()
        };

        let db = pg.db();
        let mut lockeddb = db.client().await.unwrap();
        let tx = lockeddb.transaction().await.unwrap();
        assert_that!(bad2.append("special".to_string(), &tx).await).is_err();

        // these drops are important because the errors will abort the tx
        drop(tx);
        bad2.order_id = make_nonce(None);

        let tx = lockeddb.transaction().await.unwrap();
        assert_that!(bad2.append("special".to_string(), &tx).await).is_err();

        drop(tx);
        bad2.identifier = Some("example.com".to_string());

        let tx = lockeddb.transaction().await.unwrap();
        assert_that!(bad2.append("special".to_string(), &tx).await).is_ok();

        let auths = good2.append("special".to_string(), &tx).await.unwrap();
        tx.commit().await.unwrap();

        assert_that!(auths.len()).is_equal_to(12);

        for auth in &auths {
            assert_that!(auth
                .exists(
                    "special".to_string(),
                    &lockeddb.transaction().await.unwrap(),
                )
                .await
                .unwrap())
            .is_true();
        }

        assert_that!(auths[11]
            .exists(
                "special".to_string(),
                &lockeddb.transaction().await.unwrap(),
            )
            .await
            .unwrap())
        .is_true();

        let tx = lockeddb.transaction().await.unwrap();

        assert_that!(auths[11].remove("special".to_string(), &tx).await).is_ok();

        tx.commit().await.unwrap();

        let auths_new = Authorization::collect(
            "special".to_string(),
            &lockeddb.transaction().await.unwrap(),
        )
        .await;
        assert_that!(auths_new).is_ok();
        let auths_new = auths_new.unwrap();

        assert_that!(auths[11]
            .exists(
                "special".to_string(),
                &lockeddb.transaction().await.unwrap(),
            )
            .await
            .unwrap())
        .is_false();

        assert_that!(auths_new.len()).is_equal_to(11);
    }
}
