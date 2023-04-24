use std::{
    convert::TryInto,
    sync::Arc,
    time::{Duration, SystemTime},
};

use log::warn;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{extension, X509Extension, X509Name, X509Req, X509},
};
use tokio::sync::RwLock;

pub(crate) fn st_to_asn1(time: SystemTime) -> Result<Asn1Time, ErrorStack> {
    Asn1Time::from_unix(
        time.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .try_into()
            .unwrap_or_default(),
    )
}

/// CA defines a certificate authority in the standard sense of the word; it is used to sign
/// certificate signing requests and return them as fully functional certificates. To create one,
/// use the ::new constructor.
#[derive(Clone, Debug)]
pub struct CA {
    certificate: X509,
    private_key: PKey<Private>,
}

impl CA {
    /// new constructs a new certificate authority with a X.509 certificate and private key.
    pub fn new(certificate: X509, private_key: PKey<Private>) -> Self {
        Self {
            certificate,
            private_key,
        }
    }

    /// returns the certificate
    pub fn certificate(self) -> X509 {
        self.certificate
    }

    /// returns the private key
    pub fn private_key(self) -> PKey<Private> {
        self.private_key
    }

    /// signs a CSR with the CA's private key. The not_before and not_after parameters can be used
    /// to control its lifetime.
    pub fn generate_and_sign_cert(
        &self,
        req: X509Req,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> Result<X509, ErrorStack> {
        let mut builder = X509::builder()?;
        builder.set_pubkey(req.public_key()?.as_ref())?;
        builder.set_issuer_name(self.certificate.issuer_name())?;
        builder.set_serial_number(
            BigNum::from_u32(rand::random::<u32>())?
                .as_ref()
                .to_asn1_integer()?
                .as_ref(),
        )?;

        let exts = req.extensions();
        if let Ok(exts) = exts {
            for ext in exts {
                builder.append_extension(ext)?;
            }
        }

        builder.append_extension(
            extension::KeyUsage::new()
                .critical()
                .key_encipherment()
                .digital_signature()
                .build()?,
        )?;

        builder.append_extension(
            extension::ExtendedKeyUsage::new()
                .server_auth()
                .client_auth()
                .build()?,
        )?;

        builder.append_extension(
            extension::AuthorityKeyIdentifier::new()
                .keyid(false)
                .build(&builder.x509v3_context(Some(&self.certificate), None))?,
        )?;

        builder.append_extension(
            extension::SubjectKeyIdentifier::new().build(&builder.x509v3_context(Some(&self.certificate), None))?,
        )?;

        builder.append_extension(X509Extension::new(
            None,
            Some(&builder.x509v3_context(None, None)),
            "issuerAltName",
            "issuer:copy",
        )?)?;

        builder.set_subject_name(req.subject_name())?;
        builder.set_version(2)?;
        builder.set_not_before(st_to_asn1(not_before)?.as_ref())?;
        builder.set_not_after(st_to_asn1(not_after)?.as_ref())?;

        builder.sign(&self.private_key, MessageDigest::sha512())?;
        Ok(builder.build())
    }

    /// new_test_ca is a convenience function for creating a quick and dirty CA for use in tests
    /// and demo applications (such as the examples).
    pub fn new_test_ca() -> Result<Self, ErrorStack> {
        let mut builder = X509::builder()?;

        let mut namebuilder = X509Name::builder()?;
        namebuilder.append_entry_by_text("C", "US")?;
        namebuilder.append_entry_by_text("O", "ZeroTier")?;
        namebuilder.append_entry_by_text("CN", "CA Signing Certificate")?;
        namebuilder.append_entry_by_text("ST", "California")?;
        namebuilder.append_entry_by_text("L", "Irvine")?;
        namebuilder.append_entry_by_text("OU", "A Test Suite")?;
        builder.set_subject_name(&namebuilder.build())?;

        let mut namebuilder = X509Name::builder()?;
        namebuilder.append_entry_by_text("C", "US")?;
        namebuilder.append_entry_by_text("O", "ZeroTier")?;
        namebuilder.append_entry_by_text("CN", "CA Signing Certificate")?;
        namebuilder.append_entry_by_text("ST", "California")?;
        namebuilder.append_entry_by_text("L", "Irvine")?;
        namebuilder.append_entry_by_text("OU", "A Test Suite")?;
        builder.set_issuer_name(&namebuilder.build())?;

        builder.set_serial_number(
            BigNum::from_u32(rand::random::<u32>())?
                .as_ref()
                .to_asn1_integer()?
                .as_ref(),
        )?;

        let key = Rsa::generate(4096)?;
        // FIXME there has to be a much better way of doing this!
        let pubkey = PKey::public_key_from_pem(&key.public_key_to_pem().unwrap()).unwrap();

        builder.set_pubkey(&pubkey)?;
        builder.set_version(2)?;
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;

        builder.append_extension(X509Extension::new(
            None,
            Some(&builder.x509v3_context(None, None)),
            "basicConstraints",
            "critical,CA:true,pathlen:0",
        )?)?;

        builder.append_extension(X509Extension::new(
            None,
            Some(&builder.x509v3_context(None, None)),
            "keyUsage",
            "critical,keyCertSign",
        )?)?;

        builder.append_extension(X509Extension::new(
            None,
            Some(&builder.x509v3_context(None, None)),
            "subjectKeyIdentifier",
            "hash",
        )?)?;

        builder.append_extension(X509Extension::new(
            None,
            Some(&builder.x509v3_context(None, None)),
            "issuerAltName",
            "issuer:copy",
        )?)?;

        let privkey = PKey::from_rsa(key)?;
        builder.sign(privkey.as_ref(), MessageDigest::sha512())?;
        Ok(Self::new(builder.build(), privkey))
    }
}

/// CACollector is an async observer which waits for a CA to arrive, and fosters the creation of
/// signed CSRs as certificates. This allows for the rotation of CA certificates, or delayed
/// loading, without loss of functionality due to race conditions. Please see the `acmed` example for usage.
#[derive(Clone, Debug)]
pub struct CACollector {
    poll_interval: Duration,
    ca: SharedCA,
}

/// SharedCA is a simple type for managing the locking around a CA.
type SharedCA = Arc<RwLock<Option<CA>>>;

impl CACollector {
    /// new is a constructor; the duration provided determines how often the loop will awake and
    /// process a CA injection.
    pub fn new(poll_interval: Duration) -> Self {
        Self {
            poll_interval,
            ca: Arc::new(RwLock::new(None)),
        }
    }

    /// returns the CA as a SharedCA.
    pub fn ca(self) -> SharedCA {
        self.ca.clone()
    }

    /// majority of callers will use this function to collect the CA. It takes a closure which
    /// accepts a CA and returns it to this function so that it can overwrite the previous CA.
    pub async fn spawn_collector<F>(&mut self, f: F)
    where
        F: Fn() -> Result<CA, ErrorStack>,
    {
        loop {
            let res = f();

            match res {
                Ok(ca) => { self.ca.write().await.replace(ca); },
                Err(e) => warn!("Failed to retrieve CA, signing will will continue to use the old CA, if any. Error: {}", e.to_string())
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    /// similar to CA::generate_and_sign_cert, this signs the CSR through the SharedCA provided by
    /// the collector.
    pub async fn sign(
        self,
        req: X509Req,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> Result<X509, ErrorStack> {
        Ok(self
            .ca()
            .read()
            .await
            .clone()
            .unwrap()
            .generate_and_sign_cert(req, not_before, not_after)?)
    }
}

#[cfg(test)]
mod tests {
    use openssl::{error::ErrorStack, x509::X509Req};

    fn generate_csr() -> Result<X509Req, ErrorStack> {
        use openssl::{pkey::PKey, rsa::Rsa, x509::X509Name};

        let mut namebuilder = X509Name::builder().unwrap();
        namebuilder
            .append_entry_by_text("CN", "example.org")
            .unwrap();
        let mut req = X509Req::builder().unwrap();
        req.set_subject_name(&namebuilder.build()).unwrap();

        let key = Rsa::generate(4096).unwrap();
        // FIXME there has to be a much better way of doing this!
        let pubkey = PKey::public_key_from_pem(&key.public_key_to_pem().unwrap()).unwrap();

        req.set_pubkey(&pubkey).unwrap();
        Ok(req.build())
    }

    #[test]
    fn test_basic_ca_sign() {
        use spectral::prelude::*;

        use super::{st_to_asn1, CA};
        use openssl::{pkey::PKey, rsa::Rsa};
        use std::time::SystemTime;

        let now = SystemTime::now();

        let ca = CA::new_test_ca().unwrap();
        let signed = ca
            .generate_and_sign_cert(generate_csr().unwrap(), SystemTime::UNIX_EPOCH, now)
            .unwrap();

        let result = signed.verify(&ca.private_key());
        assert_that!(result).is_ok();
        assert_that!(result.unwrap()).is_true();

        let badkey = Rsa::generate(4096).unwrap();
        let result = signed.verify(PKey::from_rsa(badkey).unwrap().as_ref());
        assert_that!(result).is_ok();
        assert_that!(result.unwrap()).is_false();

        assert_that!(signed.not_before())
            .is_equal_to(&*st_to_asn1(SystemTime::UNIX_EPOCH).unwrap());
        assert_that!(signed.not_after()).is_equal_to(&*st_to_asn1(now).unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ca_collector() {
        use super::{st_to_asn1, CACollector, CA};
        use openssl::{pkey::PKey, rsa::Rsa};
        use spectral::prelude::*;
        use std::time::Duration;
        use std::time::SystemTime;

        let collector = CACollector::new(Duration::new(0, 500));

        let mut inner = collector.clone();
        let handle = tokio::spawn(async move {
            // we only want one of these, instead of polling for new ones, in this test.
            let ca = CA::new_test_ca().unwrap();
            inner
                .spawn_collector(|| -> Result<CA, ErrorStack> { Ok(ca.clone()) })
                .await
        });

        tokio::time::sleep(Duration::new(1, 0)).await;

        let now = SystemTime::now();
        let signed = collector
            .clone()
            .sign(generate_csr().unwrap(), SystemTime::UNIX_EPOCH, now)
            .await
            .unwrap();

        let result = signed.verify(&collector.ca().read().await.clone().unwrap().private_key());
        assert_that!(result).is_ok();
        assert_that!(result.unwrap()).is_true();

        let badkey = Rsa::generate(4096).unwrap();
        let result = signed.verify(PKey::from_rsa(badkey).unwrap().as_ref());
        assert_that!(result).is_ok();
        assert_that!(result.unwrap()).is_false();

        assert_that!(signed.not_before())
            .is_equal_to(&*st_to_asn1(SystemTime::UNIX_EPOCH).unwrap());
        assert_that!(signed.not_after()).is_equal_to(&*st_to_asn1(now).unwrap());

        handle.abort();
    }
}
