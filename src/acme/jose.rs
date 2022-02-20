use std::{
    convert::{TryFrom, TryInto},
    time::SystemTime,
};

use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey, EcPointRef},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    sha::sha256,
    sign::{Signer, Verifier},
};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    acme::{NonceValidator, PostgresNonceValidator, ACME_EXPECTED_ALGS},
    errors::{acme::*, ACMEValidationError},
    util::{make_nonce, to_base64},
};

use lazy_static::lazy_static;

const NID_ES256: Nid = Nid::X9_62_PRIME256V1;

lazy_static! {
    pub(crate) static ref EC_GROUP: EcGroup = EcGroup::from_curve_name(NID_ES256).unwrap();
}

/// ACMEProtectedHeader identifies an ACME protected header per RFC8555. Typically this function is
/// deserialized into, but in the event you need a "fresh" ACME protected header, the functions
/// [ACMEProtectedHeader::new_jwk] and [ACMEProtectedHeader::new_kid] exist for construction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ACMEProtectedHeader {
    alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<JWK>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<Url>,
    nonce: String,
    url: Url,
}

impl ACMEProtectedHeader {
    /// This function constructs an ACME protected header from a JWK and the previous URL/nonce
    /// used to lead to this JWK instantiation. The constructed value will default to using an
    /// `alg` field of ES256, which is per [[struct@super::ACME_EXPECTED_ALGS]] preference.
    pub fn new_jwk(jwk: JWK, url: Url, nonce: String) -> Self {
        Self {
            url,
            alg: String::from(ACME_EXPECTED_ALGS[0].clone()),
            jwk: Some(jwk),
            kid: None,
            nonce,
        }
    }

    /// This function constructs an ACME protected header from a key id, and the previous URL/nonce
    /// used to lead to this JWK instantiation. The constructed value will default to using an
    /// `alg` field of ES256, which is per [[struct@super::ACME_EXPECTED_ALGS]] preference.
    pub fn new_kid(kid: Url, url: Url, nonce: String) -> Self {
        Self {
            url,
            alg: String::from(ACME_EXPECTED_ALGS[0].clone()),
            jwk: None,
            kid: Some(kid),
            nonce,
        }
    }

    /// nonce returns the replay-nonce supplied in this protected header.
    pub fn nonce(&self) -> String {
        self.nonce.clone()
    }

    /// kid returns the key identifier supplied in this protected header, or None if no key id
    /// existed.
    pub fn kid(&self) -> Option<Url> {
        self.kid.clone()
    }

    /// jwk returns the JSON web key supplied in this protected header, or None if no key
    /// existed.
    pub fn jwk(&mut self) -> Option<&mut JWK> {
        self.jwk.as_mut()
    }

    /// validate performs a ACME validation of the protected header, which includes:
    /// - validating the nonce exists
    /// - validating the nonce can be decoded
    /// - validating we at least have one of the two: jwk, key id.
    /// - validating the URL in the header equals the request URL (provided as a part of the
    ///   function call)
    /// - validating we have a salient `alg` field, which is in
    ///   [[struct@super::ACME_EXPECTED_ALGS]].
    /// - finally, the nonce is validated against storage, which is expected to implement
    ///   [super::NonceValidator].
    pub async fn validate(
        &self,
        request_url: Url,
        validator: PostgresNonceValidator,
    ) -> Result<(), ACMEValidationError> {
        if self.nonce.is_empty() {
            return Err(ACMEValidationError::NonceNotFound);
        }

        if base64::decode_config(self.nonce.clone(), base64::URL_SAFE_NO_PAD).is_err() {
            return Err(ACMEValidationError::NonceDecodeError);
        }

        if self.jwk.is_none() && self.kid.is_none() {
            return Err(ACMEValidationError::NoKeyProvided);
        }

        if !self.url.eq(&request_url) {
            return Err(ACMEValidationError::URLNotEqual(
                request_url.to_string(),
                self.url.to_string(),
            ));
        }

        if !ACME_EXPECTED_ALGS.contains(&self.alg) {
            return Err(ACMEValidationError::AlgNotEqual(
                ACME_EXPECTED_ALGS.join(", "),
                self.alg.to_string(),
            ));
        }

        Ok(validator.validate(&self.nonce).await?)
    }
}

/// ACME Public Key type enumeration
#[derive(Debug, Clone)]
pub enum ACMEKey {
    ECDSA(EcKey<Public>),
    RSA(Rsa<Public>),
}

/// ACME Private Key type enumeration
#[derive(Debug, Clone)]
pub enum ACMEPrivateKey {
    ECDSA(EcKey<Private>),
    RSA(Rsa<Private>),
}

impl TryFrom<&EcPointRef> for ACMEKey {
    type Error = JWSError;

    fn try_from(ec: &EcPointRef) -> Result<Self, Self::Error> {
        let mut ctx = openssl::bn::BigNumContext::new()?;
        let mut x = openssl::bn::BigNum::new()?;
        let mut y = openssl::bn::BigNum::new()?;
        ec.affine_coordinates_gfp(&EC_GROUP, &mut x, &mut y, &mut ctx)?;
        Ok((&mut JWK {
            x: Some(base64::encode_config(&x.to_vec(), base64::URL_SAFE_NO_PAD)),
            y: Some(base64::encode_config(&y.to_vec(), base64::URL_SAFE_NO_PAD)),
            alg: Some("ES256".into()),
            crv: Some("P-256".into()),
            _use: Some("sig".into()),
            kty: "EC".into(),
            n: None,
            e: None,
        })
            .try_into()?)
    }
}

impl TryFrom<Rsa<Public>> for ACMEKey {
    type Error = JWSError;

    fn try_from(value: Rsa<Public>) -> Result<Self, Self::Error> {
        Ok((&mut JWK {
            e: Some(base64::encode_config(
                &value.e().to_vec(),
                base64::URL_SAFE_NO_PAD,
            )),
            n: Some(base64::encode_config(
                &value.n().to_vec(),
                base64::URL_SAFE_NO_PAD,
            )),
            alg: Some("RS256".into()),
            kty: "RSA".into(),
            _use: Some("sig".into()),
            x: None,
            y: None,
            crv: None,
        })
            .try_into()?)
    }
}

impl TryFrom<&mut JWK> for ACMEKey {
    type Error = JWSError;

    fn try_from(jwk: &mut JWK) -> Result<Self, Self::Error> {
        log::info!("{}", jwk.kty);
        match jwk.kty.as_str() {
            "RSA" => Ok(ACMEKey::RSA(jwk.into_rsa()?)),
            "EC" | "ECDSA" => Ok(ACMEKey::ECDSA(jwk.into_ec()?)),
            _ => Err(JWSError::InvalidPublicKey),
        }
    }
}

impl TryInto<ACMEKey> for JWK {
    type Error = JWSError;
    fn try_into(self) -> Result<ACMEKey, Self::Error> {
        match self.kty.as_str() {
            "RSA" => Ok(ACMEKey::RSA(self.into_rsa()?)),
            "EC" | "ECDSA" => Ok(ACMEKey::ECDSA(self.into_ec()?)),
            _ => Err(JWSError::InvalidPublicKey),
        }
    }
}

impl TryFrom<JWS> for ACMEKey {
    type Error = JWSError;

    fn try_from(mut jws: JWS) -> Result<Self, Self::Error> {
        if let Some(jwk) = jws.protected()?.jwk() {
            return jwk.try_into();
        }

        return Err(JWSError::InvalidPublicKey);
    }
}

/// JWK is the implementation of JSON web keys: RFC7515.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWK {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "use")]
    pub _use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

impl JWK {
    /// into_rsa transforms the JWK into a RSA public key
    fn into_rsa(&self) -> Result<Rsa<Public>, JWSError> {
        if self.n.is_none() || self.e.is_none() {
            return Err(JWSError::Encode(
                "e/n parameters missing in RSA JWK translation".to_string(),
            ));
        }

        let n = base64::decode_config(self.n.clone().unwrap(), base64::URL_SAFE_NO_PAD)?;
        let e = base64::decode_config(self.e.clone().unwrap(), base64::URL_SAFE_NO_PAD)?;

        Ok(Rsa::from_public_components(
            BigNum::from_slice(&n)?,
            BigNum::from_slice(&e)?,
        )?)
    }

    /// into_ec transforms the JWK into a EC public key
    fn into_ec(&self) -> Result<EcKey<Public>, JWSError> {
        if self.x.is_none() || self.y.is_none() {
            return Err(JWSError::Encode(
                "x/y parameters missing in EC JWK translation".to_string(),
            ));
        }

        let x = base64::decode_config(self.x.clone().unwrap(), base64::URL_SAFE_NO_PAD)?;
        let y = base64::decode_config(self.y.clone().unwrap(), base64::URL_SAFE_NO_PAD)?;

        let key = EcKey::from_public_key_affine_coordinates(
            &EC_GROUP,
            BigNum::from_slice(&x)?.as_ref(),
            BigNum::from_slice(&y)?.as_ref(),
        )?;

        Ok(key)
    }

    /// from_jws transforms a JSON web signature into a JWK. It uses the ACME-derived `alg` field
    /// from the protected header to determine what crypto to use.
    #[allow(dead_code)]
    fn from_jws(jws: &mut JWS) -> Result<Self, JWSError> {
        let mut aph = jws.protected()?;
        let alg = aph.alg.clone();

        if aph.jwk().is_some() {
            let mut jwk = aph.jwk.unwrap();
            jwk.alg = Some(alg);
            return Ok(jwk);
        }

        return Err(JWSError::InvalidPublicKey);
    }

    // just a simple way to unroll private params without making them easy to dink with
    pub(crate) fn params(
        &self,
    ) -> (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        (
            self.alg.clone(),
            self.n.clone(),
            self.e.clone(),
            self.x.clone(),
            self.y.clone(),
        )
    }
}

/// JWS is an implementation of the JSON web signature RFC: RFC7515. The majority of API traffic
/// uses this structure to talk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWS {
    /// protected is the envelope, more or less, of the request. This corresponds to the
    /// [ACMEProtectedHeader] in most cases.
    protected: String,
    /// payload is more dynamic and usually corresponds to whatever request is being made. This
    /// field usually needs to have its type be dynamically derived.
    payload: String,
    /// the signature verifies that the key has indeed signed the payload.
    signature: String,
}

impl JWS {
    /// constructor taking a [ACMEProtectedHeader] and arbitrary type payload.
    pub fn new<T>(protected: &ACMEProtectedHeader, payload: &T) -> Self
    where
        T: serde::Serialize + ?Sized,
    {
        JWS {
            protected: to_base64(protected).expect("could not encode protected header"),
            payload: to_base64(payload).expect("could not encode payload"),
            signature: Default::default(),
        }
    }

    /// returns the [ACMEProtectedHeader].
    pub fn protected(&mut self) -> Result<ACMEProtectedHeader, JWSError> {
        let res = serde_json::from_slice::<ACMEProtectedHeader>(&base64::decode_config(
            self.protected.clone(),
            base64::URL_SAFE_NO_PAD,
        )?)?;

        Ok(res)
    }

    /// returns the payload. The type must be [serde_json] compatible.
    pub fn payload<T>(&self) -> Result<T, JWSError>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        Ok(serde_json::from_slice(&base64::decode_config(
            self.payload.clone(),
            base64::URL_SAFE_NO_PAD,
        )?)?)
    }

    /// verify verifies the protected header and payload were signed by the public key provided.
    pub fn verify(&self, key: ACMEKey) -> Result<bool, JWSValidationError> {
        let to_verify = format!("{}.{}", self.protected, self.payload);
        let digest = sha256(to_verify.as_bytes());

        let decoded = base64::decode_config(self.signature.clone(), base64::URL_SAFE_NO_PAD)?;

        match key {
            ACMEKey::ECDSA(key) => {
                if decoded.len() != 64 {
                    return Err(JWSValidationError::SignatureDecode);
                }

                let r = BigNum::from_slice(&decoded[0..32])?;
                let s = BigNum::from_slice(&decoded[32..64])?;

                let signature =
                    EcdsaSig::from_private_components(r, s).expect("could not program components");

                Ok(signature.verify(&digest, &key)?)
            }
            ACMEKey::RSA(key) => {
                let pkey = PKey::from_rsa(key)?;
                let mut verifier = Verifier::new(MessageDigest::sha256(), pkey.as_ref())?;
                verifier.update(to_verify.as_bytes())?;
                Ok(verifier.verify(&decoded)?)
            }
        }
    }

    /// verify_with_signature verifies with a third party signature
    pub fn verify_with_signature(
        &mut self,
        key: ACMEKey,
        signature: String,
    ) -> Result<bool, JWSValidationError> {
        // FIXME is this function even in use?
        self.signature = signature;
        self.verify(key)
    }

    /// sign the header and payload with a private key.
    pub fn sign(&mut self, key: ACMEPrivateKey) -> Result<Self, JWSError> {
        let to_sign = format!("{}.{}", self.protected, self.payload);

        match key {
            ACMEPrivateKey::ECDSA(key) => {
                let digest = sha256(to_sign.as_bytes());
                let signature = EcdsaSig::sign(&digest, &key)?;

                let r = signature.r().to_vec();
                let s = signature.s().to_vec();

                let mut v = Vec::with_capacity(r.len() + s.len());
                let pad = &[0; 32];
                v.extend_from_slice(
                    &pad.iter()
                        .take(32 - r.len())
                        .map(|c| *c)
                        .collect::<Vec<u8>>(),
                );
                v.extend_from_slice(&r);
                v.extend_from_slice(
                    &pad.iter()
                        .take(32 - s.len())
                        .map(|c| *c)
                        .collect::<Vec<u8>>(),
                );
                v.extend_from_slice(&s);

                self.signature = base64::encode_config(v, base64::URL_SAFE_NO_PAD);

                Ok(self.clone())
            }
            ACMEPrivateKey::RSA(key) => {
                let pkey = PKey::from_rsa(key)?;
                let mut signer = Signer::new(MessageDigest::sha256(), pkey.as_ref())?;
                signer.update(to_sign.as_bytes())?;

                self.signature =
                    base64::encode_config(signer.sign_to_vec().unwrap(), base64::URL_SAFE_NO_PAD);

                Ok(self.clone())
            }
        }
    }

    pub(crate) fn into_db_jwk(&self) -> Result<crate::models::account::JWK, JWSError> {
        let aph = self.clone().protected()?;
        if aph.jwk.is_none() {
            return Err(JWSError::InvalidPublicKey);
        }

        let jwk = aph.jwk.unwrap();

        Ok(crate::models::account::JWK {
            nonce_key: make_nonce(crate::models::NONCE_KEY_SIZE),
            n: jwk.n.clone(),
            e: jwk.e.clone(),
            x: jwk.x.clone(),
            y: jwk.y.clone(),
            alg: aph.alg.clone(),
            id: None,
            created_at: chrono::DateTime::<chrono::Local>::from(SystemTime::now()),
            deleted_at: None,
        })
    }
}

mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn aph_test_validate() {
        use super::*;
        use crate::test::TestService;
        use spectral::prelude::*;

        let svc = TestService::new("aph_test_validate").await;

        let good_url = Url::parse("https://one/two").unwrap();
        let bad_url = Url::parse("https://not/one/two").unwrap();

        let validator = crate::acme::PostgresNonceValidator::new(svc.pg.db());

        let kid = Url::parse("http://127.0.0.1:8000/accounts/this_is_a_kid").unwrap();

        let aph = ACMEProtectedHeader::new_kid(kid.clone(), good_url.clone(), "😀".to_string());
        assert_that!(aph.validate(good_url.clone(), validator.clone()).await)
            .is_err_containing(ACMEValidationError::NonceDecodeError);

        let aph = ACMEProtectedHeader::new_kid(kid.clone(), good_url.clone(), "".to_string());

        assert_that!(aph.validate(good_url.clone(), validator.clone()).await)
            .is_err_containing(ACMEValidationError::NonceNotFound);

        let aph = ACMEProtectedHeader::new_kid(
            kid.clone(),
            good_url.clone(),
            validator.make().await.expect("could not insert a nonce"),
        );
        assert_that!(aph.validate(good_url.clone(), validator.clone()).await).is_ok();

        assert_that!(
            ACMEProtectedHeader::new_kid(
                kid.clone(),
                good_url.clone(),
                validator.make().await.expect("could not insert a nonce")
            )
            .validate(bad_url.clone(), validator.clone())
            .await
        )
        .is_err_containing(ACMEValidationError::URLNotEqual(
            bad_url.to_string(),
            good_url.to_string(),
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn jws_validate() {
        use super::{ACMEProtectedHeader, JWS};
        use openssl::{ec::EcKey, rsa::Rsa};
        use serde::Serialize;
        use spectral::prelude::*;
        use std::convert::TryInto;
        use url::Url;

        #[derive(Serialize, Clone)]
        struct JWSTest {
            artist: String,
            song: String,
        }

        let payload = JWSTest {
            artist: "Tone Loc".to_string(),
            song: "Funky Cold Medina".to_string(),
        };

        let kid = Url::parse("http://127.0.0.1:8000/accounts/this_is_a_kid").unwrap();

        // we won't be validating the protected headers in this pass so garbage for the nonce is OK
        let protected = ACMEProtectedHeader::new_kid(
            kid,
            Url::parse("http://good.url").unwrap(),
            "1234".to_string(),
        );

        // 1000 iterations of this crap because we were seeing some stuff
        // in parallel becausa I hate waiting
        let mut handles = Vec::new();

        for _ in 0..10 {
            let payload = payload.clone();
            let protected = protected.clone();
            let handle = tokio::spawn(async move {
                for _ in 0..100 {
                    let mut jws = JWS::new(&protected, &payload);
                    let eckey = EcKey::generate(super::EC_GROUP.as_ref()).unwrap();

                    let signed = jws.sign(super::ACMEPrivateKey::ECDSA(eckey.clone()));
                    assert_that!(signed).is_ok();

                    let mut jws = signed.unwrap();
                    let acmekey: &super::ACMEKey = &eckey.public_key().try_into().unwrap();
                    let res = jws.verify(acmekey.clone());
                    assert_that!(res).is_ok();
                    assert_that!(res.unwrap()).is_true();

                    let rsa = Rsa::generate(4096).unwrap();
                    let pubkey = Rsa::from_public_components(
                        rsa.n().to_owned().unwrap(),
                        rsa.e().to_owned().unwrap(),
                    )
                    .unwrap();

                    let signed = jws.sign(super::ACMEPrivateKey::RSA(rsa.clone()));
                    assert_that!(signed).is_ok();

                    let jws = signed.unwrap();
                    let res = jws.verify(pubkey.try_into().unwrap());
                    assert_that!(res).is_ok();
                    assert_that!(res.unwrap()).is_true();
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[test]
    fn jwk_into() {
        use openssl::ec::EcKey;
        use openssl::rsa::Rsa;
        use spectral::prelude::*;
        use std::convert::TryInto;

        let eckey = EcKey::generate(&super::EC_GROUP).unwrap();
        let jwk: Result<super::ACMEKey, super::JWSError> = eckey.public_key().try_into();
        assert_that!(jwk).is_ok();

        let eckey2 = match jwk.unwrap() {
            super::ACMEKey::ECDSA(key) => Some(key),
            _ => None,
        };

        assert_that!(eckey2).is_some();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();

        let res = eckey
            .public_key()
            .eq(&super::EC_GROUP, eckey2.unwrap().public_key(), &mut ctx);
        assert_that!(res).is_ok();
        assert_that!(res.unwrap()).is_true();

        let rsa = Rsa::generate(4096).unwrap();
        let pubkey =
            Rsa::from_public_components(rsa.n().to_owned().unwrap(), rsa.e().to_owned().unwrap())
                .unwrap();

        let jwk: Result<super::ACMEKey, super::JWSError> = pubkey.clone().try_into();

        assert_that!(jwk).is_ok();

        let rsa2 = match jwk.unwrap() {
            super::ACMEKey::RSA(key) => Some(key),
            _ => None,
        };

        assert_that!(rsa2).is_some();

        assert_that!(pubkey.public_key_to_der().unwrap())
            .is_equal_to(rsa2.unwrap().public_key_to_der().unwrap());
    }
}
