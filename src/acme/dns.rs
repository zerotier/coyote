use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use std::str::FromStr;
use trust_dns_client::rr::Name;

#[derive(Debug, Clone, PartialEq)]
pub struct DNSName(pub(crate) Name);

impl DNSName {
    pub(crate) fn from_str(name: &str) -> Result<Self, trust_dns_client::error::ParseError> {
        Ok(Self(Name::from_str(&name)?))
    }

    pub(crate) fn to_string(&self) -> String {
        self.0.to_string()
    }
}

pub struct DNSNameVisitor;

impl<'de> Visitor<'de> for DNSNameVisitor {
    type Value = DNSName;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A DNS Name")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match Self::Value::from_str(v) {
            Ok(name) => Ok(name),
            Err(e) => Err(serde::de::Error::custom(e)),
        }
    }
}

impl Serialize for DNSName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string().trim_end_matches("."))
    }
}

impl<'de> Deserialize<'de> for DNSName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(deserializer.deserialize_string(DNSNameVisitor)?)
    }
}

mod tests {
    #[test]
    fn test_dns_serde() {
        use super::DNSName;
        use crate::acme::ACMEIdentifier;
        use spectral::prelude::*;

        let json =
            serde_json::to_string(&ACMEIdentifier::DNS(DNSName::from_str("foo.com").unwrap()));
        assert_that!(json).is_ok();
        let json = json.unwrap();

        let id = serde_json::from_str::<ACMEIdentifier>(&json);
        assert_that!(id).is_ok();
        let id = id.unwrap();
        assert_that!(id.to_string()).is_equal_to("foo.com".to_string());
    }
}
