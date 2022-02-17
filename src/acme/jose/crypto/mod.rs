use lazy_static::lazy_static;
use openssl::{ec::EcGroup, nid::Nid};

const NID_ES256: Nid = Nid::X9_62_PRIME256V1;

lazy_static! {
    pub static ref EC_GROUP: EcGroup = EcGroup::from_curve_name(NID_ES256).unwrap();
}
