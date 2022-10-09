pub mod jose;
pub mod pbkdf;
pub mod utils;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum KeyTypeEnum {
    EC,
    RSA,
    OTC,
}

impl ToString for KeyTypeEnum {
    fn to_string(&self) -> String {
        match self {
            KeyTypeEnum::EC => "EC".to_owned(),
            KeyTypeEnum::RSA => "RSA".to_owned(),
            KeyTypeEnum::OTC => "OTC".to_owned(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum KeyUseEnum {
    SIG,
    ENC,
}

impl ToString for KeyUseEnum {
    fn to_string(&self) -> String {
        match self {
            KeyUseEnum::SIG => "SIG".to_owned(),
            KeyUseEnum::ENC => "ENC".to_owned(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum KeyStatusEnum {
    ACTIVE,
    DISABLE,
    PASSIVE,
}

impl ToString for KeyStatusEnum {
    fn to_string(&self) -> String {
        match self {
            KeyStatusEnum::ACTIVE => "ACTIVE".to_owned(),
            KeyStatusEnum::DISABLE => "DISABLE".to_owned(),
            KeyStatusEnum::PASSIVE => "PASSIVE".to_owned(),
        }
    }
}
