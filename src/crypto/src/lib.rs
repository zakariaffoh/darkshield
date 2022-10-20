pub mod core;
pub mod jose;
pub mod pbkdf;
pub mod providers;
pub mod utils;

use serde::{Deserialize, Serialize};
use utils::HashUtils;

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

pub trait HashProvider {
    fn hash(self, data: &str) -> Vec<u8>;
}

pub struct DefaultHashProvider {
    algorithm: String,
}

impl DefaultHashProvider {
    pub fn new(algorithm: &str) -> Self {
        Self {
            algorithm: algorithm.to_owned(),
        }
    }
}

impl HashProvider for DefaultHashProvider {
    fn hash(self, data: &str) -> Vec<u8> {
        HashUtils::hash(&self.algorithm, &data.as_bytes())
    }
}
