use std::{collections::HashMap, convert::TryFrom};

use ring::hmac::{self, Algorithm};

#[derive(Debug, PartialEq)]
pub enum SignatureAlgorithmEnum {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    PS256,
    PS384,
    PS512,
}

impl TryFrom<&str> for SignatureAlgorithmEnum {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_uppercase().as_str() {
            "HS256" => Ok(SignatureAlgorithmEnum::HS256),
            "HS384" => Ok(SignatureAlgorithmEnum::HS384),
            "HS512" => Ok(SignatureAlgorithmEnum::HS512),
            "RS256" => Ok(SignatureAlgorithmEnum::RS256),
            "RS384" => Ok(SignatureAlgorithmEnum::RS384),
            "RS512" => Ok(SignatureAlgorithmEnum::RS512),
            "ES256" => Ok(SignatureAlgorithmEnum::ES256),
            "ES384" => Ok(SignatureAlgorithmEnum::ES384),
            "PS256" => Ok(SignatureAlgorithmEnum::PS256),
            "PS384" => Ok(SignatureAlgorithmEnum::PS384),
            "PS512" => Ok(SignatureAlgorithmEnum::PS512),
            _ => Err(format!("Value: {} is not supported", value)),
        }
    }
}

pub trait Key {
    fn encoded(&self) -> &[u8];

    fn algorithm(&self) -> &str;

    fn format(&self) -> &HashMap<String, String>;
}

pub trait PrivateKey: Key {
    fn encoded(&self) -> &[u8];
}

pub trait PublicKey: Key {
    fn encoded(&self) -> &[u8];
}

pub trait SecretKey: Key {
    fn encoded(&self) -> &[u8];
}

pub trait Signature {
    fn public_key(&mut self, public_key: dyn PublicKey);

    fn private_key(&mut self, private_key: dyn PrivateKey);

    fn update(&mut self, data: Vec<u8>);

    fn verify(self, signature: Vec<u8>) -> bool;

    fn sign(&self) -> Vec<u8>;
}

pub struct MacSignature {
    hmac_algo: Algorithm,
    algorithm: String,
}

impl MacSignature {
    pub fn new(algorithm: &str) -> Result<Self, String> {
        let hmac = match algorithm.to_uppercase().as_str() {
            "HMAC_SHA256" => Some(hmac::HMAC_SHA256),
            "HMAC_SHA384" => Some(hmac::HMAC_SHA384),
            "HMAC_SHA512" => Some(hmac::HMAC_SHA512),
            _ => None,
        };
        if let Some(hmac_algo) = hmac {
            Ok(Self {
                hmac_algo: hmac_algo,
                algorithm: algorithm.to_owned(),
            })
        } else {
            Err(format!("Algorithm: {} is not supported", algorithm))
        }
    }

    pub fn sign(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let hmac_key = hmac::Key::new(self.hmac_algo, key);
        let signature = hmac::sign(&hmac_key, data);
        let dd = signature.as_ref();
        return Vec::<u8>::from(dd);
    }

    pub fn verify(&self, key: &[u8], data: &[u8], signature: &[u8]) -> bool {
        let v_key = hmac::Key::new(self.hmac_algo, key);
        let result = hmac::verify(&v_key, data, signature);
        match result {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[allow(dead_code)]
pub struct RsaSignature {
    hash_algorithm: Option<String>,
    padding: Option<String>,
    ec_algorithm: Option<String>,
    public_key: Option<Box<dyn PublicKey>>,
    private_key: Option<Box<dyn PrivateKey>>,
    data: Vec<u8>,
}

impl RsaSignature {
    pub fn new(algorithm: &str) -> Result<Self, String> {
        let rsa_sign_algo = SignatureAlgorithmEnum::try_from(algorithm);
        match rsa_sign_algo {
            Err(err) => Err(err),
            Ok(algo) => Ok(Self {
                hash_algorithm: Default::default(),
                padding: Default::default(),
                ec_algorithm: Default::default(),
                public_key: Default::default(),
                private_key: Default::default(),
                data: Default::default(),
            }),
        }
    }
}
