use ring::hmac::{self, Algorithm};

pub struct CryptographyHMAC {
    key: Vec<u8>,
    hmac_algo: Algorithm,
}

impl CryptographyHMAC {
    pub fn new(algorithm: &str, key: &[u8]) -> Result<Self, String> {
        let hmac_algo = match algorithm.to_uppercase().as_str() {
            "HS256" => Some(hmac::HMAC_SHA256),
            "HS384" => Some(hmac::HMAC_SHA384),
            "HS512" => Some(hmac::HMAC_SHA512),
            _ => None,
        };

        match hmac_algo {
            Some(algo) => Ok(Self {
                hmac_algo: algo,
                key: Vec::from(key),
            }),
            _ => Err(format!("Algorithm: {} is not supported", algorithm)),
        }
    }

    pub fn sign(self, data: &[u8]) -> Result<Vec<u8>, String> {
        let hmac_key = hmac::Key::new(self.hmac_algo, &self.key);
        let signature = hmac::sign(&hmac_key, data);
        return Ok(Vec::<u8>::from(signature.as_ref()));
    }

    pub fn verify(self, data: &[u8], signature: &[u8]) -> bool {
        let v_key = hmac::Key::new(self.hmac_algo, &self.key);
        let result = hmac::verify(&v_key, data, signature);
        matches!(result, Ok(_))
    }
}
