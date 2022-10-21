use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use base64_url::base64;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use serde_json::Value;

use crate::core::hash_algorithm::HashAlgorithm;
use crate::jose::error::JoseError;
use crate::jose::jwk::jwk::Jwk;

use super::{JwsAlgorithm, JwsSigner, JwsVerifier};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum HmacJwsAlgorithm {
    HS256,
    HS384,
    HS512,
}

impl HmacJwsAlgorithm {
    pub fn to_jwk(&self, secret: &[u8]) -> Jwk {
        let k = base64::encode_config(secret, base64::URL_SAFE_NO_PAD);

        let mut jwk = Jwk::new("oct");
        jwk.set_key_use("sig");
        jwk.set_key_operations(vec!["sign", "verify"]);
        jwk.set_algorithm(self.name());
        jwk.set_parameter("k", Some(Value::String(k))).unwrap();

        jwk
    }

    pub fn signer_from_bytes(&self, input: impl AsRef<[u8]>) -> Result<HmacJwsSigner, JoseError> {
        (|| -> anyhow::Result<HmacJwsSigner> {
            let input = input.as_ref();

            let min_key_len = self.hash_algorithm().output_len();
            if input.len() < min_key_len {
                bail!(
                    "Secret key size must be larger than or equal to {}: {}",
                    min_key_len,
                    input.len()
                );
            }

            let private_key = PKey::hmac(input)?;

            Ok(HmacJwsSigner {
                algorithm: self.clone(),
                private_key,
                kid: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<HmacJwsSigner, JoseError> {
        (|| -> anyhow::Result<HmacJwsSigner> {
            match jwk.key_type() {
                val if val == "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            }
            if !jwk.is_for_key_operation("sign") {
                bail!("A parameter key_ops must contains sign.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            let min_key_len = self.hash_algorithm().output_len();
            if k.len() < min_key_len {
                bail!(
                    "Secret key size must be larger than or equal to {}: {}",
                    min_key_len,
                    k.len()
                );
            }

            let private_key = PKey::hmac(&k)?;
            let kid = jwk.kid().map(|val| val.to_string());

            Ok(HmacJwsSigner {
                algorithm: self.clone(),
                private_key,
                kid,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn verifier_from_bytes(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<HmacJwsVerifier, JoseError> {
        (|| -> anyhow::Result<HmacJwsVerifier> {
            let input = input.as_ref();

            let min_key_len = self.hash_algorithm().output_len();
            if input.len() < min_key_len {
                bail!(
                    "Secret key size must be larger than or equal to {}: {}",
                    min_key_len,
                    input.len()
                );
            }

            let private_key = PKey::hmac(input)?;

            Ok(HmacJwsVerifier {
                algorithm: self.clone(),
                private_key,
                kid: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<HmacJwsVerifier, JoseError> {
        (|| -> anyhow::Result<HmacJwsVerifier> {
            match jwk.key_type() {
                val if val == "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            }
            if !jwk.is_for_key_operation("verify") {
                bail!("A parameter key_ops must contains verify.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }

            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            let min_key_len = self.hash_algorithm().output_len();
            if k.len() < min_key_len {
                bail!(
                    "Secret key size must be larger than or equal to {}: {}",
                    min_key_len,
                    k.len()
                );
            }

            let private_key = PKey::hmac(&k)?;
            let kid = jwk.kid().map(|val| val.to_string());

            Ok(HmacJwsVerifier {
                algorithm: self.clone(),
                private_key,
                kid: kid,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::HS256 => HashAlgorithm::Sha256,
            Self::HS384 => HashAlgorithm::Sha384,
            Self::HS512 => HashAlgorithm::Sha512,
        }
    }
}

impl JwsAlgorithm for HmacJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",
        }
    }

    fn box_clone(&self) -> Box<dyn JwsAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for HmacJwsAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for HmacJwsAlgorithm {
    type Target = dyn JwsAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct HmacJwsSigner {
    algorithm: HmacJwsAlgorithm,
    private_key: PKey<Private>,
    kid: Option<String>,
}

impl HmacJwsSigner {
    pub fn set_kid(&mut self, value: impl Into<String>) {
        self.kid = Some(value.into());
    }

    pub fn remove_kid(&mut self) {
        self.kid = None;
    }
}

impl JwsSigner for HmacJwsSigner {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn signature_len(&self) -> usize {
        self.algorithm.hash_algorithm().output_len()
    }

    fn kid(&self) -> Option<&str> {
        match &self.kid {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let md = self.algorithm.hash_algorithm().message_digest();

            let mut signer = Signer::new(md, &self.private_key)?;
            signer.update(message)?;
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsSigner> {
        Box::new(self.clone())
    }
}

impl Deref for HmacJwsSigner {
    type Target = dyn JwsSigner;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct HmacJwsVerifier {
    algorithm: HmacJwsAlgorithm,
    private_key: PKey<Private>,
    kid: Option<String>,
}

impl HmacJwsVerifier {
    pub fn set_kid(&mut self, value: impl Into<String>) {
        self.kid = Some(value.into());
    }

    pub fn remove_kid(&mut self) {
        self.kid = None;
    }
}

impl JwsVerifier for HmacJwsVerifier {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn kid(&self) -> Option<&str> {
        match &self.kid {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let md = self.algorithm.hash_algorithm().message_digest();

            let mut signer = Signer::new(md, &self.private_key)?;
            signer.update(message)?;
            let new_signature = signer.sign_to_vec()?;
            if new_signature.as_slice() != signature {
                bail!("Failed to verify.");
            }
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier> {
        Box::new(self.clone())
    }
}

impl Deref for HmacJwsVerifier {
    type Target = dyn JwsVerifier;

    fn deref(&self) -> &Self::Target {
        self
    }
}
