use anyhow::bail;
use base64_url::base64;
use openssl::aes::{self, AesKey};
use serde_json::Value;
use std::borrow::Cow;
use std::fmt::Display;
use std::ops::Deref;

use crate::jose::{
    error::JoseError,
    jwe::{
        header::JweHeader,
        jwe::{JweAlgorithm, JweContentEncryption, JweDecrypter, JweEncrypter},
    },
    jwk::jwk::Jwk,
};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AeskwJweAlgorithm {
    /// AES Key Wrap with default initial value using 128-bit key
    A128kw,
    /// AES Key Wrap with default initial value using 192-bit key
    A192kw,
    /// AES Key Wrap with default initial value using 256-bit key
    A256kw,
}

impl AeskwJweAlgorithm {
    pub fn encrypter_from_bytes(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<AeskwJweEncrypter, JoseError> {
        (|| -> anyhow::Result<AeskwJweEncrypter> {
            let private_key = input.as_ref().to_vec();

            if private_key.len() != self.key_len() {
                bail!(
                    "The key size must be {}: {}",
                    self.key_len(),
                    private_key.len()
                );
            }

            Ok(AeskwJweEncrypter {
                algorithm: self.clone(),
                private_key,
                kid: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<AeskwJweEncrypter, JoseError> {
        (|| -> anyhow::Result<AeskwJweEncrypter> {
            match jwk.key_type() {
                val if val == "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            if !jwk.is_for_key_operation("wrapKey") {
                bail!("A parameter key_ops must contains wrapKey.");
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

            if k.len() != self.key_len() {
                bail!("The key size must be {}: {}", self.key_len(), k.len());
            }

            let kid = jwk.kid().map(|val| val.to_string());

            Ok(AeskwJweEncrypter {
                algorithm: self.clone(),
                private_key: k,
                kid,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_bytes(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<AeskwJweDecrypter, JoseError> {
        (|| -> anyhow::Result<AeskwJweDecrypter> {
            let private_key = input.as_ref().to_vec();

            if private_key.len() != self.key_len() {
                bail!(
                    "The key size must be {}: {}",
                    self.key_len(),
                    private_key.len()
                );
            }

            Ok(AeskwJweDecrypter {
                algorithm: self.clone(),
                private_key,
                kid: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<AeskwJweDecrypter, JoseError> {
        (|| -> anyhow::Result<AeskwJweDecrypter> {
            match jwk.key_type() {
                val if val == "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            if !jwk.is_for_key_operation("unwrapKey") {
                bail!("A parameter key_ops must contains unwrapKey.");
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

            if k.len() != self.key_len() {
                bail!("The key size must be {}: {}", self.key_len(), k.len());
            }

            let kid = jwk.kid().map(|val| val.to_string());

            Ok(AeskwJweDecrypter {
                algorithm: self.clone(),
                private_key: k,
                kid,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn key_len(&self) -> usize {
        match self {
            Self::A128kw => 16,
            Self::A192kw => 24,
            Self::A256kw => 32,
        }
    }
}

impl JweAlgorithm for AeskwJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::A128kw => "A128KW",
            Self::A192kw => "A192KW",
            Self::A256kw => "A256KW",
        }
    }

    fn box_clone(&self) -> Box<dyn JweAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for AeskwJweAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for AeskwJweAlgorithm {
    type Target = dyn JweAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct AeskwJweEncrypter {
    algorithm: AeskwJweAlgorithm,
    private_key: Vec<u8>,
    kid: Option<String>,
}

impl AeskwJweEncrypter {
    pub fn set_kid(&mut self, value: impl Into<String>) {
        self.kid = Some(value.into());
    }

    pub fn remove_kid(&mut self) {
        self.kid = None;
    }
}

impl JweEncrypter for AeskwJweEncrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn kid(&self) -> Option<&str> {
        match &self.kid {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn compute_content_encryption_key(
        &self,
        _cencryption: &dyn JweContentEncryption,
        _in_header: &JweHeader,
        _out_header: &mut JweHeader,
    ) -> Result<Option<Cow<[u8]>>, JoseError> {
        Ok(None)
    }

    fn encrypt(
        &self,
        key: &[u8],
        _in_header: &JweHeader,
        _out_header: &mut JweHeader,
    ) -> Result<Option<Vec<u8>>, JoseError> {
        (|| -> anyhow::Result<Option<Vec<u8>>> {
            let aes = match AesKey::new_encrypt(&self.private_key) {
                Ok(val) => val,
                Err(_) => bail!("Failed to set encrypt key."),
            };

            let mut encrypted_key = vec![0; key.len() + 8];
            match aes::wrap_key(&aes, None, &mut encrypted_key, &key) {
                Ok(val) => {
                    if val < encrypted_key.len() {
                        encrypted_key.truncate(val);
                    }
                }
                Err(_) => bail!("Failed to wrap key."),
            }

            Ok(Some(encrypted_key))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

impl Deref for AeskwJweEncrypter {
    type Target = dyn JweEncrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct AeskwJweDecrypter {
    algorithm: AeskwJweAlgorithm,
    private_key: Vec<u8>,
    kid: Option<String>,
}

impl AeskwJweDecrypter {
    pub fn set_kid(&mut self, value: impl Into<String>) {
        self.kid = Some(value.into());
    }

    pub fn remove_kid(&mut self) {
        self.kid = None;
    }
}

impl JweDecrypter for AeskwJweDecrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn kid(&self) -> Option<&str> {
        match &self.kid {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn decrypt(
        &self,
        encrypted_key: Option<&[u8]>,
        _cencryption: &dyn JweContentEncryption,
        _header: &JweHeader,
    ) -> Result<Cow<[u8]>, JoseError> {
        (|| -> anyhow::Result<Cow<[u8]>> {
            let encrypted_key = match encrypted_key {
                Some(val) => val,
                None => bail!("A encrypted_key is required."),
            };

            let aes = match AesKey::new_decrypt(&self.private_key) {
                Ok(val) => val,
                Err(_) => bail!("Failed to set decrypt key."),
            };

            let mut key = vec![0; encrypted_key.len() - 8];
            match aes::unwrap_key(&aes, None, &mut key, encrypted_key) {
                Ok(val) => {
                    if val < key.len() {
                        key.truncate(val);
                    }
                }
                Err(_) => bail!("Failed to unwrap key."),
            };

            Ok(Cow::Owned(key))
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}

impl Deref for AeskwJweDecrypter {
    type Target = dyn JweDecrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}
