use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use base64_url::base64;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde_json::Value;

use crate::core::hash_algorithm::HashAlgorithm;
use crate::jose::error::JoseError;
use crate::jose::jwk::alg::rsa::RsaKeyPair;
use crate::jose::jwk::der::der_builder::DerBuilder;
use crate::jose::jwk::der::der_type::DerType;
use crate::jose::jwk::jwk::Jwk;
use crate::jose::util;

use super::{JwsAlgorithm, JwsSigner, JwsVerifier};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum RsaSsaJwsAlgorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,

    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,

    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
}

impl RsaSsaJwsAlgorithm {
    pub fn generate_key_pair(&self, bits: u32) -> Result<RsaKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaKeyPair> {
            if bits < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let mut key_pair = RsaKeyPair::generate(bits)?;
            key_pair.set_algorithm(Some(self.name()));
            Ok(key_pair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    pub fn key_pair_from_der(&self, input: impl AsRef<[u8]>) -> Result<RsaKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaKeyPair> {
            let mut key_pair = RsaKeyPair::from_der(input)?;

            if key_pair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            key_pair.set_algorithm(Some(self.name()));
            Ok(key_pair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    pub fn key_pair_from_pem(&self, input: impl AsRef<[u8]>) -> Result<RsaKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaKeyPair> {
            let mut key_pair = RsaKeyPair::from_pem(input.as_ref())?;

            if key_pair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            key_pair.set_algorithm(Some(self.name()));
            Ok(key_pair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    pub fn signer_from_der(&self, input: impl AsRef<[u8]>) -> Result<RsaSsaJwsSigner, JoseError> {
        let key_pair = self.key_pair_from_der(input.as_ref())?;
        Ok(RsaSsaJwsSigner {
            algorithm: self.clone(),
            private_key: key_pair.into_private_key(),
            kid: None,
        })
    }

    pub fn signer_from_pem(&self, input: impl AsRef<[u8]>) -> Result<RsaSsaJwsSigner, JoseError> {
        let key_pair = self.key_pair_from_pem(input.as_ref())?;
        Ok(RsaSsaJwsSigner {
            algorithm: self.clone(),
            private_key: key_pair.into_private_key(),
            kid: None,
        })
    }

    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<RsaSsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<RsaSsaJwsSigner> {
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

            let key_pair = RsaKeyPair::from_jwk(jwk)?;
            if key_pair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let private_key = key_pair.into_private_key();
            let kid = jwk.kid().map(|val| val.to_string());

            Ok(RsaSsaJwsSigner {
                algorithm: self.clone(),
                private_key,
                kid,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn verifier_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsaSsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsaSsaJwsVerifier> {
            let spki_der_vec;
            let spki_der = match RsaKeyPair::detect_pkcs8(input.as_ref(), true) {
                Some(_) => input.as_ref(),
                None => {
                    spki_der_vec = RsaKeyPair::to_pkcs8(input.as_ref(), true);
                    spki_der_vec.as_slice()
                }
            };

            let public_key = PKey::public_key_from_der(spki_der)?;

            let rsa = public_key.rsa()?;
            if rsa.size() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            Ok(RsaSsaJwsVerifier {
                algorithm: self.clone(),
                public_key,
                kid: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn verifier_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsaSsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsaSsaJwsVerifier> {
            let (alg, data) = util::parse_pem(input.as_ref())?;

            let spki_der_vec;
            let spki_der = match alg.as_str() {
                "PUBLIC KEY" => match RsaKeyPair::detect_pkcs8(&data, true) {
                    Some(_) => &data,
                    None => bail!("Invalid PEM contents."),
                },
                "RSA PUBLIC KEY" => {
                    spki_der_vec = RsaKeyPair::to_pkcs8(&data, true);
                    spki_der_vec.as_slice()
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            let public_key = PKey::public_key_from_der(spki_der)?;

            let rsa = public_key.rsa()?;
            if rsa.size() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            Ok(RsaSsaJwsVerifier {
                algorithm: self.clone(),
                public_key,
                kid: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<RsaSsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsaSsaJwsVerifier> {
            match jwk.key_type() {
                val if val == "RSA" => {}
                val => bail!("A parameter kty must be RSA: {}", val),
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

            let n = match jwk.parameter("n") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter n must be a string."),
                None => bail!("A parameter n is required."),
            };
            let e = match jwk.parameter("e") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter e must be a string."),
                None => bail!("A parameter e is required."),
            };

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_be_slice(&n, false); // n
                builder.append_integer_from_be_slice(&e, false); // e
            }
            builder.end();

            let pkcs8 = RsaKeyPair::to_pkcs8(&builder.build(), true);
            let public_key = PKey::public_key_from_der(&pkcs8)?;
            let kid = jwk.kid().map(|val| val.to_string());

            let rsa = public_key.rsa()?;
            if rsa.size() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            Ok(RsaSsaJwsVerifier {
                algorithm: self.clone(),
                public_key,
                kid,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::RS256 => HashAlgorithm::Sha256,
            Self::RS384 => HashAlgorithm::Sha384,
            Self::RS512 => HashAlgorithm::Sha512,
        }
    }
}

impl JwsAlgorithm for RsaSsaJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
        }
    }

    fn box_clone(&self) -> Box<dyn JwsAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for RsaSsaJwsAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for RsaSsaJwsAlgorithm {
    type Target = dyn JwsAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct RsaSsaJwsSigner {
    algorithm: RsaSsaJwsAlgorithm,
    private_key: PKey<Private>,
    kid: Option<String>,
}

impl RsaSsaJwsSigner {
    pub fn set_kid(&mut self, value: impl Into<String>) {
        self.kid = Some(value.into());
    }

    pub fn remove_kid(&mut self) {
        self.kid = None;
    }
}

impl JwsSigner for RsaSsaJwsSigner {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn signature_len(&self) -> usize {
        256
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

impl Deref for RsaSsaJwsSigner {
    type Target = dyn JwsSigner;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct RsaSsaJwsVerifier {
    algorithm: RsaSsaJwsAlgorithm,
    public_key: PKey<Public>,
    kid: Option<String>,
}

impl RsaSsaJwsVerifier {
    pub fn set_kid(&mut self, value: impl Into<String>) {
        self.kid = Some(value.into());
    }

    pub fn remove_kid(&mut self) {
        self.kid = None;
    }
}

impl JwsVerifier for RsaSsaJwsVerifier {
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

            let mut verifier = Verifier::new(md, &self.public_key)?;
            verifier.update(message)?;
            if !verifier.verify(signature)? {
                bail!("The signature does not match.")
            }
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier> {
        Box::new(self.clone())
    }
}

impl Deref for RsaSsaJwsVerifier {
    type Target = dyn JwsVerifier;

    fn deref(&self) -> &Self::Target {
        self
    }
}
