use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use base64_url::base64;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use serde_json::Value;

use crate::core::hash_algorithm::HashAlgorithm;
use crate::jose::error::JoseError;
use crate::jose::jwk::alg::rsa::RsaKeyPair;
use crate::jose::jwk::alg::rsapss::RsaPssKeyPair;
use crate::jose::jwk::der::der_builder::DerBuilder;
use crate::jose::jwk::der::der_type::DerType;
use crate::jose::jwk::jwk::Jwk;
use crate::jose::util;

use super::{JwsAlgorithm, JwsSigner, JwsVerifier};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum RsaSsaPssJwsAlgorithm {
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    PS512,
}

impl RsaSsaPssJwsAlgorithm {
    pub fn generate_key_pair(&self, bits: u32) -> Result<RsaPssKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaPssKeyPair> {
            if bits < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let mut key_pair = RsaPssKeyPair::generate(
                bits,
                self.hash_algorithm(),
                self.hash_algorithm(),
                self.salt_len(),
            )?;
            key_pair.set_algorithm(Some(self.name()));
            Ok(key_pair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    pub fn key_pair_from_der(&self, input: impl AsRef<[u8]>) -> Result<RsaPssKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaPssKeyPair> {
            let mut key_pair = RsaPssKeyPair::from_der(
                input,
                Some(self.hash_algorithm()),
                Some(self.hash_algorithm()),
                Some(self.salt_len()),
            )?;

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

    pub fn key_pair_from_pem(&self, input: impl AsRef<[u8]>) -> Result<RsaPssKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaPssKeyPair> {
            let mut key_pair = RsaPssKeyPair::from_pem(
                input.as_ref(),
                Some(self.hash_algorithm()),
                Some(self.hash_algorithm()),
                Some(self.salt_len()),
            )?;

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

    pub fn signer_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsaSsaPssJwsSigner, JoseError> {
        let key_pair = self.key_pair_from_der(input.as_ref())?;
        Ok(RsaSsaPssJwsSigner {
            algorithm: self.clone(),
            private_key: key_pair.into_private_key(),
            kid: None,
        })
    }

    pub fn signer_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsaSsaPssJwsSigner, JoseError> {
        let key_pair = self.key_pair_from_pem(input.as_ref())?;
        Ok(RsaSsaPssJwsSigner {
            algorithm: self.clone(),
            private_key: key_pair.into_private_key(),
            kid: None,
        })
    }

    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<RsaSsaPssJwsSigner, JoseError> {
        (|| -> anyhow::Result<RsaSsaPssJwsSigner> {
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

            let key_pair = RsaPssKeyPair::from_jwk(
                jwk,
                self.hash_algorithm(),
                self.hash_algorithm(),
                self.salt_len(),
            )?;
            if key_pair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let private_key = key_pair.into_private_key();
            let kid = jwk.kid().map(|val| val.to_string());

            Ok(RsaSsaPssJwsSigner {
                algorithm: self.clone(),
                private_key,
                kid: kid,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn verifier_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsassaPssJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsassaPssJwsVerifier> {
            let input = input.as_ref();
            let spki_der_vec;
            let spki_der = match RsaPssKeyPair::detect_pkcs8(input, true) {
                Some((hash, mgf1_hash, salt_len)) => {
                    if hash != self.hash_algorithm() {
                        bail!("The message digest parameter is mismatched: {}", hash);
                    } else if mgf1_hash != self.hash_algorithm() {
                        bail!(
                            "The mgf1 message digest parameter is mismatched: {}",
                            mgf1_hash
                        );
                    } else if salt_len != self.salt_len() {
                        bail!("The salt size is mismatched: {}", salt_len);
                    }

                    input.as_ref()
                }
                None => {
                    let rsa_der_vec;
                    let rsa_der = match RsaKeyPair::detect_pkcs8(input, true) {
                        Some(_) => {
                            let rsa = Rsa::public_key_from_der(input)?;
                            rsa_der_vec = rsa.public_key_to_der_pkcs1()?;
                            &rsa_der_vec
                        }
                        None => input,
                    };

                    spki_der_vec = RsaPssKeyPair::to_pkcs8(
                        rsa_der,
                        true,
                        self.hash_algorithm(),
                        self.hash_algorithm(),
                        self.salt_len(),
                    );
                    spki_der_vec.as_slice()
                }
            };

            let public_key = PKey::public_key_from_der(spki_der)?;

            let rsa = public_key.rsa()?;
            if rsa.size() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            Ok(RsassaPssJwsVerifier {
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
    ) -> Result<RsassaPssJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsassaPssJwsVerifier> {
            let (alg, data) = util::parse_pem(input.as_ref())?;
            let public_key = match alg.as_str() {
                "PUBLIC KEY" => match RsaPssKeyPair::detect_pkcs8(&data, true) {
                    Some((hash, mgf1_hash, salt_len)) => {
                        if hash != self.hash_algorithm() {
                            bail!("The message digest parameter is mismatched: {}", hash);
                        } else if mgf1_hash != self.hash_algorithm() {
                            bail!(
                                "The mgf1 message digest parameter is mismatched: {}",
                                mgf1_hash
                            );
                        } else if salt_len != self.salt_len() {
                            bail!("The salt size is mismatched: {}", salt_len);
                        }

                        PKey::public_key_from_der(&data)?
                    }
                    None => bail!("Invalid PEM contents."),
                },
                "RSA PUBLIC KEY" => {
                    let pkcs8 = RsaPssKeyPair::to_pkcs8(
                        &data,
                        true,
                        self.hash_algorithm(),
                        self.hash_algorithm(),
                        self.salt_len(),
                    );
                    PKey::public_key_from_der(&pkcs8)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            let rsa = public_key.rsa()?;
            if rsa.size() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            Ok(RsassaPssJwsVerifier {
                algorithm: self.clone(),
                public_key,
                kid: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key that is formatted by a JWK of RSA type.
    ///
    /// # Arguments
    /// * `jwk` - A public key that is formatted by a JWK of RSA type.
    pub fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<RsassaPssJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsassaPssJwsVerifier> {
            match jwk.key_type() {
                val if val == "RSA" => {}
                val => bail!("A parameter kty must be RSA: {}", val),
            };
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            };
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

            let pkcs8 = RsaPssKeyPair::to_pkcs8(
                &builder.build(),
                true,
                self.hash_algorithm(),
                self.hash_algorithm(),
                self.salt_len(),
            );
            let public_key = PKey::public_key_from_der(&pkcs8)?;
            let kid = jwk.kid().map(|val| val.to_string());

            let rsa = public_key.rsa()?;
            if rsa.size() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            Ok(RsassaPssJwsVerifier {
                algorithm: self.clone(),
                public_key,
                kid,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::PS256 => HashAlgorithm::Sha256,
            Self::PS384 => HashAlgorithm::Sha384,
            Self::PS512 => HashAlgorithm::Sha512,
        }
    }

    fn salt_len(&self) -> u8 {
        match self {
            Self::PS256 => 32,
            Self::PS384 => 48,
            Self::PS512 => 64,
        }
    }
}

impl JwsAlgorithm for RsaSsaPssJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
        }
    }

    fn box_clone(&self) -> Box<dyn JwsAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for RsaSsaPssJwsAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for RsaSsaPssJwsAlgorithm {
    type Target = dyn JwsAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct RsaSsaPssJwsSigner {
    algorithm: RsaSsaPssJwsAlgorithm,
    private_key: PKey<Private>,
    kid: Option<String>,
}

impl RsaSsaPssJwsSigner {
    pub fn set_kid(&mut self, value: impl Into<String>) {
        self.kid = Some(value.into());
    }

    pub fn remove_kid(&mut self) {
        self.kid = None;
    }
}

impl JwsSigner for RsaSsaPssJwsSigner {
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

impl Deref for RsaSsaPssJwsSigner {
    type Target = dyn JwsSigner;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct RsassaPssJwsVerifier {
    algorithm: RsaSsaPssJwsAlgorithm,
    public_key: PKey<Public>,
    kid: Option<String>,
}

impl RsassaPssJwsVerifier {
    pub fn set_kid(&mut self, value: impl Into<String>) {
        self.kid = Some(value.into());
    }

    pub fn remove_kid(&mut self) {
        self.kid = None;
    }
}

impl JwsVerifier for RsassaPssJwsVerifier {
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
                bail!("The signature does not match.");
            }
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier> {
        Box::new(self.clone())
    }
}

impl Deref for RsassaPssJwsVerifier {
    type Target = dyn JwsVerifier;

    fn deref(&self) -> &Self::Target {
        self
    }
}
