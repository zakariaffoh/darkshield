pub mod pbkdf2_error;

use anyhow::{self, bail};
use openssl::{memcmp::eq, pkcs5};
use std::fmt::Debug;
use std::fmt::Display;

use self::pbkdf2_error::PBKDF2Error;
use crate::jose::util::hash_algorithm::HashAlgorithm;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum PBKDF2AlgorithmEnum {
    Pbkdf2HmacSha1,
    Pbkdf2HmacSha256,
    Pbkdf2HmacSha384,
    Pbkdf2HmacSha512,
}

impl PBKDF2AlgorithmEnum {
    pub fn name(&self) -> &str {
        match &self {
            Self::Pbkdf2HmacSha1 => "pbkdf2-sha1",
            Self::Pbkdf2HmacSha256 => "pbkdf2-sha256",
            Self::Pbkdf2HmacSha384 => "pbkdf2-sha384",
            Self::Pbkdf2HmacSha512 => "pbkdf2-sha512",
        }
    }

    pub fn pbkdf2_hasher(&self, algorithm: &str) -> Result<Box<dyn PBKDF2Hasher>, PBKDF2Error> {
        (|| -> anyhow::Result<Box<dyn PBKDF2Hasher>> {
            if algorithm.to_lowercase().as_str() != self.name() {
                bail!("{}", algorithm.to_lowercase())
            }
            match algorithm.to_lowercase().as_str() {
                "pbkdf2-sha1" => Ok(Box::new(PBKDF2HasherImp::new(Self::Pbkdf2HmacSha1))),
                "pbkdf2-sha256" => Ok(Box::new(PBKDF2HasherImp::new(Self::Pbkdf2HmacSha1))),
                "pbkdf2-sha384" => Ok(Box::new(PBKDF2HasherImp::new(Self::Pbkdf2HmacSha1))),
                "pbkdf2-sha512" => Ok(Box::new(PBKDF2HasherImp::new(Self::Pbkdf2HmacSha1))),
                _ => bail!("{}", algorithm.to_lowercase()),
            }
        })()
        .map_err(|err| match err.downcast::<PBKDF2Error>() {
            Ok(err) => err,
            Err(err) => PBKDF2Error::UnsupportedPBKDF2HashAlgorithm(err),
        })
    }

    pub fn pbkdf2_verifier(&self, algorithm: &str) -> Result<Box<dyn PBKDF2Verifier>, PBKDF2Error> {
        (|| -> anyhow::Result<Box<dyn PBKDF2Verifier>> {
            if algorithm.to_lowercase().as_str() != self.name() {
                bail!("{}", algorithm.to_lowercase())
            }
            match algorithm.to_lowercase().as_str() {
                "pbkdf2-sha1" => Ok(Box::new(PBKDF2VerifierImp::new(Self::Pbkdf2HmacSha1))),
                "pbkdf2-sha256" => Ok(Box::new(PBKDF2VerifierImp::new(Self::Pbkdf2HmacSha1))),
                "pbkdf2-sha384" => Ok(Box::new(PBKDF2VerifierImp::new(Self::Pbkdf2HmacSha1))),
                "pbkdf2-sha512" => Ok(Box::new(PBKDF2VerifierImp::new(Self::Pbkdf2HmacSha1))),
                _ => bail!("{}", algorithm.to_lowercase()),
            }
        })()
        .map_err(|err| match err.downcast::<PBKDF2Error>() {
            Ok(err) => err,
            Err(err) => PBKDF2Error::UnsupportedPBKDF2VerifierAlgorithm(err),
        })
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::Pbkdf2HmacSha1 => HashAlgorithm::Sha1,
            Self::Pbkdf2HmacSha256 => HashAlgorithm::Sha256,
            Self::Pbkdf2HmacSha384 => HashAlgorithm::Sha384,
            Self::Pbkdf2HmacSha512 => HashAlgorithm::Sha512,
        }
    }

    pub fn derived_key_len(&self) -> usize {
        match self {
            Self::Pbkdf2HmacSha1 => 64,
            Self::Pbkdf2HmacSha256 => 64,
            Self::Pbkdf2HmacSha384 => 64,
            Self::Pbkdf2HmacSha512 => 64,
        }
    }
}

impl Display for PBKDF2AlgorithmEnum {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

pub trait PBKDF2Hasher: Debug + Send + Sync {
    fn algorithm(&self) -> &PBKDF2AlgorithmEnum;

    fn derive(&self, password: &[u8], salt: &[u8], iterations: u32)
        -> Result<Vec<u8>, PBKDF2Error>;
}

#[derive(Debug)]
pub struct PBKDF2HasherImp {
    algorithm: PBKDF2AlgorithmEnum,
}

impl PBKDF2HasherImp {
    pub fn new(algorithm: PBKDF2AlgorithmEnum) -> Self {
        Self {
            algorithm: algorithm,
        }
    }
}

impl PBKDF2Hasher for PBKDF2HasherImp {
    fn algorithm(&self) -> &PBKDF2AlgorithmEnum {
        &self.algorithm
    }

    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<Vec<u8>, PBKDF2Error> {
        (|| -> anyhow::Result<Vec<u8>> {
            let md = self.algorithm.hash_algorithm().message_digest();
            let mut derived_key = vec![0; self.algorithm.derived_key_len()];
            let p2c = iterations as usize;
            pkcs5::pbkdf2_hmac(&password, &salt, p2c, md, &mut derived_key)?;
            Ok(derived_key)
        })()
        .map_err(|err| match err.downcast::<PBKDF2Error>() {
            Ok(err) => err,
            Err(err) => PBKDF2Error::UnsupportedPBKDF2HashAlgorithm(err),
        })
    }
}

pub trait PBKDF2Verifier: Debug + Send + Sync {
    fn algorithm(&self) -> &PBKDF2AlgorithmEnum;

    fn verify(
        &self,
        encoded_password: &[u8],
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<bool, PBKDF2Error>;
}

#[derive(Debug)]
pub struct PBKDF2VerifierImp {
    algorithm: PBKDF2AlgorithmEnum,
}

impl PBKDF2VerifierImp {
    pub fn new(algorithm: PBKDF2AlgorithmEnum) -> Self {
        Self {
            algorithm: algorithm,
        }
    }
}

impl PBKDF2Verifier for PBKDF2VerifierImp {
    fn algorithm(&self) -> &PBKDF2AlgorithmEnum {
        &self.algorithm
    }

    fn verify(
        &self,
        encoded_password: &[u8],
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<bool, PBKDF2Error> {
        (|| -> anyhow::Result<bool> {
            let md = self.algorithm.hash_algorithm().message_digest();
            let mut derived_key = vec![0; self.algorithm.derived_key_len()];
            let p2c = iterations as usize;
            pkcs5::pbkdf2_hmac(&password, &salt, p2c, md, &mut derived_key)?;
            Ok(eq(&derived_key, &encoded_password))
        })()
        .map_err(|err| match err.downcast::<PBKDF2Error>() {
            Ok(err) => err,
            Err(err) => PBKDF2Error::UnsupportedPBKDF2VerifierAlgorithm(err),
        })
    }
}
