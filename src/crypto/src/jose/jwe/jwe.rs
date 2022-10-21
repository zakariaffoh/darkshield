use super::header::JweHeader;
use crate::jose::error::JoseError;
use std::borrow::Cow;
use std::cmp::Eq;
use std::fmt::Debug;
use std::io;

pub trait Jwe {}

#[derive(Debug, PartialEq)]
pub enum ContentEncryptionAlgorithmEnum {
    A128GCM,
    A192GCM,
    A256GCM,
    A128cbcHs256,
    A192cbcHs384,
    A256cbcHs512,
}

impl TryFrom<&str> for ContentEncryptionAlgorithmEnum {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_uppercase().as_str() {
            "A128GCM" => Ok(ContentEncryptionAlgorithmEnum::A128GCM),
            "A192GCM" => Ok(ContentEncryptionAlgorithmEnum::A192GCM),
            "A256GCM" => Ok(ContentEncryptionAlgorithmEnum::A192GCM),
            "A192CBC-HS384" => Ok(ContentEncryptionAlgorithmEnum::A192cbcHs384),
            "A192CBC_HS384" => Ok(ContentEncryptionAlgorithmEnum::A192cbcHs384),
            "A256CBC-HS512" => Ok(ContentEncryptionAlgorithmEnum::A256cbcHs512),
            "A256CBC_HS512" => Ok(ContentEncryptionAlgorithmEnum::A256cbcHs512),
            "A128CBC-HS256" => Ok(ContentEncryptionAlgorithmEnum::A128cbcHs256),
            "A128CBC_HS256" => Ok(ContentEncryptionAlgorithmEnum::A128cbcHs256),
            _ => Err(format!("Value: {} is not supported", value)),
        }
    }
}

impl ToString for ContentEncryptionAlgorithmEnum {
    fn to_string(&self) -> String {
        match &self {
            ContentEncryptionAlgorithmEnum::A128GCM => "A128GCM".to_owned(),
            ContentEncryptionAlgorithmEnum::A192GCM => "A192GCM".to_owned(),
            ContentEncryptionAlgorithmEnum::A256GCM => "A256GCM".to_owned(),
            ContentEncryptionAlgorithmEnum::A192cbcHs384 => "A192CBC-HS384".to_owned(),
            ContentEncryptionAlgorithmEnum::A256cbcHs512 => "A256CBC-HS512".to_owned(),
            ContentEncryptionAlgorithmEnum::A128cbcHs256 => "A128CBC-HS256".to_owned(),
        }
    }
}

pub trait JweCompression: Debug + Send + Sync {
    /// Return the "zip" (compression algorithm) header parameter value of JWE.
    fn name(&self) -> &str;

    fn compress(&self, message: &[u8]) -> Result<Vec<u8>, io::Error>;

    fn decompress(&self, message: &[u8]) -> Result<Vec<u8>, io::Error>;

    fn box_clone(&self) -> Box<dyn JweCompression>;
}

impl PartialEq for Box<dyn JweCompression> {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for Box<dyn JweCompression> {}

impl Clone for Box<dyn JweCompression> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

/// Represent a algorithm of JWE enc header claim.
pub trait JweContentEncryption: Debug + Send + Sync {
    /// Return the "enc" (encryption) header parameter value of JWE.
    fn name(&self) -> &str;

    fn key_len(&self) -> usize;

    fn iv_len(&self) -> usize;

    fn encrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        message: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), JoseError>;

    fn decrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypted_message: &[u8],
        aad: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<Vec<u8>, JoseError>;

    fn box_clone(&self) -> Box<dyn JweContentEncryption>;
}

pub trait JweAlgorithm: Debug + Send + Sync {
    fn name(&self) -> &str;

    fn box_clone(&self) -> Box<dyn JweAlgorithm>;
}

impl PartialEq for Box<dyn JweAlgorithm> {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for Box<dyn JweAlgorithm> {}

impl Clone for Box<dyn JweAlgorithm> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait JweEncrypter: Debug + Send + Sync {
    fn algorithm(&self) -> &dyn JweAlgorithm;

    fn kid(&self) -> Option<&str>;

    fn compute_content_encryption_key(
        &self,
        cencryption: &dyn JweContentEncryption,
        in_header: &JweHeader,
        out_header: &mut JweHeader,
    ) -> Result<Option<Cow<[u8]>>, JoseError>;

    fn encrypt(
        &self,
        key: &[u8],
        in_header: &JweHeader,
        out_header: &mut JweHeader,
    ) -> Result<Option<Vec<u8>>, JoseError>;

    fn box_clone(&self) -> Box<dyn JweEncrypter>;
}

impl Clone for Box<dyn JweEncrypter> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait JweDecrypter: Debug + Send + Sync {
    fn algorithm(&self) -> &dyn JweAlgorithm;

    fn kid(&self) -> Option<&str>;

    fn decrypt(
        &self,
        encrypted_key: Option<&[u8]>,
        cencryption: &dyn JweContentEncryption,
        header: &JweHeader,
    ) -> Result<Cow<[u8]>, JoseError>;

    fn box_clone(&self) -> Box<dyn JweDecrypter>;
}

impl Clone for Box<dyn JweDecrypter> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
