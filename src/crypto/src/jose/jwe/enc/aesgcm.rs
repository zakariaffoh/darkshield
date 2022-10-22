use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use openssl::symm::{self, Cipher};

use crate::jose::{jwe::jwe_content_encryption::JweContentEncryption, JoseError};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AESGCMJweEncryption {
    A128gcm,
    A192gcm,
    A256gcm,
}

impl AESGCMJweEncryption {
    fn cipher(&self) -> Cipher {
        match self {
            Self::A128gcm => Cipher::aes_128_gcm(),
            Self::A192gcm => Cipher::aes_192_gcm(),
            Self::A256gcm => Cipher::aes_256_gcm(),
        }
    }
}

impl JweContentEncryption for AESGCMJweEncryption {
    fn name(&self) -> &str {
        match self {
            Self::A128gcm => "A128GCM",
            Self::A192gcm => "A192GCM",
            Self::A256gcm => "A256GCM",
        }
    }

    fn key_len(&self) -> usize {
        match self {
            Self::A128gcm => 16,
            Self::A192gcm => 24,
            Self::A256gcm => 32,
        }
    }

    fn iv_len(&self) -> usize {
        12
    }

    fn encrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        message: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), JoseError> {
        (|| -> anyhow::Result<(Vec<u8>, Option<Vec<u8>>)> {
            let expected_len = self.key_len();
            if key.len() != expected_len {
                bail!(
                    "The length of content encryption key must be {}: {}",
                    expected_len,
                    key.len()
                );
            }

            let cipher = self.cipher();
            let mut tag = [0; 16];
            let encrypted_message = symm::encrypt_aead(cipher, key, iv, aad, message, &mut tag)?;
            Ok((encrypted_message, Some(tag.to_vec())))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypted_message: &[u8],
        aad: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let expected_len = self.key_len();
            if key.len() != expected_len {
                bail!(
                    "The length of content encryption key must be {}: {}",
                    expected_len,
                    key.len()
                );
            }

            let tag = match tag {
                Some(val) => val,
                None => bail!("A tag value is required."),
            };

            let cipher = self.cipher();
            let message = symm::decrypt_aead(cipher, key, iv, aad, encrypted_message, tag)?;
            Ok(message)
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweContentEncryption> {
        Box::new(self.clone())
    }
}

impl Display for AESGCMJweEncryption {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for AESGCMJweEncryption {
    type Target = dyn JweContentEncryption;

    fn deref(&self) -> &Self::Target {
        self
    }
}
