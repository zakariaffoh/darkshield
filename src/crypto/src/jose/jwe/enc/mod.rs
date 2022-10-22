use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;

use crate::jose::error::JoseError;
use crate::jose::jwe::jwe::JweContentEncryption;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
    symm::{self, Cipher},
};

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

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AESCBCHMACJweEncryption {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
    A128cbcHs256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
    A192cbcHs384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
    A256cbcHs512,
}

impl AESCBCHMACJweEncryption {
    fn cipher(&self) -> Cipher {
        match self {
            Self::A128cbcHs256 => Cipher::aes_128_cbc(),
            Self::A192cbcHs384 => Cipher::aes_192_cbc(),
            Self::A256cbcHs512 => Cipher::aes_256_cbc(),
        }
    }

    fn calculate_tag(
        &self,
        aad: &[u8],
        iv: Option<&[u8]>,
        ciphertext: &[u8],
        mac_key: &[u8],
    ) -> Result<Vec<u8>, JoseError> {
        let (message_digest, tlen) = match self {
            Self::A128cbcHs256 => (MessageDigest::sha256(), 16),
            Self::A192cbcHs384 => (MessageDigest::sha384(), 24),
            Self::A256cbcHs512 => (MessageDigest::sha512(), 32),
        };

        let pkey = (|| -> anyhow::Result<PKey<Private>> {
            let pkey = PKey::hmac(mac_key)?;
            Ok(pkey)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))?;

        let signature = (|| -> anyhow::Result<Vec<u8>> {
            let aad_bits = ((aad.len() * 8) as u64).to_be_bytes();

            let mut signer = Signer::new(message_digest, &pkey)?;
            signer.update(aad)?;
            if let Some(val) = iv {
                signer.update(val)?;
            }
            signer.update(ciphertext)?;
            signer.update(&aad_bits)?;
            let mut signature = signer.sign_to_vec()?;
            signature.truncate(tlen);
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))?;

        Ok(signature)
    }
}

impl JweContentEncryption for AESCBCHMACJweEncryption {
    fn name(&self) -> &str {
        match self {
            Self::A128cbcHs256 => "A128CBC-HS256",
            Self::A192cbcHs384 => "A192CBC-HS384",
            Self::A256cbcHs512 => "A256CBC-HS512",
        }
    }

    fn key_len(&self) -> usize {
        match self {
            Self::A128cbcHs256 => 32,
            Self::A192cbcHs384 => 48,
            Self::A256cbcHs512 => 64,
        }
    }

    fn iv_len(&self) -> usize {
        16
    }

    fn encrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        message: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), JoseError> {
        let (encrypted_message, mac_key) = (|| -> anyhow::Result<(Vec<u8>, &[u8])> {
            let expected_len = self.key_len();
            if key.len() != expected_len {
                bail!(
                    "The length of content encryption key must be {}: {}",
                    expected_len,
                    key.len()
                );
            }

            let mac_key_len = expected_len / 2;
            let mac_key = &key[0..mac_key_len];
            let enc_key = &key[mac_key_len..];

            let cipher = self.cipher();
            let encrypted_message = symm::encrypt(cipher, enc_key, iv, message)?;
            Ok((encrypted_message, mac_key))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))?;

        let tag = self.calculate_tag(aad, iv, &encrypted_message, mac_key)?;

        Ok((encrypted_message, Some(tag)))
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypted_message: &[u8],
        aad: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<Vec<u8>, JoseError> {
        let (message, mac_key) = (|| -> anyhow::Result<(Vec<u8>, &[u8])> {
            let expected_len = self.key_len();
            if key.len() != expected_len {
                bail!(
                    "The length of content encryption key must be {}: {}",
                    expected_len,
                    key.len()
                );
            }

            let mac_key_len = expected_len / 2;
            let mac_key = &key[0..mac_key_len];
            let enc_key = &key[mac_key_len..];

            let cipher = self.cipher();
            let message = symm::decrypt(cipher, enc_key, iv, encrypted_message)?;
            Ok((message, mac_key))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))?;

        (|| -> anyhow::Result<()> {
            let tag = match tag {
                Some(val) => val,
                None => bail!("A tag value is required."),
            };

            let calc_tag = self.calculate_tag(aad, iv, &encrypted_message, mac_key)?;
            if calc_tag.as_slice() != tag {
                bail!("The tag doesn't match.");
            }

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))?;

        Ok(message)
    }

    fn box_clone(&self) -> Box<dyn JweContentEncryption> {
        Box::new(self.clone())
    }
}

impl Display for AESCBCHMACJweEncryption {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for AESCBCHMACJweEncryption {
    type Target = dyn JweContentEncryption;

    fn deref(&self) -> &Self::Target {
        self
    }
}

pub use AESGCMJweEncryption::A128gcm as A128GCM;
pub use AESGCMJweEncryption::A192gcm as A192GCM;
pub use AESGCMJweEncryption::A256gcm as A256GCM;

pub use AESCBCHMACJweEncryption::A128cbcHs256 as A128CBC_HS256;
pub use AESCBCHMACJweEncryption::A192cbcHs384 as A192CBC_HS384;
pub use AESCBCHMACJweEncryption::A256cbcHs512 as A256CBC_HS512;
