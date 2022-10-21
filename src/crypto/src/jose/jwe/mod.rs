pub mod enc;
pub mod header;
pub mod jwe;
pub mod zip;

use crate::core::{
    aes::{CipherParams, CryptographyAES, EncryptionCipher, EncryptionCipherFactory},
    keys::Key,
};

pub mod alg;

#[derive(Debug, PartialEq)]
pub enum CekManagementAlgorithmEnum {
    Rsa1_5,
    RsaOaep,
    RsaOaep256,
    Dir,
    A128KW,
    EcdhEs,
    EcdhEsA128kw,
}

impl TryFrom<&str> for CekManagementAlgorithmEnum {
    type Error = String;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_uppercase().as_str() {
            "RSA1_5" => Ok(CekManagementAlgorithmEnum::Rsa1_5),
            "RSA_OAEP" => Ok(CekManagementAlgorithmEnum::RsaOaep),
            "RSA-OAEP" => Ok(CekManagementAlgorithmEnum::RsaOaep),
            "RSA_OAEP_256" => Ok(CekManagementAlgorithmEnum::RsaOaep256),
            "RSA-OAEP-256" => Ok(CekManagementAlgorithmEnum::RsaOaep256),
            "DIR" => Ok(CekManagementAlgorithmEnum::RsaOaep256),
            "A128KW" => Ok(CekManagementAlgorithmEnum::A128KW),
            "ECDH_ES" => Ok(CekManagementAlgorithmEnum::EcdhEs),
            "ECDH-ES" => Ok(CekManagementAlgorithmEnum::EcdhEs),
            "ECDH_ES_A128KW" => Ok(CekManagementAlgorithmEnum::EcdhEsA128kw),
            "ECDH-ES-A128KW" => Ok(CekManagementAlgorithmEnum::EcdhEsA128kw),
            _ => Err(format!("Value: {} is not supported", value)),
        }
    }
}

impl ToString for CekManagementAlgorithmEnum {
    fn to_string(&self) -> String {
        match &self {
            CekManagementAlgorithmEnum::Dir => "DIR".to_owned(),
            CekManagementAlgorithmEnum::Rsa1_5 => "RSA1_5".to_owned(),
            CekManagementAlgorithmEnum::A128KW => "A128KW".to_owned(),
            CekManagementAlgorithmEnum::RsaOaep => "RSA-OAEP".to_owned(),
            CekManagementAlgorithmEnum::RsaOaep256 => "RSA-OAEP-256".to_owned(),
            CekManagementAlgorithmEnum::EcdhEs => "ECDH-ES".to_owned(),
            CekManagementAlgorithmEnum::EcdhEsA128kw => "ECDH-ES+A128KW".to_owned(),
        }
    }
}

/*pub trait JweAlgorithmProvider {
    fn decode_cek(
        &self,
        encoded_cek: &[u8],
        encryption_key: &Box<dyn Key>,
    ) -> Result<Vec<u8>, String>;

    fn encode_cek(
        &self,
        cek_bytes: &[u8],
        encryption_provider: &Box<dyn JweEncryptionProvider>,
        encryption_key: &Box<dyn Key>,
    ) -> Result<Vec<u8>, String>;
}

pub struct DirectAlgorithmProvider;

impl JweAlgorithmProvider for DirectAlgorithmProvider {
    fn decode_cek(
        &self,
        _encoded_cek: &[u8],
        _encryption_key: &Box<dyn Key>,
    ) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }

    fn encode_cek(
        &self,
        _cek_bytes: &[u8],
        _encryption_provider: &Box<dyn JweEncryptionProvider>,
        _encryption_key: &Box<dyn Key>,
    ) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
}

pub struct AesKeyWrapAlgorithmProvider;

impl JweAlgorithmProvider for AesKeyWrapAlgorithmProvider {
    fn decode_cek(
        &self,
        encoded_cek: &[u8],
        encryption_key: &Box<dyn Key>,
    ) -> Result<Vec<u8>, String> {
        let aes_backend_provider = CryptographyAES::new(
            encryption_key.encoded(),
            &CekManagementAlgorithmEnum::A128KW.to_string(),
        );
        match aes_backend_provider {
            Ok(aes_backend) => aes_backend.unwrap_key(encoded_cek),
            Err(err) => Err(err),
        }
    }

    fn encode_cek(
        &self,
        cek_bytes: &[u8],
        _encryption_provider: &Box<dyn JweEncryptionProvider>,
        encryption_key: &Box<dyn Key>,
    ) -> Result<Vec<u8>, String> {
        let aes_backend_provider = CryptographyAES::new(
            encryption_key.encoded(),
            &CekManagementAlgorithmEnum::A128KW.to_string(),
        );
        match aes_backend_provider {
            Ok(aes_backend) => aes_backend.wrap_key(cek_bytes),
            Err(err) => Err(err),
        }
    }
}

trait KeyEncryptionJweAlgorithmProvider {
    fn decode_cek_internal(
        &self,
        encoded_cek: &[u8],
        encryption_key: &Box<dyn Key>,
    ) -> Result<Vec<u8>, String> {
        let cipher = self.cipher_provider();
        cipher.init(CipherParams::new(
            false,
            Some(Vec::from(encryption_key.encoded())),
            None,
        ));
        cipher.do_final(encoded_cek)
    }

    fn encode_cek_internal(
        &self,
        cek_bytes: &[u8],
        _encryption_provider: &Box<dyn JweEncryptionProvider>,
        encryption_key: &Box<dyn Key>,
    ) -> Result<Vec<u8>, String> {
        let cipher = self.cipher_provider();
        cipher.init(CipherParams::new(
            true,
            Some(Vec::from(encryption_key.encoded())),
            None,
        ));
        cipher.do_final(cek_bytes)
    }

    fn cipher_provider(&self) -> Box<dyn EncryptionCipher>;
}

pub struct RsaKeyEncryptionJweAlgorithmProvider {
    algorithm: String,
}

impl RsaKeyEncryptionJweAlgorithmProvider {
    pub fn new(algorithm: &str) -> Self {
        Self {
            algorithm: algorithm.to_owned(),
        }
    }
}

impl KeyEncryptionJweAlgorithmProvider for RsaKeyEncryptionJweAlgorithmProvider {
    fn cipher_provider(&self) -> Box<dyn EncryptionCipher> {
        EncryptionCipherFactory::create(&self.algorithm)
    }
}

impl JweAlgorithmProvider for RsaKeyEncryptionJweAlgorithmProvider {
    fn decode_cek(
        &self,
        encoded_cek: &[u8],
        encryption_key: &Box<dyn Key>,
    ) -> Result<Vec<u8>, String> {
        self.decode_cek_internal(encoded_cek, encryption_key)
    }

    fn encode_cek(
        &self,
        cek_bytes: &[u8],
        encryption_provider: &Box<dyn JweEncryptionProvider>,
        encryption_key: &Box<dyn Key>,
    ) -> Result<Vec<u8>, String> {
        self.encode_cek_internal(cek_bytes, encryption_provider, encryption_key)
    }
}

pub struct ECDKKeyEncryptionJweAlgorithmProvider {
    algorithm: String,
}

impl ECDKKeyEncryptionJweAlgorithmProvider {
    pub fn new(algorithm: &str) -> Self {
        Self {
            algorithm: algorithm.to_owned(),
        }
    }
}

impl KeyEncryptionJweAlgorithmProvider for ECDKKeyEncryptionJweAlgorithmProvider {
    fn cipher_provider(&self) -> Box<dyn EncryptionCipher> {
        EncryptionCipherFactory::create(&self.algorithm)
    }
}

impl JweAlgorithmProvider for ECDKKeyEncryptionJweAlgorithmProvider {
    fn decode_cek(
        &self,
        encoded_cek: &[u8],
        encryption_key: &Box<dyn Key>,
    ) -> Result<Vec<u8>, String> {
        self.decode_cek_internal(encoded_cek, encryption_key)
    }

    fn encode_cek(
        &self,
        cek_bytes: &[u8],
        encryption_provider: &Box<dyn JweEncryptionProvider>,
        encryption_key: &Box<dyn Key>,
    ) -> Result<Vec<u8>, String> {
        self.encode_cek_internal(cek_bytes, encryption_provider, encryption_key)
    }
}*/
