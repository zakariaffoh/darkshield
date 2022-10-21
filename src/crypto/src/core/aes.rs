use super::algorithms::*;

#[allow(dead_code)]
pub struct CipherParams {
    encryption_mode: bool,
    secret_key: Option<Vec<u8>>,
    iv: Option<Vec<u8>>,
}

impl CipherParams {
    pub fn new(encryption_mode: bool, secret_key: Option<Vec<u8>>, iv: Option<Vec<u8>>) -> Self {
        Self {
            encryption_mode: encryption_mode,
            secret_key: secret_key,
            iv: iv,
        }
    }
}

pub trait EncryptionCipher {
    fn init(&self, params: CipherParams);

    fn do_final(&self, data: &[u8]) -> Result<Vec<u8>, String>;
}

pub struct EncryptionCipherFactory;

#[allow(dead_code)]
impl EncryptionCipherFactory {
    pub fn create(_algorithm: &str) -> Box<dyn EncryptionCipher> {
        todo!()
    }
}

#[allow(dead_code)]
pub struct CryptographyAES {
    algorithm: AlgorithmsEnum,
    mode: AesMode,
    encryption_key: Vec<u8>,
}

#[allow(dead_code)]
const AES_KEY_128: [&'static AlgorithmsEnum; 4] = [
    &AlgorithmsEnum::A128GCM,
    &AlgorithmsEnum::A128GCMKW,
    &AlgorithmsEnum::A128KW,
    &AlgorithmsEnum::A128CBC,
];

#[allow(dead_code)]
const AES_KEY_192: [&'static AlgorithmsEnum; 4] = [
    &AlgorithmsEnum::A192GCM,
    &AlgorithmsEnum::A192GCMKW,
    &AlgorithmsEnum::A192KW,
    &AlgorithmsEnum::A192CBC,
];

#[allow(dead_code)]
const AES_KEY_256: [&'static AlgorithmsEnum; 5] = [
    &AlgorithmsEnum::A256GCM,
    &AlgorithmsEnum::A256GCMKW,
    &AlgorithmsEnum::A256KW,
    &AlgorithmsEnum::A128CBC_HS256,
    &AlgorithmsEnum::A256CBC,
];

#[allow(dead_code)]
const AES_KEY_384: [&'static AlgorithmsEnum; 1] = [&AlgorithmsEnum::A192CBC_HS384];

#[allow(dead_code)]
const AES_KEY_512: [&'static AlgorithmsEnum; 1] = [&AlgorithmsEnum::A256CBC_HS512];

#[allow(dead_code)]
const AES_KW_ALGS: [&'static AlgorithmsEnum; 3] = [
    &AlgorithmsEnum::A128KW,
    &AlgorithmsEnum::A192KW,
    &AlgorithmsEnum::A256KW,
];

#[allow(non_camel_case_types, dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AesMode {
    GCM,
    CBC,
    NONE,
}

#[allow(dead_code)]
impl CryptographyAES {
    pub fn new(encryption_key: &[u8], alg: &str) -> Result<Self, String> {
        let resolved_algorithm = AlgorithmsEnum::try_from(alg);
        if let Err(err) = resolved_algorithm {
            return Err(err);
        }
        let algorithm = resolved_algorithm.unwrap();
        if !AES.contains(&&algorithm) {
            return Err(format!(
                "{} is not a valid AES algorithm",
                algorithm.to_string()
            ));
        }

        if AES_KEY_128.contains(&&algorithm) && encryption_key.len() != 16 {
            return Err(format!(
                "Key must be 128 bit for algorithm {}",
                algorithm.to_string()
            ));
        }

        if AES_KEY_192.contains(&&algorithm) && encryption_key.len() != 24 {
            return Err(format!(
                "Key must be 192 bit for algorithm {}",
                algorithm.to_string()
            ));
        }

        if AES_KEY_256.contains(&&algorithm) && encryption_key.len() != 24 {
            return Err(format!(
                "Key must be 256 bit for algorithm {}",
                algorithm.to_string()
            ));
        }

        if AES_KEY_384.contains(&&algorithm) && encryption_key.len() != 24 {
            return Err(format!(
                "Key must be 384 bit for algorithm {}",
                algorithm.to_string()
            ));
        }

        if AES_KEY_512.contains(&&algorithm) && encryption_key.len() != 24 {
            return Err(format!(
                "Key must be 512 bit for algorithm {}",
                algorithm.to_string()
            ));
        }

        Ok(Self {
            algorithm: algorithm,
            mode: CryptographyAES::aes_mode(&algorithm),
            encryption_key: Vec::<u8>::from(encryption_key),
        })
    }

    pub fn encrypt(
        &self,
        data: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        if let Some(_) = aad {
            return Err("invalid add".to_owned());
        }
        let iv = self.get_random_bytes();
        let mode = 1;
        if self.mode == AesMode::GCM {
        } else {
        }
        todo!()
    }

    pub fn decrypt(
        &self,
        _data: &[u8],
        _aad: Option<&[u8]>,
        _tag: Option<&[u8]>,
        _iv: Option<&[u8]>,
    ) -> Result<String, String> {
        todo!()
    }

    pub fn wrap_key(self, key_data: &[u8]) -> Result<Vec<u8>, String> {
        todo!()
    }

    pub fn unwrap_key(self, key_data: &[u8]) -> Result<Vec<u8>, String> {
        todo!()
    }

    fn aes_mode(algorithm: &AlgorithmsEnum) -> AesMode {
        match &algorithm {
            AlgorithmsEnum::A128GCM => AesMode::GCM,
            AlgorithmsEnum::A192GCM => AesMode::GCM,
            AlgorithmsEnum::A256GCM => AesMode::GCM,
            AlgorithmsEnum::A128CBC_HS256 => AesMode::CBC,
            AlgorithmsEnum::A192CBC_HS384 => AesMode::CBC,
            AlgorithmsEnum::A256CBC_HS512 => AesMode::CBC,
            AlgorithmsEnum::A128CBC => AesMode::CBC,
            AlgorithmsEnum::A192CBC => AesMode::CBC,
            AlgorithmsEnum::A256CBC => AesMode::CBC,
            AlgorithmsEnum::A128GCMKW => AesMode::GCM,
            AlgorithmsEnum::A192GCMKW => AesMode::GCM,
            AlgorithmsEnum::A256GCMKW => AesMode::GCM,
            AlgorithmsEnum::A128KW => AesMode::NONE,
            AlgorithmsEnum::A192KW => AesMode::NONE,
            AlgorithmsEnum::A256KW => AesMode::NONE,
            _ => AesMode::NONE,
        }
    }

    fn get_random_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}
