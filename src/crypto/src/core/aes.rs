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

impl EncryptionCipherFactory {
    pub fn create(algorithm: &str) -> Box<dyn EncryptionCipher> {
        todo!()
    }
}

pub struct AESBackend {
    algorithm: String,
    encryption_key: Vec<u8>,
}

impl AESBackend {
    pub fn new(encryption_key: &[u8], algorithm: &str) -> Result<Self, String> {
        Ok(Self {
            algorithm: algorithm.to_owned(),
            encryption_key: Vec::<u8>::from(encryption_key),
        })
    }
    pub fn encrypt(data: &[u8], aad: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        todo!()
    }

    pub fn decrypt(
        data: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
        iv: Option<&[u8]>,
    ) -> Result<String, String> {
        todo!()
    }

    pub fn wrap_key(self, key_data: &[u8]) -> Result<Vec<u8>, String> {
        todo!()
    }

    pub fn unwrap_key(self, key_data: &[u8]) -> Result<Vec<u8>, String> {
        todo!()
    }
}
