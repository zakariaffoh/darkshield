pub struct AESBackend {
    algorithm: String,
    mode: String,
}

impl AESBackend {
    pub fn encrypt(
        data: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Tuple<Vec<u8>, Vec<u8>, Vec<u8>>, String> {
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
