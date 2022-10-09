pub enum PBKDF2AlgorithmEnum {
    Pbkdf2HmacSha224,
    Pbkdf2HmacSha256,
    Pbkdf2HmacSha384,
    Pbkdf2HmacSha512,
}

impl ToString for PBKDF2AlgorithmEnum {
    fn to_string(&self) -> String {
        match self {
            PBKDF2AlgorithmEnum::Pbkdf2HmacSha224 => "pbkdf2-sha224".to_owned(),
            PBKDF2AlgorithmEnum::Pbkdf2HmacSha256 => "pbkdf2-sha256".to_owned(),
            PBKDF2AlgorithmEnum::Pbkdf2HmacSha384 => "pbkdf2-sha384".to_owned(),
            PBKDF2AlgorithmEnum::Pbkdf2HmacSha512 => "pbkdf2-sha512".to_owned(),
        }
    }
}

pub struct PBKDF2HashProvider(String);

impl PBKDF2HashProvider {
    pub fn new(algorithm: &PBKDF2AlgorithmEnum) -> Result<Self, String> {
        todo!();
    }

    pub fn derive(
        &self,
        password: &str,
        salt: &str,
        iterations: u32,
        derived_key_size: u32,
    ) -> String {
        todo!();
    }

    pub fn verify(
        self,
        encoded_password: &str,
        raw_password: &str,
        salt: &str,
        iterations: u32,
        derived_key_size: u32,
    ) -> bool {
        todo!();
    }
}
