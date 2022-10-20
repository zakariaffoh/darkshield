use data_encoding::HEXUPPER;
use ring::pbkdf2;
use std::num::NonZeroU32;
use std::str;

#[derive(PartialEq, Eq)]
pub enum PBKDF2AlgorithmEnum {
    Pbkdf2HmacSha1,
    Pbkdf2HmacSha256,
    Pbkdf2HmacSha384,
    Pbkdf2HmacSha512,
}

impl ToString for PBKDF2AlgorithmEnum {
    fn to_string(&self) -> String {
        match self {
            PBKDF2AlgorithmEnum::Pbkdf2HmacSha1 => "pbkdf24".to_owned(),
            PBKDF2AlgorithmEnum::Pbkdf2HmacSha256 => "pbkdf2-sha256".to_owned(),
            PBKDF2AlgorithmEnum::Pbkdf2HmacSha384 => "pbkdf2-sha384".to_owned(),
            PBKDF2AlgorithmEnum::Pbkdf2HmacSha512 => "pbkdf2-sha512".to_owned(),
        }
    }
}

pub struct PBKDF2HashProvider(PBKDF2AlgorithmEnum);

impl PBKDF2HashProvider {
    pub fn new(algorithm: PBKDF2AlgorithmEnum) -> Self {
        Self(algorithm)
    }

    pub fn derive(
        &self,
        password: &str,
        salt: &str,
        iterations: u32,
        derived_key_size: u32,
    ) -> String {
        let algorithm = self.get_algorithm();
        let encoded_salt = HEXUPPER.decode(&salt.as_bytes()).unwrap();
        let iters = NonZeroU32::new(iterations).unwrap();
        let mut hashed_cred_store = Vec::<u8>::new();
        hashed_cred_store.resize(derived_key_size as usize, 0);
        pbkdf2::derive(
            algorithm,
            iters,
            &encoded_salt,
            password.as_bytes(),
            &mut hashed_cred_store,
        );

        return HEXUPPER.encode(&hashed_cred_store);
    }

    pub fn verify(
        self,
        encoded_password: &str,
        raw_password: &str,
        salt: &str,
        iterations: u32,
    ) -> bool {
        let algorithm = self.get_algorithm();
        let encoded_salt = HEXUPPER.decode(&salt.as_bytes()).unwrap();
        let iters = NonZeroU32::new(iterations).unwrap();

        let response = pbkdf2::verify(
            algorithm,
            iters,
            &encoded_salt,
            &raw_password.as_bytes(),
            &HEXUPPER.decode(&encoded_password.as_bytes()).unwrap(),
        );
        if let Ok(_) = response {
            return true;
        }
        return false;
    }

    fn get_algorithm(&self) -> pbkdf2::Algorithm {
        let algo = &self.0;
        if algo == &PBKDF2AlgorithmEnum::Pbkdf2HmacSha1 {
            pbkdf2::PBKDF2_HMAC_SHA1.clone()
        } else if algo == &PBKDF2AlgorithmEnum::Pbkdf2HmacSha256 {
            pbkdf2::PBKDF2_HMAC_SHA256.clone()
        } else if algo == &PBKDF2AlgorithmEnum::Pbkdf2HmacSha384 {
            pbkdf2::PBKDF2_HMAC_SHA384.clone()
        } else {
            pbkdf2::PBKDF2_HMAC_SHA512.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::{self, SecureRandom};

    fn salt_generator() -> String {
        let mut salt = [0u8; 64];
        let rng = rand::SystemRandom::new();
        rng.fill(&mut salt).unwrap();
        HEXUPPER.encode(&salt)
    }

    #[test]
    fn test_pdbdk() {
        let password = "password";
        let iterations = 100_000;
        let salt = "F18E70D777B93C9B6B66D4CA563D9563EC08CAAD48003C06DAB1C37BA92D7EF03EC85B168B8F30481DF9D2EBE01A6935DA329A8510AE2954FEC2A23769A847B9";
        {
            let hasher = PBKDF2HashProvider::new(PBKDF2AlgorithmEnum::Pbkdf2HmacSha1);
            let response = hasher.derive(password, salt, iterations, 32);
            assert_eq!(
                response,
                "63ABF9763FD968DD8A7A07230D2CFF5A1CDAA7C0EAB97134A0E02A2FC45AF7C2"
            );
            assert_eq!(
                hasher.verify(
                    "63ABF9763FD968DD8A7A07230D2CFF5A1CDAA7C0EAB97134A0E02A2FC45AF7C2",
                    password,
                    salt,
                    iterations
                ),
                true
            );
        }
        {
            let hasher = PBKDF2HashProvider::new(PBKDF2AlgorithmEnum::Pbkdf2HmacSha256);
            let response = hasher.derive(password, salt, iterations, 32);
            assert_eq!(
                response,
                "315C5AEF98B9E9117FB2022BABD6A28728F32BECDD56E3ED9F03FBEAE644A82F"
            );
        }
        {
            let hasher = PBKDF2HashProvider::new(PBKDF2AlgorithmEnum::Pbkdf2HmacSha384);
            let response = hasher.derive(password, salt, iterations, 32);
            assert_eq!(
                response,
                "01CEBC9B2B6B20A081BB000759E180D13B2B3886E652D82947170D7E821DDD20"
            );
        }
        {
            let hasher = PBKDF2HashProvider::new(PBKDF2AlgorithmEnum::Pbkdf2HmacSha512);
            let response = hasher.derive(password, salt, iterations, 32);
            assert_eq!(
                response,
                "905814FB4F6C953A86FDCEDCDB2C2AB9D0B57BA52CCC78F4C8847B1A300A6403"
            );
        }
    }
}
