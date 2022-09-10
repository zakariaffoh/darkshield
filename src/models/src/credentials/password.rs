use crypto::pbkdf::PBKDF2AlgorithmEnum;

use crate::entities::{
    credentials::{CredentialModel, PasswordCredentialModel},
    realm::PasswordPolicy,
};

pub trait PasswordHashProvider {
    fn encode(self, raw_password: &str, iterations: u32) -> String;

    fn encode_with_salt(self, raw_password: &str, salt: Vec<u32>, iterations: u32) -> String;

    fn verify(self, current_credential: CredentialModel, password: &str) -> bool;

    fn encoded_credential(self, password: &str, iterations: u32) -> PasswordCredentialModel;

    fn policy_check(self, policy: PasswordPolicy, credential: PasswordCredentialModel) -> bool;
}

const DEFAULT_PROVIDER_ID: &str = "pbkdf2-sha256";
const DEFAULT_ALGORITHM: &str = "pbkdf2-sha256";
const DEFAULT_DERIVED_KEY_SIZE: u32 = 64;
const PBKDF2_SALT_SIZE: u32 = 32;
const DEFAULT_ITERATIONS: u32 = 20000;

pub struct Pbkdf2PasswordHashProvider {
    provider_id: String,
    pbkdf2_algorithm: String,
    default_iteration: u32,
    derived_key_size: u32,
}

impl Pbkdf2PasswordHashProvider {
    pub fn new(
        provider_id: &str,
        pbkdf2_algorithm: &str,
        default_iteration: u32,
        derived_key_size: u32,
    ) -> Self {
        Self {
            provider_id: provider_id.to_owned(),
            pbkdf2_algorithm: pbkdf2_algorithm.to_owned(),
            default_iteration: default_iteration,
            derived_key_size: derived_key_size,
        }
    }

    pub fn pbkd2_from_algorithm(pbkdf2_algorithm: &str) -> Self {
        Self {
            provider_id: DEFAULT_PROVIDER_ID.to_owned(),
            pbkdf2_algorithm: pbkdf2_algorithm.to_owned(),
            default_iteration: DEFAULT_ITERATIONS,
            derived_key_size: DEFAULT_DERIVED_KEY_SIZE,
        }
    }

    pub fn pbkd2_hasher() -> Self {
        Self {
            provider_id: DEFAULT_PROVIDER_ID.to_owned(),
            pbkdf2_algorithm: DEFAULT_ALGORITHM.to_owned(),
            default_iteration: DEFAULT_ITERATIONS,
            derived_key_size: DEFAULT_DERIVED_KEY_SIZE,
        }
    }
}

impl PasswordHashProvider for Pbkdf2PasswordHashProvider {
    fn encode(self, raw_password: &str, iterations: u32) -> String {
        todo!()
    }

    fn encode_with_salt(self, raw_password: &str, salt: Vec<u32>, iterations: u32) -> String {
        todo!()
    }

    fn verify(self, current_credential: CredentialModel, password: &str) -> bool {
        todo!()
    }

    fn encoded_credential(self, password: &str, iterations: u32) -> PasswordCredentialModel {
        todo!()
    }

    fn policy_check(self, policy: PasswordPolicy, credential: PasswordCredentialModel) -> bool {
        todo!()
    }
}

pub struct PasswordHashFactory;

impl PasswordHashFactory {
    fn hash_algorithm(algorithm: &str) -> Result<Box<dyn PasswordHashProvider>, String> {
        match algorithm {
            "pbkdf2-sha224" => Ok(Box::new(Pbkdf2PasswordHashProvider::pbkd2_from_algorithm(
                PBKDF2AlgorithmEnum::Pbkdf2HmacSha224.to_string().as_str(),
            ))),
            "pbkdf2-sha256" => Ok(Box::new(Pbkdf2PasswordHashProvider::pbkd2_from_algorithm(
                PBKDF2AlgorithmEnum::Pbkdf2HmacSha256.to_string().as_str(),
            ))),
            "pbkdf2-sha384" => Ok(Box::new(Pbkdf2PasswordHashProvider::pbkd2_from_algorithm(
                PBKDF2AlgorithmEnum::Pbkdf2HmacSha384.to_string().as_str(),
            ))),
            "pbkdf2-sha512" => Ok(Box::new(Pbkdf2PasswordHashProvider::pbkd2_from_algorithm(
                PBKDF2AlgorithmEnum::Pbkdf2HmacSha512.to_string().as_str(),
            ))),
            _ => Err(String::from("unsupported pbkdf2 algorithm")),
        }
    }
}
