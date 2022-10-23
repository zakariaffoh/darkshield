use super::keys::{PrivateKey, PublicKey};

pub struct RSASignature;

impl RSASignature {
    pub fn new(algorithm: &str) -> Self {
        Self
    }

    pub fn private_key(&mut self, private_key: &Box<dyn PrivateKey>) {
        todo!()
    }

    pub fn public_key(&mut self, public_key: &Box<dyn PublicKey>) {
        todo!()
    }

    pub fn update(&mut self, data: &[u8]) {
        todo!()
    }

    pub fn sign(&self) -> Result<Vec<u8>, String> {
        todo!()
    }

    pub fn verify(&self, signature: &[u8]) -> Result<bool, String> {
        todo!()
    }
}

impl RSASignature {
    pub fn hash_algorithm(algorithm: &str) -> String {
        todo!()
    }
}
