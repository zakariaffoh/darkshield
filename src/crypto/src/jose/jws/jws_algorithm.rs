use std::fmt::Debug;

use crate::jose::JoseError;

pub trait JwsAlgorithm: Debug + Send + Sync {
    fn name(&self) -> &str;

    fn box_clone(&self) -> Box<dyn JwsAlgorithm>;
}

impl PartialEq for Box<dyn JwsAlgorithm> {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for Box<dyn JwsAlgorithm> {}

impl Clone for Box<dyn JwsAlgorithm> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait JwsSigner: Debug + Send + Sync {
    fn algorithm(&self) -> &dyn JwsAlgorithm;

    fn kid(&self) -> Option<&str>;

    fn signature_len(&self) -> usize;

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError>;

    fn box_clone(&self) -> Box<dyn JwsSigner>;
}

impl Clone for Box<dyn JwsSigner> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait JwsVerifier: Debug + Send + Sync {
    fn algorithm(&self) -> &dyn JwsAlgorithm;

    fn kid(&self) -> Option<&str>;

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError>;

    fn box_clone(&self) -> Box<dyn JwsVerifier>;
}

impl Clone for Box<dyn JwsVerifier> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
