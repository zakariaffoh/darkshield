use std::borrow::Cow;
use std::fmt::Debug;

use super::jwe_content_encryption::JweContentEncryption;
use super::jwe_header::JweHeader;
use crate::jose::JoseError;

pub trait JweAlgorithm: Debug + Send + Sync {
    fn name(&self) -> &str;

    fn box_clone(&self) -> Box<dyn JweAlgorithm>;
}

impl PartialEq for Box<dyn JweAlgorithm> {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for Box<dyn JweAlgorithm> {}

impl Clone for Box<dyn JweAlgorithm> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait JweEncrypter: Debug + Send + Sync {
    fn algorithm(&self) -> &dyn JweAlgorithm;

    fn kid(&self) -> Option<&str>;

    fn compute_content_encryption_key(
        &self,
        cencryption: &dyn JweContentEncryption,
        in_header: &JweHeader,
        out_header: &mut JweHeader,
    ) -> Result<Option<Cow<[u8]>>, JoseError>;

    fn encrypt(
        &self,
        key: &[u8],
        in_header: &JweHeader,
        out_header: &mut JweHeader,
    ) -> Result<Option<Vec<u8>>, JoseError>;

    fn box_clone(&self) -> Box<dyn JweEncrypter>;
}

impl Clone for Box<dyn JweEncrypter> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait JweDecrypter: Debug + Send + Sync {
    fn algorithm(&self) -> &dyn JweAlgorithm;

    fn kid(&self) -> Option<&str>;

    fn decrypt(
        &self,
        encrypted_key: Option<&[u8]>,
        cencryption: &dyn JweContentEncryption,
        header: &JweHeader,
    ) -> Result<Cow<[u8]>, JoseError>;

    fn box_clone(&self) -> Box<dyn JweDecrypter>;
}

impl Clone for Box<dyn JweDecrypter> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
