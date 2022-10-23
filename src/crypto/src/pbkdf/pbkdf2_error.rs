use thiserror::Error;

#[derive(Error, Debug)]
pub enum PBKDF2Error {
    #[error("Unsupported algorithm: {0}")]
    UnsupportedPBKDF2HashAlgorithm(#[source] anyhow::Error),
    #[error("Unsupported algorithm: {0}")]
    UnsupportedPBKDF2VerifierAlgorithm(#[source] anyhow::Error),
}
