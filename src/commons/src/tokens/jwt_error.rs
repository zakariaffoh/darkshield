use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("Invalid JWT format: {0}")]
    InvalidJwtFormat(#[source] anyhow::Error),

    #[error("Invalid resource access: {0}")]
    InvalidResourceAccess(#[source] anyhow::Error),

    #[error("Invalid certificate config: {0}")]
    CertificateConfigError(#[source] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum ActionTokenError {
    #[error("Invalid Action Token format: {0}")]
    InvalidActionTokenFormat(#[source] anyhow::Error),
}
