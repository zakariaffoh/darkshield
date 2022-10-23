pub mod access_token;
pub mod id_token;
pub mod json_web_token;
pub mod logout_token;
pub mod refresh_token;
pub mod response_token;

use super::{jwt_error::JwtError, token::Token};
use anyhow::{self, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, fmt::Debug, time::SystemTime};

pub trait Jwt: Token + Debug + Send + Sync {
    fn token_id(&self) -> Option<&str>;

    fn issuer(&self) -> Option<&str>;

    fn not_before(&self) -> Option<SystemTime>;

    fn issue_at(&self) -> Option<SystemTime>;

    fn audience(&self) -> Option<Vec<&str>>;

    fn has_audience(&self, audience: &str) -> bool;

    fn has_any_audiences(&self, audiences: &Vec<String>) -> bool;

    fn subject(&self) -> Option<&str>;

    fn expires_at(&self) -> Option<SystemTime>;

    fn token_type(&self) -> Option<&str>;

    fn issued_for(&self) -> Option<&str>;

    fn claims_set(&self) -> &Map<String, Value>;

    fn is_expired(&self) -> bool;

    fn is_not_before(&self, allow_clock_skew: u64) -> bool;

    fn is_active(&self, allow_clock_skew: u64) -> bool;
}

pub trait IdToken: Jwt {
    fn nonce(&self) -> Option<&str>;

    fn auth_time(&self) -> Option<u64>;

    fn session_id(&self) -> Option<&str>;

    fn preferred_username(&self) -> Option<&str>;

    fn access_token_hash(&self) -> Option<&str>;

    fn code_hash(&self) -> Option<&str>;

    fn given_name(&self) -> Option<&str>;

    fn name(&self) -> Option<&str>;

    fn family_name(&self) -> Option<&str>;

    fn middle_name(&self) -> Option<&str>;

    fn nick_name(&self) -> Option<&str>;

    fn profile(&self) -> Option<&str>;

    fn picture(&self) -> Option<&str>;

    fn website(&self) -> Option<&str>;

    fn email(&self) -> Option<&str>;

    fn email_verified(&self) -> Option<bool>;

    fn gender(&self) -> Option<&str>;

    fn birth_date(&self) -> Option<&str>;

    fn zoneinfo(&self) -> Option<&str>;

    fn locale(&self) -> Option<&str>;

    fn phone_number(&self) -> Option<&str>;

    fn phone_number_verified(&self) -> Option<bool>;

    fn updated_at(&self) -> Option<u64>;

    fn claims_locales(&self) -> Option<&str>;

    fn acr(&self) -> Option<&str>;

    fn state_hash(&self) -> Option<&str>;
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    #[serde(alias = "x5t#S256")]
    cert_thumbprint: String,
}

#[allow(dead_code)]
impl CertificateConfig {
    pub fn new(cert_thumbprint: &str) -> Self {
        Self {
            cert_thumbprint: cert_thumbprint.to_owned(),
        }
    }

    pub fn cert_thumbprint(&self) -> &str {
        &self.cert_thumbprint
    }

    pub fn set_cert_thumbprint(&mut self, cert_thumbprint: &str) {
        self.cert_thumbprint = cert_thumbprint.to_owned();
    }

    pub fn from_map(map: &Map<String, Value>) -> Result<Self, JwtError> {
        (|| -> anyhow::Result<Self> {
            match map.get("x5t#S256") {
                Some(cert) => match cert {
                    Value::String(cert_thumbprint_v) => {
                        Ok(CertificateConfig::new(cert_thumbprint_v))
                    }
                    _ => bail!("invalid certificate config"),
                },
                _ => bail!("invalid certificate config"),
            }
        })()
        .map_err(|err| match err.downcast::<JwtError>() {
            Ok(err) => err,
            Err(err) => JwtError::CertificateConfigError(err),
        })
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct AccessTokenAccess {
    #[serde(alias = "roles")]
    roles: Vec<String>,
    #[serde(alias = "verify_caller")]
    verify_caller: Option<bool>,
}

#[allow(dead_code)]
impl AccessTokenAccess {
    pub fn new(roles: Vec<String>, verify_caller: Option<bool>) -> Self {
        Self {
            roles: roles,
            verify_caller: verify_caller,
        }
    }

    pub fn roles(&self) -> &Vec<String> {
        &self.roles
    }

    pub fn set_roles(&mut self, roles: Vec<String>) {
        self.roles = roles;
    }

    pub fn verify_caller(&self) -> Option<bool> {
        self.verify_caller.clone()
    }

    pub fn set_verify_caller(&mut self, verify_caller: Option<bool>) {
        self.verify_caller = verify_caller;
    }

    pub fn from_map(map: &Map<String, Value>) -> Result<Self, JwtError> {
        (|| -> anyhow::Result<Self> {
            let mut roles: Vec<String> = Vec::new();
            match map.get("roles") {
                Some(roles_values) => match roles_values {
                    Value::Array(roles_array) => {
                        for val in roles_array {
                            match val {
                                Value::String(s) => roles.push(s.to_owned()),
                                _ => bail!("role is not a string"),
                            }
                        }
                    }
                    _ => bail!("role is not a string",),
                },
                _ => {}
            };
            let mut verify_caller_v = None;
            match map.get("verify_caller") {
                Some(verify_caller) => match verify_caller {
                    Value::Bool(verify_caller_bool) => {
                        verify_caller_v = Some(verify_caller_bool.clone());
                    }
                    _ => {}
                },
                _ => {}
            };

            Ok(Self {
                roles: roles,
                verify_caller: verify_caller_v,
            })
        })()
        .map_err(|err| match err.downcast::<JwtError>() {
            Ok(err) => err,
            Err(err) => JwtError::InvalidResourceAccess(err),
        })
    }
}

pub trait AccessToken: IdToken {
    fn resources_access(&self) -> Result<BTreeMap<String, AccessTokenAccess>, JwtError>;

    fn get_resource_access(&self, resource: &str) -> Result<Option<AccessTokenAccess>, JwtError>;

    fn allowed_origins(&self) -> Option<Vec<String>>;

    fn realm_access(&self) -> Option<AccessTokenAccess>;

    fn trusted_certificates(&self) -> Option<Vec<String>>;

    fn certificate_config(&self) -> Option<CertificateConfig>;

    fn is_verify_caller(&self, resource: &str) -> Option<bool>;
}

pub trait RefreshToken: AccessToken {}

pub trait LogoutToken: Jwt {
    fn session_id(&self) -> Option<&str>;

    fn events(&self) -> Option<&Map<String, Value>>;
}
