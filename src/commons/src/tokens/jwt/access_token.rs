use std::{
    collections::BTreeMap,
    fmt::Display,
    time::{Duration, SystemTime},
};

use crate::tokens::{
    jwt_error::JwtError,
    token::{Token, TokenCategoryEnum},
};
use anyhow::bail;
use serde_json::{Map, Number, Value};

use super::{id_token::IdTokenImp, json_web_token::JsonWebToken, AccessToken, IdToken, Jwt};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct AccessTokenImp {
    claims: Map<String, Value>,
}

#[allow(dead_code)]
impl AccessTokenImp {
    pub fn new() -> Self {
        Self { claims: Map::new() }
    }

    pub fn into_map(self) -> Map<String, Value> {
        self.claims
    }

    pub fn from_map(claims_map: impl Into<Map<String, Value>>) -> Result<Self, JwtError> {
        let map: Map<String, Value> = claims_map.into();
        for (key, value) in &map {
            Self::check_claim(key, value)?;
        }
        Ok(Self { claims: map })
    }

    pub fn set_token_id(&mut self, token_id: impl Into<String>) {
        let value: String = token_id.into();
        self.claims.insert("jti".to_string(), Value::String(value));
    }

    pub fn set_issuer(&mut self, issuer: impl Into<String>) {
        let value: String = issuer.into();
        self.claims.insert("iss".to_string(), Value::String(value));
    }

    pub fn set_not_before(&mut self, not_before: &SystemTime) {
        let key = "nbf".to_string();
        let val = Number::from(
            not_before
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        self.claims.insert(key.clone(), Value::Number(val));
    }

    pub fn set_token_type(&mut self, token_type: impl Into<String>) {
        let value: String = token_type.into();
        self.claims.insert("typ".to_string(), Value::String(value));
    }

    pub fn set_expiry_at(&mut self, value: &SystemTime) {
        let key = "exp".to_string();
        let val = Number::from(
            value
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        self.claims.insert(key.clone(), Value::Number(val));
    }

    pub fn set_issued_for(&mut self, token_type: impl Into<String>) {
        let value: String = token_type.into();
        self.claims.insert("azp".to_string(), Value::String(value));
    }

    pub fn issue_now(&mut self) {
        let time_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.claims
            .insert("iat".to_string(), Value::Number(Number::from(time_now)));
    }

    pub fn set_audience(&mut self, audiences: Vec<impl Into<String>>) {
        let key = "aud".to_string();
        if audiences.len() == 1 {
            for val in audiences {
                let val: String = val.into();
                self.claims.insert(key, Value::String(val));
                break;
            }
        } else if audiences.len() > 1 {
            let mut vec1 = Vec::with_capacity(audiences.len());
            let mut vec2 = Vec::with_capacity(audiences.len());
            for val in audiences {
                let val: String = val.into();
                vec1.push(Value::String(val.clone()));
                vec2.push(val);
            }
            self.claims.insert(key.clone(), Value::Array(vec1));
        }
    }

    pub fn add_audience(&mut self, audience: impl Into<String>) {
        let value: String = audience.into();
        match self.claims.get("aud") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len() + 1);
                for val in vals {
                    match val {
                        Value::String(val2) => vec.push(Value::String(val2.clone())),
                        _ => {}
                    }
                }
                vec.push(Value::String(value));
                self.claims.remove("aud");
                self.claims.insert("aud".to_string(), Value::Array(vec));
            }
            Some(Value::String(val)) => {
                let mut vec = Vec::with_capacity(2);
                vec.push(Value::String(val.clone()));
                vec.push(Value::String(value));
                self.claims.remove("aud");
                self.claims.insert("aud".to_string(), Value::Array(vec));
            }
            _ => {
                let mut vec = Vec::with_capacity(1);
                vec.push(Value::String(value));
                self.claims.insert("aud".to_string(), Value::Array(vec));
            }
        }
    }

    pub fn set_subject(&mut self, subject: impl Into<String>) {
        let value: String = subject.into();
        self.claims.insert("sub".to_string(), Value::String(value));
    }

    pub fn set_issue_at(&mut self, issue_at: &SystemTime) {
        let key = "iat".to_string();
        let value = Number::from(
            issue_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        self.claims.insert(key, Value::Number(Number::from(value)));
    }

    pub fn set_claim(&mut self, key: &str, value: Option<Value>) -> Result<(), JwtError> {
        (|| -> anyhow::Result<()> {
            match value {
                Some(val) => {
                    Self::check_claim(key, &val)?;
                    self.claims.insert(key.to_string(), val);
                }
                None => {
                    self.claims.remove(key);
                }
            }
            Ok(())
        })()
        .map_err(|err| JwtError::InvalidJwtFormat(err))
    }

    pub fn claim(&self, key: &str) -> Option<&Value> {
        self.claims.get(key)
    }

    pub fn set_nonce(&mut self, nonce: impl Into<String>) {
        let value: String = nonce.into();
        self.claims
            .insert("nonce".to_string(), Value::String(value));
    }

    pub fn set_auth_time(&mut self, auth_time: impl Into<u64>) {
        let value: u64 = auth_time.into();
        self.claims
            .insert("auth_time".to_string(), Value::Number(Number::from(value)));
    }

    pub fn set_session_id(&mut self, session_id: impl Into<String>) {
        let value: String = session_id.into();
        self.claims.insert("sid".to_string(), Value::String(value));
    }

    pub fn set_preferred_username(&mut self, preferred_username: impl Into<String>) {
        let value: String = preferred_username.into();
        self.claims
            .insert("preferred_username".to_string(), Value::String(value));
    }

    pub fn set_access_token_hash(&mut self, access_token_hash: impl Into<String>) {
        let value: String = access_token_hash.into();
        self.claims
            .insert("at_hash".to_string(), Value::String(value));
    }

    pub fn set_code_hash(&mut self, code_hash: impl Into<String>) {
        let value: String = code_hash.into();
        self.claims
            .insert("c_hash".to_string(), Value::String(value));
    }

    pub fn set_given_name(&mut self, given_name: impl Into<String>) {
        let value: String = given_name.into();
        self.claims
            .insert("given_name".to_string(), Value::String(value));
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        let value: String = name.into();
        self.claims.insert("name".to_string(), Value::String(value));
    }

    pub fn set_family_name(&mut self, family_name: impl Into<String>) {
        let value: String = family_name.into();
        self.claims
            .insert("family_name".to_string(), Value::String(value));
    }

    pub fn set_middle_name(&mut self, middle_name: impl Into<String>) {
        let value: String = middle_name.into();
        self.claims
            .insert("middle_name".to_string(), Value::String(value));
    }

    pub fn set_nick_name(&mut self, nick_name: impl Into<String>) {
        let value: String = nick_name.into();
        self.claims
            .insert("nick_name".to_string(), Value::String(value));
    }

    pub fn set_profile(&mut self, profile: impl Into<String>) {
        let value: String = profile.into();
        self.claims
            .insert("profile".to_string(), Value::String(value));
    }

    pub fn set_picture(&mut self, picture: impl Into<String>) {
        let value: String = picture.into();
        self.claims
            .insert("picture".to_string(), Value::String(value));
    }

    pub fn set_website(&mut self, website: impl Into<String>) {
        let value: String = website.into();
        self.claims
            .insert("website".to_string(), Value::String(value));
    }

    pub fn set_email(&mut self, email: impl Into<String>) {
        let value: String = email.into();
        self.claims
            .insert("email".to_string(), Value::String(value));
    }

    pub fn set_email_verified(&mut self, email_verified: impl Into<bool>) {
        let value: bool = email_verified.into();
        self.claims
            .insert("email_verified".to_string(), Value::Bool(value));
    }

    pub fn set_gender(&mut self, gender: impl Into<String>) {
        let value: String = gender.into();
        self.claims
            .insert("gender".to_string(), Value::String(value));
    }

    pub fn set_birth_date(&mut self, birthdate: impl Into<String>) {
        let value: String = birthdate.into();
        self.claims
            .insert("birthdate".to_string(), Value::String(value));
    }

    pub fn set_zoneinfo(&mut self, zoneinfo: impl Into<String>) {
        let value: String = zoneinfo.into();
        self.claims
            .insert("zoneinfo".to_string(), Value::String(value));
    }

    pub fn set_locale(&mut self, locale: impl Into<String>) {
        let value: String = locale.into();
        self.claims
            .insert("locale".to_string(), Value::String(value));
    }

    pub fn set_phone_number(&mut self, phone_number: impl Into<String>) {
        let value: String = phone_number.into();
        self.claims
            .insert("phone_number".to_string(), Value::String(value));
    }

    pub fn set_phone_number_verified(&mut self, phone_number_verified: impl Into<bool>) {
        let value: bool = phone_number_verified.into();
        self.claims
            .insert("phone_number_verified".to_string(), Value::Bool(value));
    }

    pub fn set_updated_at(&mut self, updated_at: impl Into<u64>) {
        let value: u64 = updated_at.into();
        self.claims
            .insert("updated_at".to_string(), Value::Number(Number::from(value)));
    }

    pub fn set_claims_locales(&mut self, claims_locales: impl Into<String>) {
        let value: String = claims_locales.into();
        self.claims
            .insert("claims_locales".to_string(), Value::String(value));
    }

    pub fn set_acr(&mut self, acr: impl Into<String>) {
        let value: String = acr.into();
        self.claims.insert("acr".to_string(), Value::String(value));
    }

    pub fn set_state_hash(&mut self, s_hash: impl Into<String>) {
        let value: String = s_hash.into();
        self.claims
            .insert("s_hash".to_string(), Value::String(value));
    }

    pub fn set_scope(&mut self, scope: impl Into<String>) {
        let value: String = scope.into();
        self.claims
            .insert("scope".to_string(), Value::String(value));
    }

    pub fn set_allowed_origins(&mut self, allowed_origins: Vec<impl Into<String>>) {
        let mut vec = Vec::with_capacity(allowed_origins.len());
        for val in allowed_origins {
            let val: String = val.into();
            vec.push(Value::String(val));
        }
        self.claims
            .insert("allowed-origins".to_string(), Value::Array(vec));
    }

    pub fn set_trusted_certificates(&mut self, set_trusted_certificates: Vec<impl Into<String>>) {
        let mut vec = Vec::with_capacity(set_trusted_certificates.len());
        for val in set_trusted_certificates {
            let val: String = val.into();
            vec.push(Value::String(val));
        }
        self.claims
            .insert("trusted-certs".to_string(), Value::Array(vec));
    }

    pub fn set_certificate_config(&mut self, config: super::CertificateConfig) {
        let mut access_map = Map::new();
        access_map.insert(
            "cert_thumbprint".to_owned(),
            Value::String(config.cert_thumbprint().to_owned()),
        );
        self.claims
            .insert("cnf".to_string(), Value::Object(access_map));
    }

    pub fn set_realm_access(&mut self, access: super::AccessTokenAccess) {
        AccessTokenImp::set_access_to_map("realm-access".to_string(), access, &mut self.claims);
    }

    pub fn set_resources_access(&mut self, accesses: BTreeMap<String, super::AccessTokenAccess>) {
        let mut access_map = Map::new();
        for (access_key, access) in accesses {
            AccessTokenImp::set_access_to_map(access_key, access, &mut access_map);
        }
        self.claims
            .insert("resource-access".to_string(), Value::Object(access_map));
    }

    fn set_access_to_map(
        access_key: String,
        access: super::AccessTokenAccess,
        map: &mut Map<String, Value>,
    ) {
        let mut access_map = Map::new();
        let mut roles: Vec<Value> = Vec::with_capacity(access.roles().len());
        for role in access.roles() {
            roles.push(Value::String(role.clone()));
        }
        access_map.insert("roles".to_owned(), Value::Array(roles));
        match access.verify_caller() {
            Some(val) => {
                access_map.insert("verify_caller".to_owned(), Value::Bool(val));
            }
            _ => {
                access_map.insert("verify_caller".to_owned(), Value::Null);
            }
        }
        map.insert(access_key, Value::Object(access_map));
    }

    fn check_claim(key: &str, value: &Value) -> Result<(), JwtError> {
        (|| -> anyhow::Result<()> {
            match key {
                "iss" | "sub" | "jti" | "nonce" | "sid" | "at_hash" | "c_hash" | "name"
                | "given_name" | "family_name" | "middle_name" | "nickname"
                | "preferred_username" | "profile" | "picture" | "website" | "email" | "gender"
                | "birthdate" | "zoneinfo" | "locale" | "phone_number" | "address"
                | "claims_locales" | "acr" | "s_hash" | "scope" => match &value {
                    Value::String(_) => {}
                    _ => bail!("The JWT {} payload claim must be a string.", key),
                },
                "aud" => match &value {
                    Value::String(_) => {}
                    Value::Array(vals) => {
                        for val in vals {
                            match val {
                                Value::String(_) => {}
                                _ => bail!(
                                    "An element of the JWT {} payload claim must be a string.",
                                    key
                                ),
                            }
                        }
                    }
                    _ => bail!("The JWT {} payload claim must be a string or array.", key),
                },
                "trusted-certs" | "allowed-origins" => match &value {
                    Value::Array(vals) => {
                        for val in vals {
                            match val {
                                Value::String(_) => {}
                                _ => bail!(
                                    "An element of the JWT {} payload claim must be a string.",
                                    key
                                ),
                            }
                        }
                    }
                    _ => bail!("The JWT {} payload claim must be a string of array.", key),
                },
                "exp" | "nbf" | "iat" | "auth_time" | "updated_at" => match &value {
                    Value::Number(val) => match val.as_u64() {
                        Some(_) => {}
                        None => bail!(
                            "The JWT {} payload claim must be a positive integer within 64bit.",
                            key
                        ),
                    },
                    _ => bail!("The JWT {} header claim must be a string.", key),
                },
                "email_verified" | "phone_number_verified" => match &value {
                    Value::Number(val) => match val.as_u64() {
                        Some(_) => {}
                        None => bail!("The JWT {} payload claim must be a boolean", key),
                    },
                    _ => bail!("The JWT {} header claim must be a string.", key),
                },
                "resource-access" => match &value {
                    Value::Object(resources) => {
                        for (key, resource_value) in resources {
                            match resource_value {
                                Value::Object(resource_map) => {
                                    let access_entry = super::AccessTokenAccess::from_map(resource_map);
                                    match access_entry {
                                        Ok(_) => {}
                                        _ => bail!("The JWT {} payload claim must be deserializable to resource config.", key),
                                    }
                                }
                                _ => bail!("{}", key),
                            }
                        }
                    }
                    _ => bail!("The JWT {} header claim must be a string.", key),
                },
                "realm-access" => match &value {
                    Value::Object(resource_access) => {
                        let access_entry = super::AccessTokenAccess::from_map(resource_access);
                        match access_entry {
                            Ok(_) => {}
                            _ => bail!("The JWT {} payload claim must be deserializable to resource config.", key),
                        }
                    }
                    _ => bail!("The JWT {} header claim must be a string.", key),
                },
                "cnf" => match &value {
                    Value::Object(val) => {
                        let cnf_value = super::CertificateConfig::from_map(val);
                        match cnf_value {
                            Ok(_) => {}
                            _ => bail!(
                                "An element of the JWT {} payload claim must be deserializable to certificat config.",
                                key
                            ),
                        }
                    }
                    _ => bail!("An element of the JWT {} payload claim must deserializable to certificat config.",key),
                },
                _ => {}
            }

            Ok(())
        })()
        .map_err(|err| JwtError::InvalidJwtFormat(err))
    }
}

impl AccessToken for AccessTokenImp {
    fn resources_access(&self) -> Result<BTreeMap<String, super::AccessTokenAccess>, JwtError> {
        (|| -> anyhow::Result<BTreeMap<String, super::AccessTokenAccess>> {
            let mut resources_map: BTreeMap<String, super::AccessTokenAccess> = BTreeMap::new();
            match self.claims.get("resource-access") {
                Some(Value::Object(resources)) => {
                    for (key, value) in resources {
                        match value {
                            Value::Object(resource_map) => {
                                let access_entry = super::AccessTokenAccess::from_map(resource_map);
                                match access_entry {
                                    Ok(access) => {
                                        resources_map.insert(key.clone(), access);
                                    }
                                    _ => bail!("{}", key),
                                }
                            }
                            _ => bail!("{}", key),
                        }
                    }
                }
                _ => bail!("Invalid resource access entries"),
            }
            Ok(resources_map)
        })()
        .map_err(|err| JwtError::InvalidJwtFormat(err))
    }

    fn get_resource_access(
        &self,
        resource: &str,
    ) -> Result<Option<super::AccessTokenAccess>, JwtError> {
        (|| -> anyhow::Result<Option<super::AccessTokenAccess>> {
            match self.claims.get("resource-access") {
                Some(Value::Object(resources)) => {
                    let resource_entry = resources.get(resource);
                    match resource_entry {
                        Some(Value::Object(resource_map)) => {
                            let access_entry = super::AccessTokenAccess::from_map(resource_map);
                            match access_entry {
                                Ok(access) => Ok(Some(access)),
                                _ => bail!("{}", resource),
                            }
                        }
                        _ => bail!("{}", resource),
                    }
                }
                _ => bail!("{}", resource),
            }
        })()
        .map_err(|err| JwtError::InvalidJwtFormat(err))
    }

    fn allowed_origins(&self) -> Option<Vec<String>> {
        match self.claims.get("allowed-origins") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    vec.push(val.to_string());
                }
                Some(vec)
            }
            _ => None,
        }
    }

    fn realm_access(&self) -> Option<super::AccessTokenAccess> {
        match self.claims.get("realm-access") {
            Some(Value::Object(object)) => {
                let access_entry = super::AccessTokenAccess::from_map(object);
                match access_entry {
                    Ok(access) => Some(access),
                    Err(_) => None,
                }
            }
            _ => None,
        }
    }

    fn trusted_certificates(&self) -> Option<Vec<String>> {
        match self.claims.get("trusted-certs") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    vec.push(val.to_string());
                }
                Some(vec)
            }
            _ => None,
        }
    }

    fn certificate_config(&self) -> Option<super::CertificateConfig> {
        match self.claims.get("cnf") {
            Some(Value::Object(object)) => {
                let config = super::CertificateConfig::from_map(object);
                if let Err(_) = config {
                    return None;
                }
                Some(config.unwrap())
            }
            _ => None,
        }
    }

    fn is_verify_caller(&self, resource: &str) -> Option<bool> {
        let access = self.get_resource_access(resource);
        match access {
            Ok(res) => match res {
                Some(resource_access) => resource_access.verify_caller(),
                _ => None,
            },
            _ => None,
        }
    }
}

impl IdToken for AccessTokenImp {
    fn nonce(&self) -> Option<&str> {
        match self.claims.get("nonce") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn auth_time(&self) -> Option<u64> {
        match self.claims.get("auth_time") {
            Some(Value::Number(val)) => val.as_u64(),
            _ => None,
        }
    }

    fn session_id(&self) -> Option<&str> {
        match self.claims.get("sid") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn preferred_username(&self) -> Option<&str> {
        match self.claims.get("preferred_username") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn access_token_hash(&self) -> Option<&str> {
        match self.claims.get("at_hash") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn code_hash(&self) -> Option<&str> {
        match self.claims.get("c_hash") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn given_name(&self) -> Option<&str> {
        match self.claims.get("given_name") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn name(&self) -> Option<&str> {
        match self.claims.get("name") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn family_name(&self) -> Option<&str> {
        match self.claims.get("family_name") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn middle_name(&self) -> Option<&str> {
        match self.claims.get("middle_name") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn nick_name(&self) -> Option<&str> {
        match self.claims.get("nickname") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn profile(&self) -> Option<&str> {
        match self.claims.get("profile") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn picture(&self) -> Option<&str> {
        match self.claims.get("picture") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn website(&self) -> Option<&str> {
        match self.claims.get("website") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn email(&self) -> Option<&str> {
        match self.claims.get("email") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn email_verified(&self) -> Option<bool> {
        match self.claims.get("email_verified") {
            Some(Value::Bool(val)) => Some(val.clone()),
            _ => None,
        }
    }

    fn gender(&self) -> Option<&str> {
        match self.claims.get("gender") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn birth_date(&self) -> Option<&str> {
        match self.claims.get("birth_date") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn zoneinfo(&self) -> Option<&str> {
        match self.claims.get("zoneinfo") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn locale(&self) -> Option<&str> {
        match self.claims.get("locale") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn phone_number(&self) -> Option<&str> {
        match self.claims.get("phone_number") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn phone_number_verified(&self) -> Option<bool> {
        match self.claims.get("phone_number_verified") {
            Some(Value::Bool(val)) => Some(val.clone()),
            _ => None,
        }
    }

    fn updated_at(&self) -> Option<u64> {
        match self.claims.get("updated_at") {
            Some(Value::Number(val)) => val.as_u64(),
            _ => None,
        }
    }

    fn claims_locales(&self) -> Option<&str> {
        match self.claims.get("claims_locales") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn acr(&self) -> Option<&str> {
        match self.claims.get("acr") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn state_hash(&self) -> Option<&str> {
        match self.claims.get("s_hash") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }
}

impl Jwt for AccessTokenImp {
    fn token_id(&self) -> Option<&str> {
        match self.claims.get("jti") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn issuer(&self) -> Option<&str> {
        match self.claims.get("iss") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn not_before(&self) -> Option<SystemTime> {
        match self.claims.get("nbf") {
            Some(Value::Number(val)) => match val.as_u64() {
                Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                None => None,
            },
            _ => None,
        }
    }

    fn issue_at(&self) -> Option<SystemTime> {
        match self.claims.get("iat") {
            Some(Value::Number(val)) => match val.as_u64() {
                Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                None => None,
            },
            _ => None,
        }
    }

    fn audience(&self) -> Option<Vec<&str>> {
        match self.claims.get("aud") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => {
                            vec.push(val2.as_str());
                        }
                        _ => return None,
                    }
                }
                Some(vec)
            }
            Some(Value::String(val)) => Some(vec![val]),
            _ => None,
        }
    }

    fn has_audience(&self, audience: &str) -> bool {
        match self.claims.get("aud") {
            Some(Value::Array(vals)) => {
                for val in vals {
                    if let Value::String(val2) = val {
                        if *val2 == *audience {
                            return true;
                        }
                    }
                }
                false
            }
            Some(Value::String(val)) => *val == *audience,
            _ => false,
        }
    }

    fn has_any_audiences(&self, audiences: &Vec<String>) -> bool {
        match self.claims.get("aud") {
            Some(Value::Array(vals)) => {
                for val in vals {
                    if let Value::String(val2) = val {
                        if audiences.contains(&val2) {
                            return true;
                        }
                    }
                }
                false
            }
            Some(Value::String(val)) => audiences.contains(&val),
            _ => false,
        }
    }

    fn subject(&self) -> Option<&str> {
        match self.claims.get("sub") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn expires_at(&self) -> Option<SystemTime> {
        match self.claims.get("exp") {
            Some(Value::Number(val)) => match val.as_u64() {
                Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                None => None,
            },
            _ => None,
        }
    }

    fn token_type(&self) -> Option<&str> {
        match self.claims.get("typ") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn issued_for(&self) -> Option<&str> {
        match self.claims.get("azp") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn claims_set(&self) -> &Map<String, Value> {
        &self.claims
    }

    fn is_expired(&self) -> bool {
        match self.expires_at() {
            Some(exp) => SystemTime::now() >= exp,
            _ => false,
        }
    }

    fn is_not_before(&self, allow_clock_skew: u64) -> bool {
        match self.not_before() {
            Some(exp) => {
                (SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + allow_clock_skew)
                    >= exp
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
            }
            _ => true,
        }
    }

    fn is_active(&self, allow_clock_skew: u64) -> bool {
        self.is_expired() && self.is_not_before(allow_clock_skew)
    }
}

impl Token for AccessTokenImp {
    fn category(&self) -> TokenCategoryEnum {
        TokenCategoryEnum::Access
    }
}

impl AsRef<Map<String, Value>> for AccessTokenImp {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.claims
    }
}

impl Into<Map<String, Value>> for AccessTokenImp {
    fn into(self) -> Map<String, Value> {
        self.into_map()
    }
}

impl Display for AccessTokenImp {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let val = serde_json::to_string(&self.claims).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str(&val)
    }
}

impl TryInto<IdTokenImp> for AccessTokenImp {
    type Error = JwtError;

    fn try_into(self) -> Result<IdTokenImp, Self::Error> {
        IdTokenImp::from_map(self.into_map())
    }
}

impl TryInto<JsonWebToken> for AccessTokenImp {
    type Error = JwtError;

    fn try_into(self) -> Result<JsonWebToken, Self::Error> {
        JsonWebToken::from_map(self.into_map())
    }
}
