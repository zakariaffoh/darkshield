use anyhow::bail;
use base64_url::base64;
use serde_json::{Map, Value};
use std::cmp::Eq;
use std::convert::Into;
use std::fmt::{Debug, Display};
use std::ops::Deref;

use crate::jose::error::JoseError;
use crate::jose::header::JoseHeader;
use crate::jose::jwk::jwk::Jwk;
use crate::jose::util;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JweHeader {
    claims: Map<String, Value>,
}

impl JweHeader {
    pub fn new() -> Self {
        Self { claims: Map::new() }
    }

    pub fn from_bytes(value: &[u8]) -> Result<Self, JoseError> {
        let claims = (|| -> anyhow::Result<Map<String, Value>> {
            let claims: Map<String, Value> = serde_json::from_slice(value)?;
            Ok(claims)
        })()
        .map_err(|err| JoseError::InvalidJson(err))?;

        let header = Self::from_map(claims)?;
        Ok(header)
    }

    pub fn from_map(map: impl Into<Map<String, Value>>) -> Result<Self, JoseError> {
        let map: Map<String, Value> = map.into();
        for (key, value) in &map {
            Self::check_claim(key, value)?;
        }
        Ok(Self { claims: map })
    }

    pub fn set_algorithm(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("alg".to_string(), Value::String(value));
    }

    pub fn algorithm(&self) -> Option<&str> {
        match self.claim("alg") {
            Some(Value::String(val)) => Some(&val),
            _ => None,
        }
    }

    pub fn set_content_encryption(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("enc".to_string(), Value::String(value));
    }

    pub fn content_encryption(&self) -> Option<&str> {
        match self.claims.get("enc") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_compression(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("zip".to_string(), Value::String(value));
    }

    pub fn compression(&self) -> Option<&str> {
        match self.claims.get("zip") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_jwk_set_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("jku".to_string(), Value::String(value));
    }

    pub fn jwk_set_url(&self) -> Option<&str> {
        match self.claims.get("jku") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_jwk(&mut self, value: Jwk) {
        let key = "jwk";
        let value: Map<String, Value> = value.into();
        self.claims.insert(key.to_string(), Value::Object(value));
    }

    pub fn jwk(&self) -> Option<Jwk> {
        match self.claims.get("jwk") {
            Some(Value::Object(vals)) => match Jwk::from_map(vals.clone()) {
                Ok(val) => Some(val),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_x509_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("x5u".to_string(), Value::String(value));
    }

    pub fn x509_url(&self) -> Option<&str> {
        match self.claims.get("x5u") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_x509_certificate_chain(&mut self, values: &Vec<impl AsRef<[u8]>>) {
        let key = "x5c";
        let mut vec = Vec::with_capacity(values.len());
        for val in values {
            vec.push(Value::String(base64::encode_config(
                val.as_ref(),
                base64::URL_SAFE_NO_PAD,
            )));
        }
        self.claims.insert(key.to_string(), Value::Array(vec));
    }

    pub fn x509_certificate_chain(&self) -> Option<Vec<Vec<u8>>> {
        match self.claims.get("x5c") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => {
                            match base64::decode_config(val2, base64::URL_SAFE_NO_PAD) {
                                Ok(val3) => vec.push(val3.clone()),
                                Err(_) => return None,
                            }
                        }
                        _ => return None,
                    }
                }
                Some(vec)
            }
            _ => None,
        }
    }

    pub fn set_x509_certificate_sha1_thumbprint(&mut self, value: impl AsRef<[u8]>) {
        let key = "x5t";
        let val = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        self.claims.insert(key.to_string(), Value::String(val));
    }

    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<Vec<u8>> {
        match self.claims.get("x5t") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_x509_certificate_sha256_thumbprint(&mut self, value: impl AsRef<[u8]>) {
        let key = "x5t#S256";
        let val = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        self.claims.insert(key.to_string(), Value::String(val));
    }

    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<Vec<u8>> {
        match self.claims.get("x5t#S256") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_kid(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("kid".to_string(), Value::String(value));
    }

    pub fn kid(&self) -> Option<&str> {
        match self.claims.get("kid") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_token_type(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("typ".to_string(), Value::String(value));
    }

    pub fn token_type(&self) -> Option<&str> {
        match self.claims.get("typ") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_content_type(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("cty".to_string(), Value::String(value));
    }

    pub fn content_type(&self) -> Option<&str> {
        match self.claims.get("cty") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_critical(&mut self, values: &Vec<impl AsRef<str>>) {
        let key = "crit";
        let vec = values
            .iter()
            .map(|v| Value::String(v.as_ref().to_string()))
            .collect();
        self.claims.insert(key.to_string(), Value::Array(vec));
    }

    pub fn critical(&self) -> Option<Vec<&str>> {
        match self.claims.get("crit") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => vec.push(val2.as_str()),
                        _ => return None,
                    }
                }
                Some(vec)
            }
            _ => None,
        }
    }

    pub fn set_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("url".to_string(), Value::String(value));
    }

    pub fn url(&self) -> Option<&str> {
        match self.claims.get("url") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_nonce(&mut self, value: impl AsRef<[u8]>) {
        let key = "nonce";
        let val = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        self.claims.insert(key.to_string(), Value::String(val));
    }

    pub fn nonce(&self) -> Option<Vec<u8>> {
        match self.claims.get("nonce") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_agreement_partyuinfo(&mut self, value: impl AsRef<[u8]>) {
        let key = "apu";
        let val = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        self.claims.insert(key.to_string(), Value::String(val));
    }

    pub fn agreement_partyuinfo(&self) -> Option<Vec<u8>> {
        match self.claims.get("apu") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_agreement_partyvinfo(&mut self, value: impl AsRef<[u8]>) {
        let key = "apv";
        let val = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        self.claims.insert(key.to_string(), Value::String(val));
    }

    pub fn agreement_partyvinfo(&self) -> Option<Vec<u8>> {
        match self.claims.get("apv") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_issuer(&mut self, value: impl Into<String>) {
        let key = "iss";
        let value: String = value.into();
        self.claims.insert(key.to_string(), Value::String(value));
    }

    pub fn issuer(&self) -> Option<&str> {
        match self.claims.get("iss") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_subject(&mut self, value: impl Into<String>) {
        let key = "sub";
        let value: String = value.into();
        self.claims.insert(key.to_string(), Value::String(value));
    }

    pub fn subject(&self) -> Option<&str> {
        match self.claims.get("sub") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_audience(&mut self, values: Vec<impl Into<String>>) {
        let key = "aud".to_string();
        if values.len() == 1 {
            for val in values {
                let val: String = val.into();
                self.claims.insert(key, Value::String(val));
                break;
            }
        } else if values.len() > 1 {
            let mut vec = Vec::with_capacity(values.len());
            for val in values {
                let val: String = val.into();
                vec.push(Value::String(val.clone()));
            }
            self.claims.insert(key.clone(), Value::Array(vec));
        }
    }

    /// Return values for audience header claim (aud).
    pub fn audience(&self) -> Option<Vec<&str>> {
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

    pub fn set_claim(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError> {
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
    }

    pub fn claims_set(&self) -> &Map<String, Value> {
        &self.claims
    }

    pub fn into_map(self) -> Map<String, Value> {
        self.claims
    }

    pub(crate) fn check_claim(key: &str, value: &Value) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            match key {
                "alg" | "enc" | "zip" | "jku" | "x5u" | "kid" | "typ" | "cty" | "url" | "iss"
                | "sub" => match &value {
                    Value::String(_) => {}
                    _ => bail!("The JWE {} header claim must be string.", key),
                },
                "aud" => match &value {
                    Value::String(_) => {}
                    Value::Array(vals) => {
                        for val in vals {
                            match val {
                                Value::String(_) => {}
                                _ => bail!(
                                    "An element of the JWE {} header claim must be a string.",
                                    key
                                ),
                            }
                        }
                    }
                    _ => bail!("The JWE {} payload claim must be a string or array.", key),
                },
                "crit" => match &value {
                    Value::Array(vals) => {
                        for val in vals {
                            match val {
                                Value::String(_) => {}
                                _ => bail!(
                                    "An element of the JWE {} header claim must be a string.",
                                    key
                                ),
                            }
                        }
                    }
                    _ => bail!("The JWE {} header claim must be a array.", key),
                },
                "x5t" | "x5t#S256" | "nonce" | "apu" | "apv" => match &value {
                    Value::String(val) => {
                        if !util::is_base64_url_safe_nopad(val) {
                            bail!("The JWE {} header claim must be a base64 string.", key);
                        }
                    }
                    _ => bail!("The JWE {} header claim must be a string.", key),
                },
                "x5c" => match &value {
                    Value::Array(vals) => {
                        for val in vals {
                            match val {
                                Value::String(val) => {
                                    if !util::is_base64_url_safe_nopad(val) {
                                        bail!(
                                            "The JWE {} header claim must be a base64 string.",
                                            key
                                        );
                                    }
                                }
                                _ => bail!(
                                    "An element of the JWE {} header claim must be a string.",
                                    key
                                ),
                            }
                        }
                    }
                    _ => bail!("The JWE {} header claim must be a array.", key),
                },
                "jwk" => match &value {
                    Value::Object(vals) => Jwk::check_map(vals)?,
                    _ => bail!("The JWE {} header claim must be a string.", key),
                },
                _ => {}
            }

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }
}

impl JoseHeader for JweHeader {
    fn len(&self) -> usize {
        self.claims.len()
    }

    fn claim(&self, key: &str) -> Option<&Value> {
        self.claims.get(key)
    }

    fn box_clone(&self) -> Box<dyn JoseHeader> {
        Box::new(self.clone())
    }
}

impl AsRef<Map<String, Value>> for JweHeader {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.claims
    }
}

impl Into<Map<String, Value>> for JweHeader {
    fn into(self) -> Map<String, Value> {
        self.into_map()
    }
}

impl Display for JweHeader {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let val = serde_json::to_string(&self.claims).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str(&val)
    }
}

impl Deref for JweHeader {
    type Target = dyn JoseHeader;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JweHeaderSet {
    protected: Map<String, Value>,
    unprotected: Map<String, Value>,
}

impl JweHeaderSet {
    pub fn new() -> Self {
        Self {
            protected: Map::new(),
            unprotected: Map::new(),
        }
    }

    pub fn set_algorithm(&mut self, value: impl Into<String>, protection: bool) {
        let key = "alg";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn algorithm(&self) -> Option<&str> {
        match self.claim("alg") {
            Some(Value::String(val)) => Some(&val),
            _ => None,
        }
    }

    pub fn set_content_encryption(&mut self, value: impl Into<String>, protection: bool) {
        let key = "enc";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn content_encryption(&self) -> Option<&str> {
        match self.claim("enc") {
            Some(Value::String(val)) => Some(&val),
            _ => None,
        }
    }

    pub fn set_compression(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.protected
            .insert("zip".to_string(), Value::String(value));
    }

    pub fn compression(&self) -> Option<&str> {
        match self.protected.get("zip") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_jwk_set_url(&mut self, value: impl Into<String>, protection: bool) {
        let key = "jku";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn jwk_set_url(&self) -> Option<&str> {
        match self.claim("jku") {
            Some(Value::String(val)) => Some(&val),
            _ => None,
        }
    }

    pub fn set_jwk(&mut self, value: Jwk, protection: bool) {
        let key = "jwk";
        let value: Map<String, Value> = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::Object(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::Object(value));
        }
    }

    pub fn jwk(&self) -> Option<Jwk> {
        match self.claim("jwk") {
            Some(Value::Object(vals)) => match Jwk::from_map(vals.clone()) {
                Ok(val) => Some(val),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_x509_url(&mut self, value: impl Into<String>, protection: bool) {
        let key = "x5u";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn x509_url(&self) -> Option<&str> {
        match self.claim("x5u") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_x509_certificate_chain(&mut self, values: &Vec<impl AsRef<[u8]>>, protection: bool) {
        let key = "x5c";
        let vec = values
            .iter()
            .map(|v| Value::String(base64::encode_config(v.as_ref(), base64::URL_SAFE_NO_PAD)))
            .collect();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::Array(vec));
        } else {
            self.protected.remove(key);
            self.unprotected.insert(key.to_string(), Value::Array(vec));
        }
    }

    pub fn x509_certificate_chain(&self) -> Option<Vec<Vec<u8>>> {
        match self.claim("x5c") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => {
                            match base64::decode_config(val2, base64::URL_SAFE_NO_PAD) {
                                Ok(val3) => vec.push(val3.clone()),
                                Err(_) => return None,
                            }
                        }
                        _ => return None,
                    }
                }
                Some(vec)
            }
            _ => None,
        }
    }

    pub fn set_x509_certificate_sha1_thumbprint(
        &mut self,
        value: impl AsRef<[u8]>,
        protection: bool,
    ) {
        let key = "x5t";
        let value = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<Vec<u8>> {
        match self.claim("x5t") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_x509_certificate_sha256_thumbprint(
        &mut self,
        value: impl AsRef<[u8]>,
        protection: bool,
    ) {
        let key = "x5t#S256";
        let value = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<Vec<u8>> {
        match self.claim("x5t#S256") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_kid(&mut self, value: impl Into<String>, protection: bool) {
        let key = "kid";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    /// Return the value for key ID header claim (kid).
    pub fn kid(&self) -> Option<&str> {
        match self.claim("kid") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_token_type(&mut self, value: impl Into<String>, protection: bool) {
        let key = "typ";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn token_type(&self) -> Option<&str> {
        match self.claim("typ") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_content_type(&mut self, value: impl Into<String>, protection: bool) {
        let key = "cty";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn content_type(&self) -> Option<&str> {
        match self.claim("cty") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_critical(&mut self, values: &Vec<impl AsRef<str>>) {
        let key = "crit";
        let vec = values
            .iter()
            .map(|v| Value::String(base64::encode_config(v.as_ref(), base64::URL_SAFE_NO_PAD)))
            .collect();
        self.unprotected.remove(key);
        self.protected.insert(key.to_string(), Value::Array(vec));
    }

    pub fn critical(&self) -> Option<Vec<&str>> {
        match self.claim("crit") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => vec.push(val2.as_str()),
                        _ => return None,
                    }
                }
                Some(vec)
            }
            _ => None,
        }
    }

    pub fn set_url(&mut self, value: impl Into<String>, protection: bool) {
        let key = "url";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn url(&self) -> Option<&str> {
        match self.claim("url") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_nonce(&mut self, value: impl AsRef<[u8]>, protection: bool) {
        let key = "nonce";
        let value = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn nonce(&self) -> Option<Vec<u8>> {
        match self.claim("nonce") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_agreement_partyuinfo(&mut self, value: impl AsRef<[u8]>, protection: bool) {
        let key = "apu";
        let value = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn agreement_partyuinfo(&self) -> Option<Vec<u8>> {
        match self.claim("apu") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_agreement_partyvinfo(&mut self, value: impl AsRef<[u8]>, protection: bool) {
        let key = "apv";
        let value = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn agreement_partyvinfo(&self) -> Option<Vec<u8>> {
        match self.claim("apv") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val2) => Some(val2),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_issuer(&mut self, value: impl Into<String>, protection: bool) {
        let key = "iss";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn issuer(&self) -> Option<&str> {
        match self.claim("iss") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_subject(&mut self, value: impl Into<String>, protection: bool) {
        let key = "sub";
        let value: String = value.into();
        if protection {
            self.unprotected.remove(key);
            self.protected.insert(key.to_string(), Value::String(value));
        } else {
            self.protected.remove(key);
            self.unprotected
                .insert(key.to_string(), Value::String(value));
        }
    }

    pub fn subject(&self) -> Option<&str> {
        match self.claim("sub") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    pub fn set_audience(&mut self, values: Vec<impl Into<String>>, protection: bool) {
        let key = "aud";
        if values.len() == 1 {
            for val in values {
                let value = val.into();
                if protection {
                    self.unprotected.remove(key);
                    self.protected.insert(key.to_string(), Value::String(value));
                } else {
                    self.protected.remove(key);
                    self.unprotected
                        .insert(key.to_string(), Value::String(value));
                }
                break;
            }
        } else if values.len() > 1 {
            let mut vec = Vec::with_capacity(values.len());
            for val in values {
                let val: String = val.into();
                vec.push(Value::String(val.clone()));
            }
            if protection {
                self.unprotected.remove(key);
                self.protected.insert(key.to_string(), Value::Array(vec));
            } else {
                self.protected.remove(key);
                self.unprotected.insert(key.to_string(), Value::Array(vec));
            }
        }
    }

    pub fn audience(&self) -> Option<Vec<&str>> {
        match self.claim("aud") {
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

    pub fn set_claim(
        &mut self,
        key: &str,
        value: Option<Value>,
        protection: bool,
    ) -> Result<(), JoseError> {
        match value {
            Some(val) => {
                JweHeader::check_claim(key, &val)?;
                if protection {
                    self.unprotected.remove(key);
                    self.protected.insert(key.to_string(), val);
                } else {
                    self.protected.remove(key);
                    self.unprotected.insert(key.to_string(), val);
                }
            }
            None => {
                self.protected.remove(key);
                self.unprotected.remove(key);
            }
        }

        Ok(())
    }

    pub fn claims_set(&self, protection: bool) -> &Map<String, Value> {
        if protection {
            &self.protected
        } else {
            &self.unprotected
        }
    }

    pub fn to_map(&self) -> Map<String, Value> {
        let mut map = self.protected.clone();
        for (key, value) in &self.unprotected {
            map.insert(key.clone(), value.clone());
        }
        map
    }
}

impl JoseHeader for JweHeaderSet {
    fn len(&self) -> usize {
        self.protected.len() + self.unprotected.len()
    }

    fn claim(&self, key: &str) -> Option<&Value> {
        if let Some(val) = self.protected.get(key) {
            Some(val)
        } else {
            self.unprotected.get(key)
        }
    }

    fn box_clone(&self) -> Box<dyn JoseHeader> {
        Box::new(self.clone())
    }
}

impl Display for JweHeaderSet {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let protected = serde_json::to_string(&self.protected).map_err(|_e| std::fmt::Error {})?;
        let unprotected =
            serde_json::to_string(&self.unprotected).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str("{\"protected\":")?;
        fmt.write_str(&protected)?;
        fmt.write_str(",\"unprotected\":")?;
        fmt.write_str(&unprotected)?;
        fmt.write_str("}")?;
        Ok(())
    }
}

impl Deref for JweHeaderSet {
    type Target = dyn JoseHeader;

    fn deref(&self) -> &Self::Target {
        self
    }
}
