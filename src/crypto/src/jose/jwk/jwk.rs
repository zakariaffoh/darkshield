use base64_url::base64;
use serde::{Deserialize, Serialize};
use serde_json::Map;
use serde_json::Value;

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fmt::Display;
use std::io::Read;
use std::ops::Bound::Included;
use std::string::ToString;
use std::sync::Arc;

use anyhow::bail;

use crate::core::hash_algorithm::HashAlgorithm;
use crate::jose::error::JoseError;
use crate::jose::util;
use crate::jose::util::oid::{
    OID_ED25519, OID_ED448, OID_ID_EC_PUBLIC_KEY, OID_MGF1, OID_PRIME256V1, OID_RSASSA_PSS,
    OID_RSA_ENCRYPTION, OID_SECP256K1, OID_SECP384R1, OID_SECP521R1, OID_SHA1, OID_SHA256,
    OID_SHA384, OID_SHA512, OID_X25519, OID_X448,
};

use super::alg::ec::EcCurve;
use super::alg::ec::EcKeyPair;
use super::alg::ecx::EcxCurve;
use super::alg::ecx::EcxKeyPair;
use super::alg::ed::EdCurve;
use super::alg::ed::EdKeyPair;
use super::alg::rsa::RsaKeyPair;
use super::der::der_class::DerClass;
use super::der::der_error::DerError;
use super::der::der_reader::DerReader;
use super::der::der_type::DerType;

/// Represents JWK object.
#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize)]
pub struct Jwk {
    #[serde(flatten)]
    map: Map<String, Value>,
}

impl Jwk {
    pub fn new(key_type: &str) -> Self {
        Self {
            map: {
                let mut map = Map::new();
                map.insert("kty".to_string(), Value::String(key_type.to_string()));
                map
            },
        }
    }

    pub fn from_map(map: impl Into<Map<String, Value>>) -> Result<Self, JoseError> {
        let map: Map<String, Value> = map.into();
        Self::check_map(&map)?;
        Ok(Self { map })
    }

    pub fn from_reader(input: &mut dyn Read) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let map: Map<String, Value> = serde_json::from_reader(input)?;
            Ok(Self::from_map(map)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwkFormat(err),
        })
    }

    pub fn from_bytes(input: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let map: Map<String, Value> = serde_json::from_slice(input.as_ref())?;
            Ok(Self::from_map(map)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwkFormat(err),
        })
    }

    pub fn generate_oct_key(key_len: u8) -> Result<Self, JoseError> {
        let k = util::random_bytes(key_len as usize);

        let mut jwk = Self::new("oct");
        jwk.map.insert(
            "k".to_string(),
            Value::String(base64::encode_config(&k, base64::URL_SAFE_NO_PAD)),
        );
        Ok(jwk)
    }

    pub fn generate_rsa_key(bits: u32) -> Result<Self, JoseError> {
        let key_pair = RsaKeyPair::generate(bits)?;
        Ok(key_pair.to_jwk_key_pair())
    }

    pub fn generate_ec_key(curve: EcCurve) -> Result<Self, JoseError> {
        let key_pair = EcKeyPair::generate(curve)?;
        Ok(key_pair.to_jwk_key_pair())
    }

    pub fn generate_ed_key(curve: EdCurve) -> Result<Self, JoseError> {
        let key_pair = EdKeyPair::generate(curve)?;
        Ok(key_pair.to_jwk_key_pair())
    }

    pub fn generate_ecx_key(curve: EcxCurve) -> Result<Self, JoseError> {
        let key_pair = EcxKeyPair::generate(curve)?;
        Ok(key_pair.to_jwk_key_pair())
    }

    pub fn set_key_type(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.map.insert("kty".to_string(), Value::String(value));
    }

    pub fn key_type(&self) -> &str {
        match self.map.get("kty") {
            Some(Value::String(val)) => val,
            _ => unreachable!("The JWS kty parameter is required."),
        }
    }

    pub fn set_key_use(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.map.insert("use".to_string(), Value::String(value));
    }

    pub fn key_use(&self) -> Option<&str> {
        match self.map.get("use") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    pub fn set_key_operations(&mut self, values: Vec<impl Into<String>>) {
        let mut vec = Vec::with_capacity(values.len());
        for val in values {
            let val: String = val.into();
            vec.push(Value::String(val.clone()));
        }
        self.map.insert("key_ops".to_string(), Value::Array(vec));
    }

    pub fn key_operations(&self) -> Option<Vec<&str>> {
        match self.map.get("key_ops") {
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

    pub fn is_for_key_operation(&self, key_operation: &str) -> bool {
        match self.map.get("key_ops") {
            Some(Value::Array(vals)) => vals.iter().any(|val| match val {
                Value::String(val2) if val2 == key_operation => true,
                _ => false,
            }),
            Some(_) => false,
            None => true,
        }
    }

    pub fn set_algorithm(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.map.insert("alg".to_string(), Value::String(value));
    }

    pub fn algorithm(&self) -> Option<&str> {
        match self.map.get("alg") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    pub fn set_kid(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.map.insert("kid".to_string(), Value::String(value));
    }

    pub fn kid(&self) -> Option<&str> {
        match self.map.get("kid") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    pub fn set_x509_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.map.insert("x5u".to_string(), Value::String(value));
    }

    pub fn x509_url(&self) -> Option<&str> {
        match self.map.get("x5u") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    pub fn set_x509_certificate_sha1_thumbprint(&mut self, value: impl AsRef<[u8]>) {
        self.map.insert(
            "x5t".to_string(),
            Value::String(base64::encode_config(&value, base64::URL_SAFE_NO_PAD)),
        );
    }

    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<Vec<u8>> {
        match self.map.get("x5t") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val) => Some(val),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_x509_certificate_sha256_thumbprint(&mut self, value: impl AsRef<[u8]>) {
        self.map.insert(
            "x5t#S256".to_string(),
            Value::String(base64::encode_config(&value, base64::URL_SAFE_NO_PAD)),
        );
    }

    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<Vec<u8>> {
        match self.map.get("x5t#S256") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val) => Some(val),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_x509_certificate_chain(&mut self, values: &Vec<impl AsRef<[u8]>>) {
        let mut vec = Vec::with_capacity(values.len());
        for val in values {
            vec.push(Value::String(base64::encode_config(
                &val,
                base64::URL_SAFE_NO_PAD,
            )));
        }
        self.map.insert("x5c".to_string(), Value::Array(vec));
    }

    pub fn x509_certificate_chain(&self) -> Option<Vec<Vec<u8>>> {
        match self.map.get("x5c") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => {
                            match base64::decode_config(val2, base64::URL_SAFE_NO_PAD) {
                                Ok(val3) => vec.push(val3),
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

    pub fn set_curve(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.map.insert("crv".to_string(), Value::String(value));
    }

    /// Return a value for a curve parameter (crv).
    pub fn curve(&self) -> Option<&str> {
        match self.map.get("crv") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    pub fn set_key_value(&mut self, value: impl AsRef<[u8]>) {
        self.map.insert(
            "k".to_string(),
            Value::String(base64::encode_config(&value, base64::URL_SAFE_NO_PAD)),
        );
    }

    pub fn key_value(&self) -> Option<Vec<u8>> {
        match self.map.get("k") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val) => Some(val),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn set_parameter(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError> {
        match value {
            Some(val) => {
                Self::check_parameter(key, &val)?;
                self.map.insert(key.to_string(), val);
            }
            None => {
                (|| -> anyhow::Result<()> {
                    match key {
                        "kty" => bail!("The JWK {} parameter must be required.", key),
                        _ => {}
                    }
                    Ok(())
                })()
                .map_err(|err| JoseError::InvalidJwkFormat(err))?;

                self.map.remove(key);
            }
        }
        Ok(())
    }

    pub fn parameter(&self, key: &str) -> Option<&Value> {
        self.map.get(key)
    }

    pub(crate) fn check_map(map: &Map<String, Value>) -> Result<(), JoseError> {
        for (key, value) in map {
            Self::check_parameter(key, value)?;
        }

        (|| -> anyhow::Result<()> {
            if !map.contains_key("kty") {
                bail!("The JWK kty parameter is required.");
            }
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwsFormat(err))
    }

    fn check_parameter(key: &str, value: &Value) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            match key {
                "kty" | "use" | "alg" | "kid" | "x5u" | "crv" => match &value {
                    Value::String(_) => {}
                    _ => bail!("The JWK {} parameter must be a string.", key),
                },
                "key_ops" => match &value {
                    Value::Array(vals) => {
                        for val in vals {
                            match val {
                                Value::String(_) => {}
                                _ => bail!(
                                    "An element of the JWK {} parameter must be a string.",
                                    key
                                ),
                            }
                        }
                    }
                    _ => bail!("The JWK {} parameter must be a array of string.", key),
                },
                "x5t" | "x5t#S256" | "k" | "d" | "p" | "q" | "dp" | "dq" | "qi" | "x" | "y" => {
                    match &value {
                        Value::String(val) => {
                            if !util::is_base64_url_safe_nopad(val) {
                                bail!("The JWK {} parameter must be a base64 string.", key);
                            }
                        }
                        _ => bail!("The JWK {} parameter must be a string.", key),
                    }
                }
                "x5c" => match &value {
                    Value::Array(vals) => {
                        for val in vals {
                            match val {
                                Value::String(val) => {
                                    if !util::is_base64_url_safe_nopad(val) {
                                        bail!("The JWK {} parameter must be a base64 string.", key);
                                    }
                                }
                                _ => bail!(
                                    "An element of the JWK {} parameter must be a string.",
                                    key
                                ),
                            }
                        }
                    }
                    _ => bail!("The JWK {} parameter must be a array of string.", key),
                },
                _ => {}
            }

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwkFormat(err))
    }
}

impl AsRef<Map<String, Value>> for Jwk {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.map
    }
}

impl Into<Map<String, Value>> for Jwk {
    fn into(self) -> Map<String, Value> {
        self.map
    }
}

impl Display for Jwk {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let val = serde_json::to_string(&self.map).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str(&val)
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JwkSet {
    keys: Vec<Arc<Jwk>>,
    params: Map<String, Value>,
    kid_map: BTreeMap<(String, usize), Arc<Jwk>>,
}

impl JwkSet {
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            params: Map::new(),
            kid_map: BTreeMap::new(),
        }
    }

    pub fn from_map(map: Map<String, Value>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let mut kid_map = BTreeMap::new();
            let keys = match map.get("keys") {
                Some(Value::Array(vals)) => {
                    let mut vec = Vec::new();
                    for (i, val) in vals.iter().enumerate() {
                        match val {
                            Value::Object(val) => {
                                let jwk = Arc::new(Jwk::from_map(val.clone())?);
                                if let Some(kid) = jwk.kid() {
                                    kid_map.insert((kid.to_string(), i), Arc::clone(&jwk));
                                }
                                vec.push(jwk);
                            }
                            _ => {
                                bail!("An element of the JWK set keys parameter must be a object.")
                            }
                        }
                    }
                    vec
                }
                Some(_) => bail!("The JWT keys parameter must be a array."),
                None => bail!("The JWK set must have a keys parameter."),
            };

            Ok(Self {
                keys,
                params: map,
                kid_map: kid_map,
            })
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwkFormat(err),
        })
    }

    pub fn from_reader(input: &mut dyn Read) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let keys: Map<String, Value> = serde_json::from_reader(input)?;
            Ok(Self::from_map(keys)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwkFormat(err),
        })
    }

    pub fn from_bytes(input: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let keys: Map<String, Value> = serde_json::from_slice(input.as_ref())?;
            Ok(Self::from_map(keys)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwkFormat(err),
        })
    }

    pub fn get(&self, kid: &str) -> Vec<&Jwk> {
        let mut vec = Vec::new();
        for (_, val) in self.kid_map.range((
            Included((kid.to_string(), 0)),
            Included((kid.to_string(), usize::MAX)),
        )) {
            let jwk: &Jwk = &val;
            vec.push(jwk);
        }
        vec
    }

    pub fn keys(&self) -> Vec<&Jwk> {
        self.keys.iter().map(|e| e.as_ref()).collect()
    }

    pub fn push_key(&mut self, jwk: Jwk) {
        match self.params.get_mut("keys") {
            Some(Value::Array(keys)) => {
                keys.push(Value::Object(jwk.as_ref().clone()));
            }
            _ => unreachable!(),
        }

        let jwk = Arc::new(jwk);
        if let Some(kid) = jwk.kid() {
            self.kid_map
                .insert((kid.to_string(), self.keys.len()), Arc::clone(&jwk));
        }
        self.keys.push(jwk);
    }

    pub fn remove_key(&mut self, jwk: &Jwk) {
        let index = self.keys.iter().position(|e| e.as_ref() == jwk);
        if let Some(index) = index {
            match self.params.get_mut("keys") {
                Some(Value::Array(keys)) => {
                    keys.remove(index);
                }
                _ => unreachable!(),
            }
            self.keys.remove(index);
        }
    }
}

impl AsRef<Map<String, Value>> for JwkSet {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.params
    }
}

impl Into<Map<String, Value>> for JwkSet {
    fn into(self) -> Map<String, Value> {
        self.params
    }
}

impl Display for JwkSet {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str("{\"keys\":[")?;

        for (i, jwk) in self.keys.iter().enumerate() {
            if i > 0 {
                fmt.write_str(",")?;
            }

            let map: &Map<String, Value> = &jwk.as_ref().as_ref();
            let val = serde_json::to_string(map).map_err(|_e| std::fmt::Error {})?;
            fmt.write_str(&val)?;
        }

        fmt.write_str("]}")?;

        Ok(())
    }
}

pub trait KeyPair: Debug + Send + Sync {
    /// Return the applicatable algorithm.
    fn algorithm(&self) -> Option<&str>;

    /// Return the applicatable key ID.
    fn kid(&self) -> Option<&str>;

    fn to_der_private_key(&self) -> Vec<u8>;
    fn to_der_public_key(&self) -> Vec<u8>;
    fn to_pem_private_key(&self) -> Vec<u8>;
    fn to_pem_public_key(&self) -> Vec<u8>;
    fn to_jwk_private_key(&self) -> Jwk;
    fn to_jwk_public_key(&self) -> Jwk;
    fn to_jwk_key_pair(&self) -> Jwk;

    fn box_clone(&self) -> Box<dyn KeyPair>;
}

impl PartialEq for Box<dyn KeyPair> {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for Box<dyn KeyPair> {}

impl Clone for Box<dyn KeyPair> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyAlg {
    Rsa,
    RsaPss {
        hash: Option<HashAlgorithm>,
        mgf1_hash: Option<HashAlgorithm>,
        salt_len: Option<u8>,
    },
    Ec {
        curve: Option<EcCurve>,
    },
    Ed {
        curve: Option<EdCurve>,
    },
    Ecx {
        curve: Option<EcxCurve>,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyFormat {
    Der { raw: bool },
    Pem { traditional: bool },
    Jwk,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyInfo {
    format: KeyFormat,
    alg: Option<KeyAlg>,
    is_public_key: bool,
}

impl KeyInfo {
    pub fn format(&self) -> KeyFormat {
        self.format
    }

    pub fn alg(&self) -> Option<KeyAlg> {
        self.alg
    }

    pub fn is_public_key(&self) -> bool {
        self.is_public_key
    }

    pub fn detect(input: &impl AsRef<[u8]>) -> Option<KeyInfo> {
        let input = input.as_ref();
        if input.len() == 0 {
            return None;
        }

        let key_info = match input[0] {
            // DER
            b'\x30' => Self::detect_from_der(input)?,
            // PEM
            b'-' => {
                let (alg, data) = util::parse_pem(input.as_ref()).ok()?;
                match alg.as_str() {
                    "PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key() {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: false },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "RSA PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key() || !matches!(key_info.alg(), Some(KeyAlg::Rsa))
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "RSA-PSS PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key()
                            || !matches!(
                                key_info.alg(),
                                Some(KeyAlg::RsaPss {
                                    hash: _,
                                    mgf1_hash: _,
                                    salt_len: _,
                                })
                            )
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "EC PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key()
                            || !matches!(key_info.alg(), Some(KeyAlg::Ec { curve: _ }))
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "ED25519 PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key()
                            || !matches!(
                                key_info.alg(),
                                Some(KeyAlg::Ed {
                                    curve: Some(EdCurve::Ed25519)
                                })
                            )
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "ED448 PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key()
                            || !matches!(
                                key_info.alg(),
                                Some(KeyAlg::Ed {
                                    curve: Some(EdCurve::Ed448)
                                })
                            )
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "X25519 PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key()
                            || !matches!(
                                key_info.alg(),
                                Some(KeyAlg::Ecx {
                                    curve: Some(EcxCurve::X25519)
                                })
                            )
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "X448 PRIVATE KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if key_info.is_public_key()
                            || !matches!(
                                key_info.alg(),
                                Some(KeyAlg::Ecx {
                                    curve: Some(EcxCurve::X448)
                                })
                            )
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "PUBLIC KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if !key_info.is_public_key() {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: false },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    "RSA PUBLIC KEY" => {
                        let key_info = Self::detect_from_der(&data)?;
                        if !key_info.is_public_key() || !matches!(key_info.alg(), Some(KeyAlg::Rsa))
                        {
                            return None;
                        }

                        KeyInfo {
                            format: KeyFormat::Pem { traditional: true },
                            alg: key_info.alg(),
                            is_public_key: key_info.is_public_key(),
                        }
                    }
                    _ => return None,
                }
            }
            // JWK
            _ => {
                let jwk = Jwk::from_bytes(input).ok()?;
                match jwk.key_type() {
                    "oct" => KeyInfo {
                        format: KeyFormat::Jwk,
                        alg: None,
                        is_public_key: false,
                    },
                    "RSA" => {
                        let is_public_key = matches!(jwk.parameter("d"), None);

                        KeyInfo {
                            format: KeyFormat::Jwk,
                            alg: Some(KeyAlg::Rsa),
                            is_public_key: is_public_key,
                        }
                    }
                    "EC" => {
                        let alg = match jwk.curve() {
                            Some("P-256") => Some(KeyAlg::Ec {
                                curve: Some(EcCurve::P256),
                            }),
                            Some("P-384") => Some(KeyAlg::Ec {
                                curve: Some(EcCurve::P384),
                            }),
                            Some("P-521") => Some(KeyAlg::Ec {
                                curve: Some(EcCurve::P521),
                            }),
                            Some("secp256k1") => Some(KeyAlg::Ec {
                                curve: Some(EcCurve::Secp256k1),
                            }),
                            Some(_) => Some(KeyAlg::Ec { curve: None }),
                            None => return None,
                        };
                        let is_public_key = matches!(jwk.parameter("d"), None);

                        KeyInfo {
                            format: KeyFormat::Jwk,
                            alg,
                            is_public_key,
                        }
                    }
                    "OKP" => {
                        let alg = match jwk.curve() {
                            Some("Ed25519") => Some(KeyAlg::Ed {
                                curve: Some(EdCurve::Ed25519),
                            }),
                            Some("Ed448") => Some(KeyAlg::Ed {
                                curve: Some(EdCurve::Ed448),
                            }),
                            Some("X25519") => Some(KeyAlg::Ecx {
                                curve: Some(EcxCurve::X25519),
                            }),
                            Some("X448") => Some(KeyAlg::Ecx {
                                curve: Some(EcxCurve::X448),
                            }),
                            Some(_) => None,
                            None => return None,
                        };
                        let is_public_key = matches!(jwk.parameter("d"), None);

                        KeyInfo {
                            format: KeyFormat::Jwk,
                            alg,
                            is_public_key,
                        }
                    }
                    _ => KeyInfo {
                        format: KeyFormat::Jwk,
                        alg: None,
                        is_public_key: false,
                    },
                }
            }
        };

        Some(key_info)
    }

    fn detect_from_der(input: &[u8]) -> Option<KeyInfo> {
        let mut reader = DerReader::from_reader(input);

        match reader.next().ok()? {
            Some(DerType::Sequence) => {}
            _ => return None,
        }

        let key_info = match reader.next().ok()? {
            Some(DerType::Sequence) => match reader.next().ok()? {
                Some(DerType::ObjectIdentifier) => match reader.to_object_identifier().ok()? {
                    val if val == *OID_RSA_ENCRYPTION => KeyInfo {
                        format: KeyFormat::Der { raw: false },
                        alg: Some(KeyAlg::Rsa),
                        is_public_key: true,
                    },
                    val if val == *OID_RSASSA_PSS => {
                        let (hash, mgf1_hash, salt_len) =
                            Self::parse_rsa_pss_params(&mut reader).ok()?;

                        KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::RsaPss {
                                hash,
                                mgf1_hash,
                                salt_len,
                            }),
                            is_public_key: true,
                        }
                    }
                    val if val == *OID_ID_EC_PUBLIC_KEY => {
                        let curve = match reader.next().ok()? {
                            Some(DerType::ObjectIdentifier) => {
                                match reader.to_object_identifier().ok()? {
                                    val if val == *OID_PRIME256V1 => Some(EcCurve::P256),
                                    val if val == *OID_SECP384R1 => Some(EcCurve::P384),
                                    val if val == *OID_SECP521R1 => Some(EcCurve::P521),
                                    val if val == *OID_SECP256K1 => Some(EcCurve::Secp256k1),
                                    _ => None,
                                }
                            }
                            _ => None,
                        };

                        KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::Ec { curve }),
                            is_public_key: true,
                        }
                    }
                    val if val == *OID_ED25519 => KeyInfo {
                        format: KeyFormat::Der { raw: false },
                        alg: Some(KeyAlg::Ed {
                            curve: Some(EdCurve::Ed25519),
                        }),
                        is_public_key: true,
                    },
                    val if val == *OID_ED448 => KeyInfo {
                        format: KeyFormat::Der { raw: false },
                        alg: Some(KeyAlg::Ed {
                            curve: Some(EdCurve::Ed448),
                        }),
                        is_public_key: true,
                    },
                    val if val == *OID_X25519 => KeyInfo {
                        format: KeyFormat::Der { raw: false },
                        alg: Some(KeyAlg::Ecx {
                            curve: Some(EcxCurve::X25519),
                        }),
                        is_public_key: true,
                    },
                    val if val == *OID_X448 => KeyInfo {
                        format: KeyFormat::Der { raw: false },
                        alg: Some(KeyAlg::Ecx {
                            curve: Some(EcxCurve::X448),
                        }),
                        is_public_key: true,
                    },
                    _ => KeyInfo {
                        format: KeyFormat::Der { raw: false },
                        alg: None,
                        is_public_key: true,
                    },
                },
                _ => return None,
            },
            Some(DerType::Integer) => match reader.next().ok()? {
                Some(DerType::Sequence) => match reader.next().ok()? {
                    Some(DerType::ObjectIdentifier) => match reader.to_object_identifier().ok()? {
                        val if val == *OID_RSA_ENCRYPTION => KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::Rsa),
                            is_public_key: false,
                        },
                        val if val == *OID_RSASSA_PSS => {
                            let (hash, mgf1_hash, salt_len) =
                                Self::parse_rsa_pss_params(&mut reader).ok()?;

                            KeyInfo {
                                format: KeyFormat::Der { raw: false },
                                alg: Some(KeyAlg::RsaPss {
                                    hash,
                                    mgf1_hash,
                                    salt_len,
                                }),
                                is_public_key: false,
                            }
                        }
                        val if val == *OID_ID_EC_PUBLIC_KEY => {
                            let curve = match reader.next().ok()? {
                                Some(DerType::ObjectIdentifier) => {
                                    match reader.to_object_identifier().ok()? {
                                        val if val == *OID_PRIME256V1 => Some(EcCurve::P256),
                                        val if val == *OID_SECP384R1 => Some(EcCurve::P384),
                                        val if val == *OID_SECP521R1 => Some(EcCurve::P521),
                                        val if val == *OID_SECP256K1 => Some(EcCurve::Secp256k1),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            };

                            KeyInfo {
                                format: KeyFormat::Der { raw: false },
                                alg: Some(KeyAlg::Ec { curve }),
                                is_public_key: false,
                            }
                        }
                        val if val == *OID_ED25519 => KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::Ed {
                                curve: Some(EdCurve::Ed25519),
                            }),
                            is_public_key: false,
                        },
                        val if val == *OID_ED448 => KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::Ed {
                                curve: Some(EdCurve::Ed448),
                            }),
                            is_public_key: false,
                        },
                        val if val == *OID_X25519 => KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::Ecx {
                                curve: Some(EcxCurve::X25519),
                            }),
                            is_public_key: false,
                        },
                        val if val == *OID_X448 => KeyInfo {
                            format: KeyFormat::Der { raw: false },
                            alg: Some(KeyAlg::Ecx {
                                curve: Some(EcxCurve::X448),
                            }),
                            is_public_key: false,
                        },
                        _ => return None,
                    },
                    _ => return None,
                },
                Some(DerType::Integer) => {
                    if let Some(DerType::EndOfContents) = reader.next().ok()? {
                        KeyInfo {
                            format: KeyFormat::Der { raw: true },
                            alg: Some(KeyAlg::Rsa),
                            is_public_key: true,
                        }
                    } else {
                        KeyInfo {
                            format: KeyFormat::Der { raw: true },
                            alg: Some(KeyAlg::Rsa),
                            is_public_key: false,
                        }
                    }
                }
                Some(DerType::OctetString) => {
                    let curve = match reader.next().ok()? {
                        Some(DerType::Other(DerClass::ContextSpecific, 0)) => {
                            match reader.next().ok()? {
                                Some(DerType::ObjectIdentifier) => {
                                    match reader.to_object_identifier().ok()? {
                                        val if val == *OID_PRIME256V1 => Some(EcCurve::P256),
                                        val if val == *OID_SECP384R1 => Some(EcCurve::P384),
                                        val if val == *OID_SECP521R1 => Some(EcCurve::P521),
                                        val if val == *OID_SECP256K1 => Some(EcCurve::Secp256k1),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };

                    KeyInfo {
                        format: KeyFormat::Der { raw: true },
                        alg: Some(KeyAlg::Ec { curve }),
                        is_public_key: false,
                    }
                }
                _ => return None,
            },
            _ => return None,
        };

        Some(key_info)
    }

    fn parse_rsa_pss_params(
        reader: &mut DerReader<&[u8]>,
    ) -> Result<(Option<HashAlgorithm>, Option<HashAlgorithm>, Option<u8>), DerError> {
        let mut hash = Some(HashAlgorithm::Sha1);
        let mut mgf1_hash = Some(HashAlgorithm::Sha1);
        let mut salt_len = Some(20);

        if let Some(DerType::Sequence) = reader.next()? {
            while let Some(DerType::Other(DerClass::ContextSpecific, i)) = reader.next()? {
                if i == 0 {
                    match reader.next()? {
                        Some(DerType::Sequence) => {}
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::ObjectIdentifier) => match reader.to_object_identifier()? {
                            val if val == *OID_SHA1 => hash = Some(HashAlgorithm::Sha1),
                            val if val == *OID_SHA256 => hash = Some(HashAlgorithm::Sha256),
                            val if val == *OID_SHA384 => hash = Some(HashAlgorithm::Sha384),
                            val if val == *OID_SHA512 => hash = Some(HashAlgorithm::Sha512),
                            _ => hash = None,
                        },
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::EndOfContents) => {}
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::EndOfContents) => {}
                        _ => break,
                    }
                } else if i == 1 {
                    match reader.next()? {
                        Some(DerType::Sequence) => {}
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::ObjectIdentifier) => match reader.to_object_identifier()? {
                            val if val == *OID_MGF1 => {}
                            _ => break,
                        },
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::Sequence) => {}
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::ObjectIdentifier) => match reader.to_object_identifier()? {
                            val if val == *OID_SHA1 => mgf1_hash = Some(HashAlgorithm::Sha1),
                            val if val == *OID_SHA256 => mgf1_hash = Some(HashAlgorithm::Sha256),
                            val if val == *OID_SHA384 => mgf1_hash = Some(HashAlgorithm::Sha384),
                            val if val == *OID_SHA512 => mgf1_hash = Some(HashAlgorithm::Sha512),
                            _ => mgf1_hash = None,
                        },
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::EndOfContents) => {}
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::EndOfContents) => {}
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::EndOfContents) => {}
                        _ => break,
                    }
                } else if i == 2 {
                    match reader.next()? {
                        Some(DerType::Integer) => match reader.to_u8()? {
                            val => salt_len = Some(val),
                        },
                        _ => break,
                    }

                    match reader.next()? {
                        Some(DerType::EndOfContents) => {}
                        _ => break,
                    }
                } else {
                    reader.skip_contents()?;
                }
            }
        }

        Ok((hash, mgf1_hash, salt_len))
    }
}
