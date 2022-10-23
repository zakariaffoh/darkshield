use std::{
    fmt::Display,
    io::Read,
    time::{Duration, SystemTime},
};

use crate::tokens::token::TokenCategoryEnum;
use crate::tokens::{jwt_error::JwtError, token::Token};
use anyhow::bail;
use serde_json::{Map, Number, Value};

use super::{json_web_token::JsonWebToken, Jwt, LogoutToken};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct LogoutTokenImp {
    claims: Map<String, Value>,
}

#[allow(dead_code)]
impl LogoutTokenImp {
    pub fn new() -> Self {
        Self { claims: Map::new() }
    }

    fn into_map(self) -> Map<String, Value> {
        self.claims
    }

    pub fn from_map(claims_map: impl Into<Map<String, Value>>) -> Result<Self, JwtError> {
        let map: Map<String, Value> = claims_map.into();
        for (key, value) in &map {
            Self::check_claim(key, value)?;
        }
        Ok(Self { claims: map })
    }

    pub fn from_reader(input: &mut dyn Read) -> Result<Self, JwtError> {
        (|| -> anyhow::Result<Self> {
            let map: Map<String, Value> = serde_json::from_reader(input)?;
            Ok(Self::from_map(map)?)
        })()
        .map_err(|err| match err.downcast::<JwtError>() {
            Ok(err) => err,
            Err(err) => JwtError::InvalidJwtFormat(err),
        })
    }

    pub fn from_bytes(input: impl AsRef<[u8]>) -> Result<Self, JwtError> {
        (|| -> anyhow::Result<Self> {
            let map: Map<String, Value> = serde_json::from_slice(input.as_ref())?;
            Ok(Self::from_map(map)?)
        })()
        .map_err(|err| match err.downcast::<JwtError>() {
            Ok(err) => err,
            Err(err) => JwtError::InvalidJwtFormat(err),
        })
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

    pub fn set_session_id(&mut self, session_id: impl Into<String>) {
        let value: String = session_id.into();
        self.claims.insert("sid".to_string(), Value::String(value));
    }

    pub fn set_events(&mut self, events: Map<String, Value>) {
        self.claims
            .insert("events".to_string(), Value::Object(events));
    }

    pub fn add_event(&mut self, event_key: String, event_value: Value) {
        match self.claims.get("events") {
            Some(events) => match events {
                Value::Object(evs) => {
                    let mut events_map = Map::new();
                    for (key, val) in evs {
                        events_map.insert(key.to_string(), val.clone());
                    }
                    events_map.insert(event_key, event_value);
                    self.claims.remove("events");
                    self.claims
                        .insert("events".to_owned(), Value::Object(events_map));
                }
                _ => {
                    let mut events_map = Map::new();
                    events_map.insert(event_key, event_value);
                    self.claims
                        .insert("events".to_owned(), Value::Object(events_map));
                }
            },
            _ => {
                let mut events_map = Map::new();
                events_map.insert(event_key, event_value);
                self.claims
                    .insert("events".to_owned(), Value::Object(events_map));
            }
        }
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

    fn check_claim(key: &str, value: &Value) -> Result<(), JwtError> {
        (|| -> anyhow::Result<()> {
            match key {
                "iss" | "sub" | "jti" | "sid" => match &value {
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
                "events" => match &value {
                    Value::Object(resources) => {
                        for (key, resource_value) in resources {
                            match resource_value {
                                Value::Object(_) => {}
                                _ => bail!("The JWT {} payload claim must be an object map.", key),
                            }
                        }
                    }
                    _ => bail!("The JWT {} header claim must be an object map.", key),
                },
                "exp" | "nbf" | "iat" => match &value {
                    Value::Number(val) => match val.as_u64() {
                        Some(_) => {}
                        None => bail!(
                            "The JWT {} payload claim must be a positive integer within 64bit.",
                            key
                        ),
                    },
                    _ => bail!("The JWT {} header claim must be a string.", key),
                },
                _ => {}
            }

            Ok(())
        })()
        .map_err(|err| JwtError::InvalidJwtFormat(err))
    }
}

impl Jwt for LogoutTokenImp {
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

impl Token for LogoutTokenImp {
    fn category(&self) -> TokenCategoryEnum {
        TokenCategoryEnum::Logout
    }
}

impl LogoutToken for LogoutTokenImp {
    fn session_id(&self) -> Option<&str> {
        match self.claims.get("sid") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn events(&self) -> Option<&Map<String, Value>> {
        match self.claims.get("events") {
            Some(Value::Object(val)) => Some(val),
            _ => None,
        }
    }
}

impl AsRef<Map<String, Value>> for LogoutTokenImp {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.claims
    }
}

impl Into<Map<String, Value>> for LogoutTokenImp {
    fn into(self) -> Map<String, Value> {
        self.into_map()
    }
}

impl TryInto<JsonWebToken> for LogoutTokenImp {
    type Error = JwtError;

    fn try_into(self) -> Result<JsonWebToken, Self::Error> {
        JsonWebToken::from_map(self.into_map())
    }
}

impl Display for LogoutTokenImp {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let val = serde_json::to_string(&self.claims).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str(&val)
    }
}
