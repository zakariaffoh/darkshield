use std::fmt::Display;

use base64_url::base64;
use serde_json::{Map, Value};
use std::ops::Deref;

use crate::jose::{jwk::Jwk, JoseError, JoseHeader};

use super::jws_header::JwsHeader;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JwsHeaderSet {
    protected: Map<String, Value>,
    unprotected: Map<String, Value>,
}

impl JwsHeaderSet {
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
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for JWK header claim (jwk).
    ///
    /// # Arguments
    ///
    /// * `value` - a JWK
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

    pub fn set_base64url_encode_payload(&mut self, value: bool) {
        let key = "b64";
        self.unprotected.remove(key);
        self.protected.insert(key.to_string(), Value::Bool(value));
    }

    pub fn base64url_encode_payload(&self) -> Option<bool> {
        match self.claim("b64") {
            Some(Value::Bool(val)) => Some(*val),
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

    pub fn set_claim(
        &mut self,
        key: &str,
        value: Option<Value>,
        protection: bool,
    ) -> Result<(), JoseError> {
        match value {
            Some(val) => {
                JwsHeader::check_claim(key, &val)?;
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

impl JoseHeader for JwsHeaderSet {
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

impl Display for JwsHeaderSet {
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

impl Deref for JwsHeaderSet {
    type Target = dyn JoseHeader;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::json;

    use crate::jose::{jwk::Jwk, jws::jws_header::JwsHeader};

    #[test]
    fn test_new_jws_header() -> Result<()> {
        let mut header = JwsHeader::new();
        let jwk = Jwk::new("oct");
        header.set_jwk_set_url("jku");
        header.set_jwk(jwk.clone());
        header.set_x509_url("x5u");
        header.set_x509_certificate_chain(&vec![b"x5c0", b"x5c1"]);
        header.set_x509_certificate_sha1_thumbprint(b"x5t");
        header.set_x509_certificate_sha256_thumbprint(b"x5t#S256");
        header.set_kid("kid");
        header.set_token_type("typ");
        header.set_content_type("cty");
        header.set_critical(&vec!["crit0", "crit1"]);
        header.set_url("url");
        header.set_nonce(b"nonce");
        header.set_claim("header_claim", Some(json!("header_claim")))?;

        assert!(matches!(header.jwk_set_url(), Some("jku")));
        assert!(matches!(header.jwk(), Some(val) if val == jwk));
        assert!(matches!(header.x509_url(), Some("x5u")));
        assert!(
            matches!(header.x509_certificate_chain(), Some(vals) if vals == vec![
                b"x5c0".to_vec(),
                b"x5c1".to_vec(),
            ])
        );
        assert!(
            matches!(header.x509_certificate_sha1_thumbprint(), Some(val) if val == b"x5t".to_vec())
        );
        assert!(
            matches!(header.x509_certificate_sha256_thumbprint(), Some(val) if val == b"x5t#S256".to_vec())
        );
        assert!(matches!(header.kid(), Some("kid")));
        assert!(matches!(header.token_type(), Some("typ")));
        assert!(matches!(header.content_type(), Some("cty")));
        assert!(matches!(header.url(), Some("url")));
        assert!(matches!(header.nonce(), Some(val) if val == b"nonce".to_vec()));
        assert!(matches!(header.critical(), Some(vals) if vals == vec!["crit0", "crit1"]));
        assert!(matches!(header.claim("header_claim"), Some(val) if val == &json!("header_claim")));

        Ok(())
    }
}
