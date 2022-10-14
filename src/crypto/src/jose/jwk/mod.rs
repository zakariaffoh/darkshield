use std::collections::HashMap;

pub trait Jwk {
    fn kid(&self) -> &str;

    fn kty(&self) -> &str;

    fn alg(&self) -> &str;

    fn key_use(&self) -> &str;

    fn claims(&self) -> &Option<HashMap<String, String>>;
}

#[allow(dead_code)]
pub struct EcJwk {
    kid: String,
    kty: String,
    alg: String,
    key_use: String,
    claims: Option<HashMap<String, String>>,
    crv: String,
    x: String,
    y: String,
}

impl EcJwk {
    pub fn new(
        kid: &str,
        kty: &str,
        alg: &str,
        key_use: &str,
        claims: Option<HashMap<String, String>>,
        crv: &str,
        x: &str,
        y: &str,
    ) -> Self {
        Self {
            kid: kid.to_owned(),
            kty: kty.to_owned(),
            alg: alg.to_owned(),
            key_use: key_use.to_owned(),
            claims: claims,
            crv: crv.to_owned(),
            x: x.to_owned(),
            y: x.to_owned(),
        }
    }
}

impl Jwk for EcJwk {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn kty(&self) -> &str {
        &self.kty
    }

    fn alg(&self) -> &str {
        &self.alg
    }

    fn key_use(&self) -> &str {
        &self.key_use
    }

    fn claims(&self) -> &Option<HashMap<String, String>> {
        &self.claims
    }
}

#[allow(dead_code)]
pub struct RSAJwk {
    kid: String,
    kty: String,
    alg: String,
    key_use: String,
    claims: Option<HashMap<String, String>>,
    n: String,
    e: String,
    x5c: Option<Vec<String>>,
    x5t: Option<String>,
    x5t_s256: Option<String>,
}

impl RSAJwk {
    pub fn new(
        kid: &str,
        kty: &str,
        alg: &str,
        key_use: &str,
        claims: Option<HashMap<String, String>>,
        n: &str,
        e: &str,
        x5c: Option<Vec<String>>,
        x5t: Option<String>,
        x5t_s256: Option<String>,
    ) -> Self {
        Self {
            kid: kid.to_owned(),
            kty: kty.to_owned(),
            alg: alg.to_owned(),
            key_use: key_use.to_owned(),
            claims: claims,
            n: n.to_owned(),
            e: e.to_owned(),
            x5c: x5c,
            x5t: x5t,
            x5t_s256: x5t_s256,
        }
    }
}

impl Jwk for RSAJwk {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn kty(&self) -> &str {
        &self.kty
    }

    fn alg(&self) -> &str {
        &self.alg
    }

    fn key_use(&self) -> &str {
        &self.key_use
    }

    fn claims(&self) -> &Option<HashMap<String, String>> {
        &self.claims
    }
}
