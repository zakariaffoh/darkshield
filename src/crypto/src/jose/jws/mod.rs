use std::{collections::HashMap, str};

use commons::tokens::{
    AccessToken, AccessTokenImp, AuthorizationResponseToken, AuthorizationResponseTokenImp,
    IdToken, IdTokenImp, JsonWebToken, JsonWebTokenImp, JwtClaimValue, LogoutToken, LogoutTokenImp,
    RefreshToken, RefreshTokenImp,
};

use crate::core::keys::{PrivateKey, PublicKey};
use crate::providers::sig::SignatureSignerContext;

use super::{Jose, JoseHeader};

pub struct JwsHeader {
    algorithm: Option<String>,
    header_type: Option<String>,
    kid: Option<String>,
    content_type: Option<String>,
}

impl JoseHeader for JwsHeader {
    fn algorithm(&self) -> &Option<String> {
        &self.algorithm
    }

    fn kid(&self) -> &Option<String> {
        &self.kid
    }
}

impl Default for JwsHeader {
    fn default() -> Self {
        Self {
            algorithm: Default::default(),
            header_type: Default::default(),
            kid: Default::default(),
            content_type: Default::default(),
        }
    }
}

impl JwsHeader {
    pub fn new(
        algorithm: Option<String>,
        header_type: Option<String>,
        kid: Option<String>,
        content_type: Option<String>,
    ) -> Self {
        Self {
            algorithm: algorithm,
            header_type: header_type,
            kid: kid,
            content_type: content_type,
        }
    }

    pub fn algorithm(&self) -> &Option<String> {
        &self.algorithm
    }

    pub fn header_type(&self) -> &Option<String> {
        &self.header_type
    }

    pub fn kid(&self) -> &Option<String> {
        &self.kid
    }

    pub fn content_type(&self) -> &Option<String> {
        &self.content_type
    }

    pub fn dict(&self) -> HashMap<String, Option<String>> {
        let mut res = HashMap::new();
        res.insert("alg".to_owned(), self.algorithm.clone());
        res.insert("typ".to_owned(), self.header_type.clone());
        res.insert("cty".to_owned(), self.content_type.clone());
        res.insert("kid".to_owned(), self.kid.clone());
        res
    }

    pub fn from(header: &serde_json::Value) -> JwsHeader {
        let attr_getter = |attr: &str| {
            let res = header.get(attr);
            match res {
                Some(d) => {
                    if d.is_string() {
                        return d.as_str().map(|r| r.to_owned());
                    }
                    return None;
                }
                _ => None,
            }
        };

        return JwsHeader::new(
            attr_getter("alg"),
            attr_getter("typ"),
            attr_getter("kid"),
            attr_getter("cty"),
        );
    }
}

pub struct JwsBuilder {
    jws_type: Option<String>,
    kid: Option<String>,
    content_type: Option<String>,
    content_bytes: Vec<u8>,
}

#[allow(dead_code)]
impl JwsBuilder {
    pub fn new() -> Self {
        Self {
            jws_type: Default::default(),
            kid: Default::default(),
            content_type: Default::default(),
            content_bytes: Default::default(),
        }
    }

    pub fn with_jwt_type(&mut self, jws_type: Option<String>) -> &mut Self {
        self.jws_type = jws_type;
        self
    }

    pub fn with_kid(&mut self, kid: Option<String>) -> &mut Self {
        self.kid = kid;
        self
    }

    pub fn with_content_type(&mut self, content_type: Option<String>) -> &mut Self {
        self.content_type = content_type;
        self
    }

    pub fn with_content(&mut self, content: Vec<u8>) -> &mut Self {
        self.content_bytes = content;
        self
    }

    fn encode_header(&self, sig_alg_name: &str) -> String {
        let mut map = HashMap::new();
        map.insert("alg".to_owned(), sig_alg_name.to_owned());
        if self.content_type.is_some() {
            map.insert("typ".to_owned(), self.content_type.clone().unwrap());
        }
        if self.kid.is_some() {
            map.insert("kid".to_owned(), self.kid.clone().unwrap());
        }
        if self.content_type.is_some() {
            map.insert("cty".to_owned(), self.content_type.clone().unwrap());
        }
        serde_json::to_string(&map).unwrap()
    }

    fn encode_all(&self, pre_encoded_jws: &str, signature: Option<&[u8]>) -> String {
        if let Some(sig) = signature {
            let enc_sig = base64_url::encode(str::from_utf8(&sig).unwrap());
            format!("{}.{}", pre_encoded_jws.to_owned(), enc_sig)
        } else {
            pre_encoded_jws.to_owned()
        }
    }

    pub fn marshal_content(&self) -> &Vec<u8> {
        &self.content_bytes
    }

    pub fn encode(&self, algorithm: &str, data: &Vec<u8>) -> String {
        format!(
            "{}.{}",
            base64_url::encode(&self.encode_header(algorithm)),
            base64_url::encode(str::from_utf8(&data).unwrap())
        )
    }

    pub fn unsecure_jws(&self) -> String {
        let data = self.marshal_content();
        let encoding_jws_str = self.encode("none", data);
        self.encode_all(&encoding_jws_str, None)
    }

    async fn sign(&mut self, signer: &dyn SignatureSignerContext) -> Result<String, String> {
        self.kid = signer.kid().await;
        let algorithm = signer.algorithm().await;
        let data = self.marshal_content();
        let encoding_jws_str = self.encode(&algorithm, data);
        let signature = signer.sign(&encoding_jws_str).await;
        match signature {
            Ok(sig) => {
                let sig_bytes = Some(sig.as_bytes());
                return Ok(self.encode_all(&encoding_jws_str, sig_bytes));
            }
            Err(err) => {
                return Err(err);
            }
        }
    }
}

#[allow(dead_code)]
pub struct JwsInput {
    jws_token: Option<String>,
    encoded_header: Option<String>,
    encoded_content: Option<String>,
    encoded_signature: Option<String>,
    encoded_signature_input: Option<String>,
    header: JwsHeader,
    content: Option<Vec<u8>>,
    content_str: Option<String>,
    signature: Option<Vec<u8>>,
}

impl Jose for JwsInput {
    fn header(&self) -> &dyn JoseHeader {
        &self.header
    }
}

impl JwsInput {
    pub fn new(jws_token: &str) -> Result<Self, String> {
        let mut input = Self {
            jws_token: Default::default(),
            encoded_header: Default::default(),
            encoded_content: Default::default(),
            encoded_signature: Default::default(),
            encoded_signature_input: Default::default(),
            header: Default::default(),
            content: Default::default(),
            content_str: Default::default(),
            signature: Default::default(),
        };

        input.jws_token = Some(jws_token.to_owned());
        let jws_tokens: Vec<_> = jws_token.split(".").collect();
        if jws_tokens.len() != 2 && jws_tokens.len() != 3 {
            return Err("invalid jws parse error".to_owned());
        }
        input.encoded_header = Some(jws_tokens[0].to_owned());
        input.encoded_content = Some(jws_tokens[1].to_owned());
        input.encoded_signature_input = Some(format!("{}.{}", jws_tokens[0], jws_tokens[1]));
        match base64_url::decode(jws_tokens[1]) {
            Ok(content) => {
                input.content = Some(content.clone());
                input.content_str = Some(str::from_utf8(&content).unwrap().to_string());
            }
            Err(err) => {
                return Err(err.to_string());
            }
        }
        if jws_tokens.len() > 2 {
            input.encoded_signature = Some(jws_tokens[2].to_owned());
            match base64_url::decode(jws_tokens[2]) {
                Ok(signature) => {
                    input.signature = Some(signature);
                }
                Err(err) => {
                    return Err(err.to_string());
                }
            }
        }
        match base64_url::decode(jws_tokens[0]) {
            Ok(decoded_header) => {
                let header_dict = serde_json::to_value(decoded_header);
                if let Err(err) = header_dict {
                    return Err(err.to_string());
                }
                let header_value = header_dict.unwrap();
                input.header = JwsHeader::from(&header_value);
                return Ok(input);
            }
            Err(err) => {
                return Err(err.to_string());
            }
        }
    }

    pub fn jws_token(&self) -> &Option<String> {
        &self.jws_token
    }

    pub fn encoded_header(&self) -> &Option<String> {
        &self.encoded_header
    }

    pub fn encoded_content(&self) -> &Option<String> {
        &self.encoded_content
    }

    pub fn encoded_signature(&self) -> &Option<String> {
        &self.encoded_signature
    }

    pub fn encoded_signature_input(&self) -> &Option<String> {
        &self.encoded_signature_input
    }

    pub fn signature(&self) -> &Option<Vec<u8>> {
        &self.signature
    }

    pub fn content(&self) -> &Option<Vec<u8>> {
        &self.content
    }

    pub fn read_as_json_node(&self) -> serde_json::Value {
        serde_json::to_value(&self.content).unwrap()
    }

    pub fn read_as<T>(&self, type_name: &str) -> Result<Box<dyn JsonWebToken>, String>
    where
        T: JsonWebToken,
    {
        type ClaimMap = HashMap<String, JwtClaimValue>;
        if self.content_str.is_none() {
            return Err("Invalid content".to_owned());
        }

        let json_claim =
            serde_json::from_str::<ClaimMap>(&self.content_str.as_ref().unwrap()).unwrap();
        if type_name == "jwt" {
            let mut jwt = JsonWebTokenImp::new();
            <JsonWebTokenImp as JsonWebToken>::parse(&mut jwt, &json_claim);
        }
        if type_name == "id_token" {
            let mut id_token = IdTokenImp::new();
            <IdTokenImp as IdToken>::parse(&mut id_token, &json_claim);
            return Ok(Box::new(id_token));
        }
        if type_name == "access_token" {
            let mut access_token = AccessTokenImp::new();
            <AccessTokenImp as AccessToken>::parse(&mut access_token, &json_claim);
            return Ok(Box::new(access_token));
        }
        if type_name == "refresh_token" {
            let mut refresh_token = RefreshTokenImp::new();
            <RefreshTokenImp as RefreshToken>::parse(&mut refresh_token, &json_claim);
            return Ok(Box::new(refresh_token));
        }
        if type_name == "logout_token" {
            let mut logout_token = LogoutTokenImp::new();
            <LogoutTokenImp as LogoutToken>::parse(&mut logout_token, &json_claim);
            return Ok(Box::new(logout_token));
        }
        if type_name == "authorization_response_token" {
            let mut response_token = AuthorizationResponseTokenImp::new();
            <AuthorizationResponseTokenImp as AuthorizationResponseToken>::parse(
                &mut response_token,
                &json_claim,
            );
            return Ok(Box::new(response_token));
        }
        return Err(format!("Unsupported token type {}", type_name));
    }
}

pub trait SignatureProvider {
    fn verify(&self, input_jws: &JwsInput, key: &str) -> bool;
}

pub struct RsaSignatureProvider;

impl RsaSignatureProvider {
    fn verify_via_certificate(&self, _input_jws: &JwsInput, _key: &str) -> bool {
        true
    }

    pub fn verify_with_public_key(&self, input_jws: &JwsInput, public_key: &dyn PublicKey) -> bool {
        return true;
    }

    pub fn sign(&self, data: &[u8], algorithm: &str, private_key: &dyn PrivateKey) -> &[u8] {
        "".as_bytes()
    }
}

impl SignatureProvider for RsaSignatureProvider {
    fn verify(&self, input_jws: &JwsInput, key: &str) -> bool {
        self.verify_via_certificate(input_jws, key)
    }
}
