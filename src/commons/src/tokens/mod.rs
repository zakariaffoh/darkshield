use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str;

pub enum TokenCategoryEnum {
    Id,
    Access,
    Internal,
    Admin,
    UserInfo,
    Logout,
    AuthorizationResponse,
}

pub trait Token {
    fn category(&self) -> TokenCategoryEnum;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClaimValue {
    Int(i64),
    Str(String),
    Bool(bool),
    VecStr(Vec<String>),
}

impl ClaimValue {
    pub fn int(&self) -> Option<i64> {
        match &self {
            ClaimValue::Int(it) => Some(*it),
            _ => None,
        }
    }

    pub fn str(&self) -> Option<String> {
        match &self {
            ClaimValue::Str(str) => Some(str.to_owned()),
            _ => None,
        }
    }

    pub fn int_value(value: Option<&ClaimValue>) -> Option<i64> {
        if let Some(claim) = value {
            match claim {
                ClaimValue::Int(it) => return Some(*it),
                _ => {}
            }
        }
        return None;
    }

    pub fn bool_value(value: Option<&ClaimValue>) -> Option<bool> {
        if let Some(claim) = value {
            match claim {
                ClaimValue::Bool(it) => return Some(*it),
                _ => {}
            }
        }
        return None;
    }

    pub fn string_value(value: Option<&ClaimValue>) -> Option<String> {
        if let Some(claim) = value {
            match claim {
                ClaimValue::Str(str) => return Some(str.to_owned()),
                _ => {}
            }
        }
        return None;
    }

    pub fn string_list(value: Option<&ClaimValue>) -> Vec<String> {
        if let Some(claim) = value {
            match claim {
                ClaimValue::VecStr(vec) => return vec.clone(),
                _ => {}
            }
        }
        return Vec::new();
    }

    pub fn claims(value: Option<&ClaimValue>) -> Vec<String> {
        if let Some(claim) = value {
            match claim {
                ClaimValue::VecStr(vec) => return vec.clone(),
                _ => {}
            }
        }
        return Vec::new();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JwtClaimValue {
    Int(i64),
    Str(String),
    Bool(bool),
    VecStr(Vec<String>),
    Map(HashMap<String, ClaimValue>),
    VecClaims(Vec<ClaimValue>),
}

impl JwtClaimValue {
    pub fn int_value(value: Option<&JwtClaimValue>) -> Option<i64> {
        if let Some(claim) = value {
            match claim {
                JwtClaimValue::Int(it) => return Some(*it),
                _ => {}
            }
        }
        return None;
    }

    pub fn string_value(value: Option<&JwtClaimValue>) -> Option<String> {
        if let Some(claim) = value {
            match claim {
                JwtClaimValue::Str(str) => return Some(str.to_owned()),
                _ => {}
            }
        }
        return None;
    }

    pub fn bool_value(value: Option<&JwtClaimValue>) -> Option<bool> {
        if let Some(claim) = value {
            match claim {
                JwtClaimValue::Bool(b) => return Some(b.clone()),
                _ => {}
            }
        }
        return None;
    }

    pub fn string_list(value: Option<&JwtClaimValue>) -> Vec<String> {
        if let Some(claim) = value {
            match claim {
                JwtClaimValue::VecStr(vec) => return vec.clone(),
                _ => {}
            }
        }
        return Vec::new();
    }

    pub fn claims(value: Option<&JwtClaimValue>) -> HashMap<String, ClaimValue> {
        if let Some(claim) = value {
            match claim {
                JwtClaimValue::Map(vec) => return vec.clone(),
                _ => {}
            }
        }
        return HashMap::new();
    }
}

pub struct JsonWebTokenImp {
    token_id: Option<String>,
    issuer: Option<String>,
    not_before: Option<i64>,
    issue_at: Option<i64>,
    audiences: Vec<String>,
    subject: Option<String>,
    token_type: Option<String>,
    issued_for: Option<String>,
    expiry_at: Option<i64>,
    claims: HashMap<String, ClaimValue>,
}

impl JsonWebTokenImp {
    pub fn new() -> Self {
        Self {
            token_id: Default::default(),
            issuer: Default::default(),
            not_before: Default::default(),
            issue_at: Default::default(),
            audiences: Vec::new(),
            subject: Default::default(),
            token_type: Default::default(),
            issued_for: Default::default(),
            expiry_at: Default::default(),
            claims: Default::default(),
        }
    }
}

pub trait JsonWebToken: Token {
    fn jwt(&self) -> &JsonWebTokenImp;

    fn jwt_mut(&mut self) -> &mut JsonWebTokenImp;

    fn token_id(&self) -> &Option<String> {
        &self.jwt().token_id
    }

    fn set_token_id(&mut self, token_id: Option<String>) {
        self.jwt_mut().token_id = token_id;
    }

    fn issuer(&self) -> &Option<String> {
        &self.jwt().issuer
    }

    fn set_issuer(&mut self, issuer: Option<String>) {
        self.jwt_mut().issuer = issuer.to_owned();
    }

    fn not_before(&self) -> &Option<i64> {
        &self.jwt().not_before
    }

    fn set_not_before(&mut self, not_before: Option<i64>) {
        self.jwt_mut().not_before = not_before;
    }

    fn issue_at(&self) -> &Option<i64> {
        &self.jwt().issue_at
    }

    fn set_issue_at(&mut self, issue_at: Option<i64>) {
        self.jwt_mut().issue_at = issue_at;
    }

    fn issue_now(&mut self) {
        self.jwt_mut().issue_at = Some(Utc::now().timestamp())
    }

    fn audience(&self) -> &Vec<String> {
        &self.jwt().audiences
    }

    fn set_audience(&mut self, audiences: Vec<String>) {
        self.jwt_mut().audiences = audiences;
    }

    fn add_audience(&mut self, audience: &str) {
        self.jwt_mut().audiences.push(audience.to_owned());
    }

    fn has_audience(&self, audience: &str) -> bool {
        self.jwt().audiences.contains(&audience.to_owned())
    }

    fn has_any_audiences(&self, audiences: &Vec<String>) -> bool {
        for audience in audiences {
            if self.jwt().audiences.contains(audience) {
                return true;
            }
        }
        return false;
    }

    fn subject(&self) -> &Option<String> {
        &self.jwt().subject
    }

    fn set_subject(&mut self, subject: Option<String>) {
        self.jwt_mut().subject = subject;
    }

    fn expiry_at(&self) -> &Option<i64> {
        &self.jwt().expiry_at
    }

    fn set_expiry_at(&mut self, expiry_at: Option<i64>) {
        self.jwt_mut().expiry_at = expiry_at;
    }

    fn token_type(&self) -> &Option<String> {
        &self.jwt().token_type
    }

    fn set_token_type(&mut self, token_type: Option<String>) {
        self.jwt_mut().token_type = token_type;
    }

    fn issued_for(&self) -> &Option<String> {
        &self.jwt().issued_for
    }

    fn set_issued_for(&mut self, issued_for: Option<String>) {
        self.jwt_mut().issued_for = issued_for;
    }

    fn claims(&self) -> &HashMap<String, ClaimValue> {
        &self.jwt().claims
    }

    fn set_claims(&mut self, claims: HashMap<String, ClaimValue>) {
        self.jwt_mut().claims = claims;
    }

    fn set_claim(&mut self, name: &str, value: &str) -> Option<ClaimValue> {
        let claim = self.jwt().claims.get(name).cloned();
        self.jwt_mut()
            .claims
            .insert(name.to_owned(), ClaimValue::Str(value.to_owned()));
        claim
    }

    fn get_claim(&self, name: &str) -> Option<ClaimValue> {
        let claim = self.jwt().claims.get(name).cloned();
        claim
    }

    fn is_expired(&self) -> bool {
        match self.jwt().expiry_at {
            Some(exp) => {
                return exp < Utc::now().timestamp();
            }
            None => false,
        }
    }

    fn is_not_before(&self, allow_clock_skew: i64) -> bool {
        match self.jwt().not_before {
            Some(not_before) => {
                return not_before < Utc::now().timestamp() + allow_clock_skew;
            }
            None => true,
        }
    }

    fn is_active(&self, allow_clock_skew: i64) -> bool {
        !self.is_expired() && self.is_not_before(allow_clock_skew)
    }

    fn serialize_to_map(&self, json_map: &mut HashMap<String, JwtClaimValue>) {
        if self.token_id().is_some() {
            json_map.insert(
                "jit".to_owned(),
                JwtClaimValue::Str(self.token_id().clone().unwrap()),
            );
        }
        if self.expiry_at().is_some() {
            json_map.insert(
                "exp".to_owned(),
                JwtClaimValue::Int(self.expiry_at().clone().unwrap()),
            );
        }
        if self.issue_at().is_some() {
            json_map.insert(
                "iat".to_owned(),
                JwtClaimValue::Int(self.issue_at().clone().unwrap()),
            );
        }
        if self.issuer().is_some() {
            json_map.insert(
                "iss".to_owned(),
                JwtClaimValue::Str(self.issuer().clone().unwrap()),
            );
        }

        if !self.audience().is_empty() {
            json_map.insert(
                "iss".to_owned(),
                JwtClaimValue::VecStr(self.audience().clone()),
            );
        }
        if self.subject().is_some() {
            json_map.insert(
                "sub".to_owned(),
                JwtClaimValue::Str(self.subject().clone().unwrap()),
            );
        }
        if self.token_type().is_some() {
            json_map.insert(
                "typ".to_owned(),
                JwtClaimValue::Str(self.token_type().clone().unwrap()),
            );
        }
        if self.not_before().is_some() {
            json_map.insert(
                "nbf".to_owned(),
                JwtClaimValue::Int(self.not_before().clone().unwrap()),
            );
        }
        if !self.claims().is_empty() {
            json_map.insert(
                "claims".to_owned(),
                JwtClaimValue::Map(self.claims().clone()),
            );
        }
    }

    fn serialize(&mut self) -> String {
        let mut json_map = HashMap::new();
        self.serialize_to_map(&mut json_map);
        return serde_json::to_string(&json_map).unwrap();
    }

    fn read_jwt_token(&mut self, token_dict: &HashMap<String, JwtClaimValue>) {
        self.set_token_id(JwtClaimValue::string_value(token_dict.get("jti")));
        self.set_token_type(JwtClaimValue::string_value(token_dict.get("typ")));
        self.set_not_before(JwtClaimValue::int_value(token_dict.get("nbf")));
        self.set_expiry_at(JwtClaimValue::int_value(token_dict.get("exp")));
        self.set_issuer(JwtClaimValue::string_value(token_dict.get("iss")));
        self.set_issued_for(JwtClaimValue::string_value(token_dict.get("azp")));
        self.set_audience(JwtClaimValue::string_list(token_dict.get("aud")));
        self.set_subject(JwtClaimValue::string_value(token_dict.get("sub")));
        self.set_issue_at(JwtClaimValue::int_value(token_dict.get("iat")));
        self.set_claims(JwtClaimValue::claims(token_dict.get("claims")));
    }

    fn parse(&mut self, token_dict: &HashMap<String, JwtClaimValue>) {
        self.read_jwt_token(token_dict);
    }
}

impl Token for JsonWebTokenImp {
    fn category(&self) -> TokenCategoryEnum {
        TokenCategoryEnum::Internal
    }
}

impl JsonWebToken for JsonWebTokenImp {
    fn jwt(&self) -> &JsonWebTokenImp {
        return &self;
    }

    fn jwt_mut(&mut self) -> &mut JsonWebTokenImp {
        return self;
    }
}

pub struct IdTokenImp {
    jwt: JsonWebTokenImp,
    nonce: Option<String>,
    auth_time: Option<i64>,
    session_id: Option<String>,
    access_token_hash: Option<String>,
    code_hash: Option<String>,
    given_name: Option<String>,
    name: Option<String>,
    family_name: Option<String>,
    preferred_username: Option<String>,
    middle_name: Option<String>,
    nick_name: Option<String>,
    profile: Option<String>,
    picture: Option<String>,
    website: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    gender: Option<String>,
    birthdate: Option<String>,
    zoneinfo: Option<String>,
    locale: Option<String>,
    phone_number: Option<String>,
    phone_number_verified: Option<bool>,
    updated_at: Option<i64>,
    claims_locales: Option<String>,
    acr: Option<String>,
    state_hash: Option<String>,
}

impl Token for IdTokenImp {
    fn category(&self) -> TokenCategoryEnum {
        TokenCategoryEnum::Id
    }
}

impl IdTokenImp {
    pub fn new() -> Self {
        Self {
            jwt: JsonWebTokenImp::new(),
            nonce: Default::default(),
            auth_time: Default::default(),
            session_id: Default::default(),
            access_token_hash: Default::default(),
            code_hash: Default::default(),
            given_name: Default::default(),
            name: Default::default(),
            family_name: Default::default(),
            preferred_username: Default::default(),
            middle_name: Default::default(),
            nick_name: Default::default(),
            profile: Default::default(),
            picture: Default::default(),
            website: Default::default(),
            email: Default::default(),
            email_verified: Default::default(),
            gender: Default::default(),
            birthdate: Default::default(),
            zoneinfo: Default::default(),
            locale: Default::default(),
            phone_number: Default::default(),
            phone_number_verified: Default::default(),
            updated_at: Default::default(),
            claims_locales: Default::default(),
            acr: Default::default(),
            state_hash: Default::default(),
        }
    }
}

pub trait IdToken: JsonWebToken {
    fn id_token(&self) -> &IdTokenImp;

    fn id_token_mut(&mut self) -> &mut IdTokenImp;

    fn category(&self) -> TokenCategoryEnum {
        TokenCategoryEnum::Internal
    }

    fn nonce(&self) -> &Option<String> {
        &self.id_token().nonce
    }

    fn set_nonce(&mut self, nonce: Option<String>) {
        self.id_token_mut().nonce = nonce;
    }

    fn auth_time(&self) -> &Option<i64> {
        &self.id_token().auth_time
    }

    fn set_auth_time(&mut self, auth_time: Option<i64>) {
        self.id_token_mut().auth_time = auth_time;
    }

    fn session_id(&self) -> &Option<String> {
        &self.id_token().session_id
    }

    fn set_session_id(&mut self, session_id: Option<String>) {
        self.id_token_mut().session_id = session_id;
    }

    fn preferred_username(&self) -> &Option<String> {
        &self.id_token().preferred_username
    }

    fn set_preferred_username(&mut self, preferred_username: Option<String>) {
        self.id_token_mut().preferred_username = preferred_username;
    }

    fn access_token_hash(&self) -> &Option<String> {
        &self.id_token().preferred_username
    }

    fn set_access_token_hash(&mut self, access_token_hash: Option<String>) {
        self.id_token_mut().access_token_hash = access_token_hash;
    }

    fn code_hash(&self) -> &Option<String> {
        &self.id_token().code_hash
    }

    fn set_code_hash(&mut self, code_hash: Option<String>) {
        self.id_token_mut().code_hash = code_hash;
    }

    fn given_name(&self) -> &Option<String> {
        &self.id_token().given_name
    }

    fn set_given_name(&mut self, given_name: Option<String>) {
        self.id_token_mut().given_name = given_name;
    }

    fn name(&self) -> &Option<String> {
        &self.id_token().name
    }

    fn set_name(&mut self, name: Option<String>) {
        self.id_token_mut().name = name;
    }

    fn family_name(&self) -> &Option<String> {
        &self.id_token().family_name
    }

    fn set_family_name(&mut self, family_name: Option<String>) {
        self.id_token_mut().family_name = family_name;
    }

    fn middle_name(&self) -> &Option<String> {
        &self.id_token().middle_name
    }

    fn set_middle_name(&mut self, middle_name: Option<String>) {
        self.id_token_mut().middle_name = middle_name;
    }

    fn nick_name(&self) -> &Option<String> {
        &self.id_token().nick_name
    }

    fn set_nick_name(&mut self, nick_name: Option<String>) {
        self.id_token_mut().nick_name = nick_name;
    }

    fn profile(&self) -> &Option<String> {
        &self.id_token().profile
    }

    fn set_profile(&mut self, profile: Option<String>) {
        self.id_token_mut().profile = profile;
    }

    fn picture(&self) -> &Option<String> {
        &self.id_token().picture
    }

    fn set_picture(&mut self, picture: Option<String>) {
        self.id_token_mut().picture = picture;
    }

    fn website(&self) -> &Option<String> {
        &self.id_token().website
    }

    fn set_website(&mut self, website: Option<String>) {
        self.id_token_mut().website = website;
    }

    fn email(&self) -> &Option<String> {
        &self.id_token().email
    }

    fn set_email(&mut self, email: Option<String>) {
        self.id_token_mut().email = email;
    }

    fn email_verified(&self) -> &Option<bool> {
        &self.id_token().email_verified
    }

    fn set_email_verified(&mut self, email_verified: Option<bool>) {
        self.id_token_mut().email_verified = email_verified;
    }

    fn gender(&self) -> &Option<String> {
        &self.id_token().gender
    }

    fn set_gender(&mut self, gender: Option<String>) {
        self.id_token_mut().gender = gender;
    }

    fn birth_date(&self) -> &Option<String> {
        &self.id_token().birthdate
    }

    fn set_birth_date(&mut self, birthdate: Option<String>) {
        self.id_token_mut().birthdate = birthdate;
    }

    fn zoneinfo(&self) -> &Option<String> {
        &self.id_token().zoneinfo
    }

    fn set_zoneinfo(&mut self, zoneinfo: Option<String>) {
        self.id_token_mut().zoneinfo = zoneinfo;
    }

    fn locale(&self) -> &Option<String> {
        &self.id_token().locale
    }

    fn set_locale(&mut self, locale: Option<String>) {
        self.id_token_mut().locale = locale;
    }

    fn phone_number(&self) -> &Option<String> {
        &self.id_token().phone_number
    }

    fn set_phone_number(&mut self, phone_number: Option<String>) {
        self.id_token_mut().phone_number = phone_number;
    }

    fn phone_number_verified(&self) -> &Option<bool> {
        &self.id_token().phone_number_verified
    }

    fn set_phone_number_verified(&mut self, phone_number_verified: Option<bool>) {
        self.id_token_mut().phone_number_verified = phone_number_verified;
    }

    fn updated_at(&self) -> &Option<i64> {
        &self.id_token().updated_at
    }

    fn set_updated_at(&mut self, updated_at: Option<i64>) {
        self.id_token_mut().updated_at = updated_at;
    }

    fn claims_locales(&self) -> &Option<String> {
        &self.id_token().claims_locales
    }

    fn set_claims_locales(&mut self, claims_locales: Option<String>) {
        self.id_token_mut().claims_locales = claims_locales;
    }

    fn acr(&self) -> &Option<String> {
        &self.id_token().acr
    }

    fn set_acr(&mut self, acr: Option<String>) {
        self.id_token_mut().acr = acr;
    }

    fn state_hash(&self) -> &Option<String> {
        &self.id_token().state_hash
    }

    fn set_state_hash(&mut self, state_hash: Option<String>) {
        self.id_token_mut().state_hash = state_hash;
    }

    fn serialize_id_token_to_map(&self, json_map: &mut HashMap<String, JwtClaimValue>) {
        self.jwt().serialize_to_map(json_map);
        if self.nonce().is_some() {
            json_map.insert(
                "nonce".to_owned(),
                JwtClaimValue::Str(self.nonce().clone().unwrap()),
            );
        }

        if self.auth_time().is_some() {
            json_map.insert(
                "auth_time".to_owned(),
                JwtClaimValue::Int(self.auth_time().clone().unwrap()),
            );
        }

        if self.session_id().is_some() {
            json_map.insert(
                "sid".to_owned(),
                JwtClaimValue::Str(self.session_id().clone().unwrap()),
            );
        }

        if self.access_token_hash().is_some() {
            json_map.insert(
                "at_hash".to_owned(),
                JwtClaimValue::Str(self.access_token_hash().clone().unwrap()),
            );
        }

        if self.code_hash().is_some() {
            json_map.insert(
                "c_hash".to_owned(),
                JwtClaimValue::Str(self.code_hash().clone().unwrap()),
            );
        }

        if self.name().is_some() {
            json_map.insert(
                "name".to_owned(),
                JwtClaimValue::Str(self.name().clone().unwrap()),
            );
        }

        if self.given_name().is_some() {
            json_map.insert(
                "given_name".to_owned(),
                JwtClaimValue::Str(self.given_name().clone().unwrap()),
            );
        }

        if self.family_name().is_some() {
            json_map.insert(
                "family_name".to_owned(),
                JwtClaimValue::Str(self.family_name().clone().unwrap()),
            );
        }

        if self.middle_name().is_some() {
            json_map.insert(
                "middle_name".to_owned(),
                JwtClaimValue::Str(self.middle_name().clone().unwrap()),
            );
        }

        if self.nick_name().is_some() {
            json_map.insert(
                "nickname".to_owned(),
                JwtClaimValue::Str(self.nick_name().clone().unwrap()),
            );
        }

        if self.preferred_username().is_some() {
            json_map.insert(
                "preferred_username".to_owned(),
                JwtClaimValue::Str(self.preferred_username().clone().unwrap()),
            );
        }

        if self.profile().is_some() {
            json_map.insert(
                "profile".to_owned(),
                JwtClaimValue::Str(self.profile().clone().unwrap()),
            );
        }

        if self.picture().is_some() {
            json_map.insert(
                "picture".to_owned(),
                JwtClaimValue::Str(self.picture().clone().unwrap()),
            );
        }

        if self.website().is_some() {
            json_map.insert(
                "website".to_owned(),
                JwtClaimValue::Str(self.website().clone().unwrap()),
            );
        }

        if self.email().is_some() {
            json_map.insert(
                "email".to_owned(),
                JwtClaimValue::Str(self.email().clone().unwrap()),
            );
        }

        if self.email_verified().is_some() {
            json_map.insert(
                "email_verified".to_owned(),
                JwtClaimValue::Bool(self.email_verified().clone().unwrap()),
            );
        }

        if self.gender().is_some() {
            json_map.insert(
                "gender".to_owned(),
                JwtClaimValue::Str(self.gender().clone().unwrap()),
            );
        }

        if self.birth_date().is_some() {
            json_map.insert(
                "birth_date".to_owned(),
                JwtClaimValue::Str(self.birth_date().clone().unwrap()),
            );
        }

        if self.zoneinfo().is_some() {
            json_map.insert(
                "zoneinfo".to_owned(),
                JwtClaimValue::Str(self.zoneinfo().clone().unwrap()),
            );
        }

        if self.locale().is_some() {
            json_map.insert(
                "locale".to_owned(),
                JwtClaimValue::Str(self.locale().clone().unwrap()),
            );
        }

        if self.phone_number().is_some() {
            json_map.insert(
                "phone_number".to_owned(),
                JwtClaimValue::Str(self.phone_number().clone().unwrap()),
            );
        }

        if self.phone_number_verified().is_some() {
            json_map.insert(
                "phone_number_verified".to_owned(),
                JwtClaimValue::Bool(self.phone_number_verified().clone().unwrap()),
            );
        }

        if self.claims_locales().is_some() {
            json_map.insert(
                "claims_locales".to_owned(),
                JwtClaimValue::Str(self.claims_locales().clone().unwrap()),
            );
        }

        if self.acr().is_some() {
            json_map.insert(
                "acr".to_owned(),
                JwtClaimValue::Str(self.acr().clone().unwrap()),
            );
        }

        if self.state_hash().is_some() {
            json_map.insert(
                "s_hash".to_owned(),
                JwtClaimValue::Str(self.state_hash().clone().unwrap()),
            );
        }
    }

    fn serialize(&mut self) -> String {
        let mut json_map = HashMap::new();
        self.serialize_id_token_to_map(&mut json_map);
        return serde_json::to_string(&json_map).unwrap();
    }

    fn parse(&mut self, token_dict: &HashMap<String, JwtClaimValue>) {
        self.read_id_token(token_dict);
    }

    fn read_id_token(&mut self, token_dict: &HashMap<String, JwtClaimValue>) {
        self.jwt_mut().read_jwt_token(token_dict);
        self.set_nonce(JwtClaimValue::string_value(token_dict.get("nonce")));
        self.set_auth_time(JwtClaimValue::int_value(token_dict.get("auth_time")));
        self.set_session_id(JwtClaimValue::string_value(token_dict.get("sid")));
        self.set_access_token_hash(JwtClaimValue::string_value(token_dict.get("at_hash")));
        self.set_given_name(JwtClaimValue::string_value(token_dict.get("given_name")));
        self.set_name(JwtClaimValue::string_value(token_dict.get("name")));
        self.set_family_name(JwtClaimValue::string_value(token_dict.get("family_name")));
        self.set_middle_name(JwtClaimValue::string_value(token_dict.get("middle_name")));
        self.set_preferred_username(JwtClaimValue::string_value(
            token_dict.get("preferred_username"),
        ));
        self.set_nick_name(JwtClaimValue::string_value(token_dict.get("nick_name")));
        self.set_profile(JwtClaimValue::string_value(token_dict.get("profile")));
        self.set_website(JwtClaimValue::string_value(token_dict.get("website")));
        self.set_email(JwtClaimValue::string_value(token_dict.get("email")));
        self.set_email_verified(JwtClaimValue::bool_value(token_dict.get("email_verified")));
        self.set_gender(JwtClaimValue::string_value(token_dict.get("gender")));
        self.set_birth_date(JwtClaimValue::string_value(token_dict.get("birthdate")));
        self.set_zoneinfo(JwtClaimValue::string_value(token_dict.get("zoneinfo")));
        self.set_locale(JwtClaimValue::string_value(token_dict.get("locale")));
        self.set_phone_number(JwtClaimValue::string_value(token_dict.get("phone_number")));
        self.set_phone_number_verified(JwtClaimValue::bool_value(
            token_dict.get("phone_number_verified"),
        ));
        self.set_updated_at(JwtClaimValue::int_value(token_dict.get("updated_at")));
        self.set_claims_locales(JwtClaimValue::string_value(
            token_dict.get("claims_locales"),
        ));
        self.set_acr(JwtClaimValue::string_value(token_dict.get("acr")));
        self.set_state_hash(JwtClaimValue::string_value(token_dict.get("state_hash")));
    }
}

impl JsonWebToken for IdTokenImp {
    fn jwt(&self) -> &JsonWebTokenImp {
        return &self.jwt;
    }

    fn jwt_mut(&mut self) -> &mut JsonWebTokenImp {
        return &mut self.jwt;
    }
}

impl IdToken for IdTokenImp {
    fn id_token(&self) -> &IdTokenImp {
        return &self;
    }

    fn id_token_mut(&mut self) -> &mut IdTokenImp {
        return self;
    }
}

pub struct AccessTokenAcces {
    roles: Option<Vec<String>>,
    verify_caller: Option<bool>,
}

impl AccessTokenAcces {
    pub fn new() -> Self {
        Self {
            roles: Default::default(),
            verify_caller: Default::default(),
        }
    }

    pub fn clone(&self) -> Self {
        Self {
            roles: self.roles.clone(),
            verify_caller: self.verify_caller.clone(),
        }
    }

    pub fn roles(&self) -> &Option<Vec<String>> {
        &self.roles
    }

    pub fn set_roles(&mut self, roles: Option<Vec<String>>) {
        self.roles = roles
    }

    pub fn verify_caller(&self) -> &Option<bool> {
        &self.verify_caller
    }

    pub fn set_verify_caller(&mut self, verify_caller: Option<bool>) {
        self.verify_caller = verify_caller
    }

    pub fn is_in_roles(&self, role: &str) -> bool {
        if let Some(r) = &self.roles {
            if r.contains(&role.to_owned()) {
                return true;
            }
        }
        return false;
    }

    pub fn add_role(&mut self, role: &str) {
        match &mut self.roles {
            Some(r) => {
                r.push(role.to_owned());
            }
            None => {
                let mut d = Vec::new();
                d.push(role.to_owned());
                self.roles = Some(d);
            }
        }
    }

    pub fn to_claim_map(&self) -> HashMap<String, ClaimValue> {
        let mut json_map = HashMap::new();
        if self.roles.is_some() {
            json_map.insert(
                "roles".to_owned(),
                ClaimValue::VecStr(self.roles.as_ref().unwrap().clone()),
            );
        }
        if self.verify_caller.is_some() {
            json_map.insert(
                "verify_caller".to_owned(),
                ClaimValue::Bool(self.verify_caller.as_ref().unwrap().clone()),
            );
        }
        return json_map;
    }

    pub fn from_map(json_map: &HashMap<String, ClaimValue>) -> Self {
        let mut access = AccessTokenAcces::new();
        let roles = ClaimValue::string_list(json_map.get("roles"));
        access.set_roles(Some(roles));
        let verify_caller = ClaimValue::bool_value(json_map.get("verify_caller"));
        access.set_verify_caller(verify_caller);
        access
    }
}

pub struct Permission;

pub struct Authorization {
    permissions: Vec<Permission>,
}

impl Authorization {
    pub fn permissions(&self) -> &Vec<Permission> {
        &self.permissions
    }

    pub fn set_permissions(&mut self, permissions: Vec<Permission>) {
        self.permissions = permissions
    }

    pub fn to_claim_vec(&self) -> Vec<ClaimValue> {
        let mut permissions = Vec::new();
        for permission in self.permissions.iter() {
            //permissions.push(permission.to_map());
        }
        permissions
    }
}

pub struct CertificateConfig {
    cert_thumbprint: Option<bool>,
}

impl CertificateConfig {
    pub fn new() -> Self {
        Self {
            cert_thumbprint: Default::default(),
        }
    }

    pub fn cert_thumbprint(&self) -> &Option<bool> {
        &self.cert_thumbprint
    }

    pub fn set_cert_thumbprint(&mut self, cert_thumbprint: Option<bool>) {
        self.cert_thumbprint = cert_thumbprint
    }

    pub fn to_claim_map(&self) -> HashMap<String, ClaimValue> {
        let mut json_map = HashMap::new();
        if self.cert_thumbprint.is_some() {
            json_map.insert(
                "x5t#S256".to_owned(),
                ClaimValue::Bool(self.cert_thumbprint.as_ref().unwrap().clone()),
            );
        }
        json_map
    }

    pub fn from_map(&self, json_map: &mut HashMap<String, ClaimValue>) -> Self {
        let mut config = CertificateConfig::new();
        let cert_thumbprint = ClaimValue::bool_value(json_map.get("x5t#S256"));
        config.set_cert_thumbprint(cert_thumbprint);
        config
    }
}

#[allow(dead_code)]
pub trait AccessToken: IdToken {
    fn access_token(&self) -> &AccessTokenImp;

    fn access_token_mut(&mut self) -> &mut AccessTokenImp;

    fn scope(&self) -> &Option<String> {
        &self.access_token().scope
    }

    fn set_scope(&mut self, scope: Option<String>) {
        self.access_token_mut().scope = scope;
    }

    fn resources_access(&self) -> &Option<HashMap<String, AccessTokenAcces>> {
        &self.access_token().resources_access
    }

    fn set_resources_access(
        &mut self,
        resources_access: Option<HashMap<String, AccessTokenAcces>>,
    ) {
        self.access_token_mut().resources_access = resources_access;
    }

    fn allowed_origins(&self) -> &Option<Vec<String>> {
        &self.access_token().allowed_origins
    }

    fn set_allowed_origins(&mut self, allowed_origins: Option<Vec<String>>) {
        self.access_token_mut().allowed_origins = allowed_origins;
    }

    fn realm_access(&self) -> &Option<AccessTokenAcces> {
        &self.access_token().realm_access
    }

    fn set_realm_access(&mut self, realm_access: Option<AccessTokenAcces>) {
        self.access_token_mut().realm_access = realm_access;
    }

    fn trusted_certificates(&self) -> &Option<Vec<String>> {
        &self.access_token().trusted_certificates
    }

    fn set_trusted_certificates(&mut self, trusted_certificates: Option<Vec<String>>) {
        self.access_token_mut().trusted_certificates = trusted_certificates;
    }

    fn authorization(&self) -> &Option<Authorization> {
        &self.access_token().authorization
    }

    fn set_authorization(&mut self, authorization: Option<Authorization>) {
        self.access_token_mut().authorization = authorization;
    }

    fn certificate_config(&self) -> &Option<CertificateConfig> {
        &self.access_token().certificate_config
    }

    fn set_certificate_config(&mut self, certificate_config: Option<CertificateConfig>) {
        self.access_token_mut().certificate_config = certificate_config;
    }

    fn serialize_access_token_to_map(&self, json_map: &mut HashMap<String, JwtClaimValue>) {
        let map_resource_map = |map: &HashMap<String, AccessTokenAcces>| {
            let mut result: HashMap<String, JwtClaimValue> = HashMap::new();
            for (key, value) in map.iter() {
                result.insert(key.clone(), JwtClaimValue::Map((*value).to_claim_map()));
            }
            result
        };

        self.id_token().serialize_id_token_to_map(json_map);
        if self.trusted_certificates().is_some() {
            json_map.insert(
                "trusted-certs".to_owned(),
                JwtClaimValue::VecStr(self.trusted_certificates().clone().unwrap()),
            );
        }

        if self.allowed_origins().is_some() {
            json_map.insert(
                "allowed-origins".to_owned(),
                JwtClaimValue::VecStr(self.allowed_origins().clone().unwrap()),
            );
        }
        if self.scope().is_some() {
            json_map.insert(
                "scope".to_owned(),
                JwtClaimValue::Str(self.scope().clone().unwrap()),
            );
        }
        if self.certificate_config().is_some() {
            json_map.insert(
                "cnf".to_owned(),
                JwtClaimValue::Map((*self.certificate_config().as_ref().unwrap()).to_claim_map()),
            );
        }
        if self.authorization().is_some() {
            json_map.insert(
                "authorization".to_owned(),
                JwtClaimValue::VecClaims((*self.authorization().as_ref().unwrap()).to_claim_vec()),
            );
        }
        if self.realm_access().is_some() {
            json_map.insert(
                "realm-access".to_owned(),
                JwtClaimValue::Map((*self.realm_access().as_ref().unwrap()).to_claim_map()),
            );
        }
    }

    fn serialize(&self) -> String {
        let mut json_map = HashMap::new();
        self.serialize_access_token_to_map(&mut json_map);
        return serde_json::to_string(&json_map).unwrap();
    }

    fn read_access_token(&mut self, token_dict: &HashMap<String, JwtClaimValue>) {
        self.id_token_mut().read_id_token(token_dict);

        self.set_scope(JwtClaimValue::string_value(token_dict.get("scope")));
        self.set_trusted_certificates(Some(JwtClaimValue::string_list(token_dict.get("scope"))));
        self.set_allowed_origins(Some(JwtClaimValue::string_list(
            token_dict.get("allowed-origins"),
        )));
        let cfg_opt = JwtClaimValue::bool_value(token_dict.get("x5t#S256"));
        if cfg_opt.is_some() {
            let mut cfg = CertificateConfig::new();
            cfg.set_cert_thumbprint(cfg_opt);
            self.set_certificate_config(Some(cfg));
        }
        let realm_access = JwtClaimValue::claims(token_dict.get("realm-access"));
        if !realm_access.is_empty() {
            self.set_realm_access(Some(AccessTokenAcces::from_map(&realm_access)));
        }
    }

    fn parse(&mut self, token_dict: &HashMap<String, JwtClaimValue>) {
        self.read_access_token(token_dict);
    }
}

#[allow(dead_code)]
pub struct AccessTokenImp {
    id_token: IdTokenImp,
    realm_access: Option<AccessTokenAcces>,
    allowed_origins: Option<Vec<String>>,
    resources_access: Option<HashMap<String, AccessTokenAcces>>,
    authorization: Option<Authorization>,
    certificate_config: Option<CertificateConfig>,
    scope: Option<String>,
    trusted_certificates: Option<Vec<String>>,
}

impl AccessToken for AccessTokenImp {
    fn access_token(&self) -> &AccessTokenImp {
        &self
    }

    fn access_token_mut(&mut self) -> &mut AccessTokenImp {
        self
    }
}

impl IdToken for AccessTokenImp {
    fn id_token(&self) -> &IdTokenImp {
        &self.id_token
    }

    fn id_token_mut(&mut self) -> &mut IdTokenImp {
        &mut self.id_token
    }
}

impl JsonWebToken for AccessTokenImp {
    fn jwt(&self) -> &JsonWebTokenImp {
        return self.id_token.jwt();
    }

    fn jwt_mut(&mut self) -> &mut JsonWebTokenImp {
        return self.id_token.jwt_mut();
    }
}

impl AccessTokenImp {
    pub fn new() -> Self {
        Self {
            id_token: IdTokenImp::new(),
            realm_access: Default::default(),
            allowed_origins: Default::default(),
            resources_access: Default::default(),
            authorization: Default::default(),
            certificate_config: Default::default(),
            scope: Default::default(),
            trusted_certificates: Default::default(),
        }
    }
}

impl Token for AccessTokenImp {
    fn category(&self) -> TokenCategoryEnum {
        TokenCategoryEnum::Access
    }
}

pub trait RefreshToken: AccessToken {
    fn from_access(access_token: AccessTokenImp) -> RefreshTokenImp {
        let mut refresh_token = RefreshTokenImp::new();
        refresh_token.set_issuer(access_token.issuer().clone());
        refresh_token.set_subject(access_token.subject().clone());
        refresh_token.set_issued_for(access_token.issued_for().clone());
        refresh_token.set_nonce(access_token.nonce().clone());
        refresh_token.set_scope(access_token.scope().clone());
        refresh_token.set_audience(access_token.audience().clone());
        refresh_token.set_session_id(access_token.session_id().clone());
        refresh_token.set_token_type(access_token.token_type().clone());
        refresh_token
    }

    fn parse(&mut self, token_dict: &HashMap<String, JwtClaimValue>) {
        self.read_access_token(token_dict);
    }
}

pub struct RefreshTokenImp {
    access_token: AccessTokenImp,
}

impl RefreshTokenImp {
    pub fn new() -> Self {
        Self {
            access_token: AccessTokenImp::new(),
        }
    }
}

impl RefreshToken for RefreshTokenImp {}

impl AccessToken for RefreshTokenImp {
    fn access_token(&self) -> &AccessTokenImp {
        self.access_token.access_token()
    }

    fn access_token_mut(&mut self) -> &mut AccessTokenImp {
        self.access_token.access_token_mut()
    }
}

impl IdToken for RefreshTokenImp {
    fn id_token(&self) -> &IdTokenImp {
        &self.access_token.id_token()
    }

    fn id_token_mut(&mut self) -> &mut IdTokenImp {
        self.access_token.id_token_mut()
    }
}

impl JsonWebToken for RefreshTokenImp {
    fn jwt(&self) -> &JsonWebTokenImp {
        &self.access_token.id_token().jwt()
    }

    fn jwt_mut(&mut self) -> &mut JsonWebTokenImp {
        self.access_token.id_token_mut().jwt_mut()
    }
}

impl Token for RefreshTokenImp {
    fn category(&self) -> TokenCategoryEnum {
        TokenCategoryEnum::Access
    }
}

pub trait LogoutToken: JsonWebToken {
    fn logout_token(&self) -> &LogoutTokenImp;

    fn logout_token_mut(&mut self) -> &mut LogoutTokenImp;

    fn session_id(&self) -> &Option<String> {
        &self.logout_token().session_id
    }

    fn set_session_id(&mut self, session_id: Option<String>) {
        self.logout_token_mut().session_id = session_id;
    }

    fn events(&self) -> &HashMap<String, ClaimValue> {
        &self.logout_token().events
    }

    fn set_events(&mut self, events: HashMap<String, ClaimValue>) {
        self.logout_token_mut().events = events;
    }

    fn serialize_access_token_to_map(&self, json_map: &mut HashMap<String, JwtClaimValue>) {
        self.jwt().serialize_to_map(json_map);
        if self.session_id().is_some() {
            json_map.insert(
                "session_id".to_owned(),
                JwtClaimValue::Str(self.session_id().clone().unwrap()),
            );
        }

        if self.events().is_empty() {
            json_map.insert(
                "events".to_owned(),
                JwtClaimValue::Map(self.events().clone()),
            );
        }
    }

    fn serialize(&self) -> String {
        let mut json_map = HashMap::new();
        self.serialize_access_token_to_map(&mut json_map);
        return serde_json::to_string(&json_map).unwrap();
    }

    fn read_logout_token(&mut self, token_dict: &HashMap<String, JwtClaimValue>) {
        self.jwt_mut().read_jwt_token(token_dict);
        self.set_session_id(JwtClaimValue::string_value(token_dict.get("session_id")));
        self.set_events(JwtClaimValue::claims(token_dict.get("events")));
    }

    fn parse(&mut self, token_dict: &HashMap<String, JwtClaimValue>) {
        self.read_logout_token(token_dict);
        self.set_session_id(JwtClaimValue::string_value(token_dict.get("session_id")));
        self.set_events(JwtClaimValue::claims(token_dict.get("events")));
    }
}

pub struct LogoutTokenImp {
    jwt: JsonWebTokenImp,
    session_id: Option<String>,
    events: HashMap<String, ClaimValue>,
}

impl LogoutTokenImp {
    pub fn new() -> Self {
        Self {
            jwt: JsonWebTokenImp::new(),
            session_id: None,
            events: HashMap::new(),
        }
    }
}

impl LogoutToken for LogoutTokenImp {
    fn logout_token(&self) -> &LogoutTokenImp {
        &self
    }

    fn logout_token_mut(&mut self) -> &mut LogoutTokenImp {
        self
    }
}

impl JsonWebToken for LogoutTokenImp {
    fn jwt(&self) -> &JsonWebTokenImp {
        &self.jwt
    }

    fn jwt_mut(&mut self) -> &mut JsonWebTokenImp {
        &mut self.jwt
    }
}

impl Token for LogoutTokenImp {
    fn category(&self) -> TokenCategoryEnum {
        TokenCategoryEnum::Logout
    }
}

pub trait AuthorizationResponseToken: JsonWebToken {
    fn response_token(&self) -> &AuthorizationResponseTokenImp;

    fn response_token_mut(&mut self) -> &mut AuthorizationResponseTokenImp;

    fn serialize_response_token_to_map(&self, json_map: &mut HashMap<String, JwtClaimValue>) {
        self.jwt().serialize_to_map(json_map);
    }

    fn serialize(&self) -> String {
        let mut json_map = HashMap::new();
        self.serialize_response_token_to_map(&mut json_map);
        return serde_json::to_string(&json_map).unwrap();
    }

    fn read_logout_token(&mut self, token_dict: &HashMap<String, JwtClaimValue>) {
        self.jwt_mut().read_jwt_token(token_dict);
    }

    fn parse(&mut self, token_dict: &HashMap<String, JwtClaimValue>) {
        self.read_jwt_token(token_dict);
    }
}

pub struct AuthorizationResponseTokenImp {
    jwt: JsonWebTokenImp,
}

impl AuthorizationResponseTokenImp {
    pub fn new() -> Self {
        Self {
            jwt: JsonWebTokenImp::new(),
        }
    }
}

impl AuthorizationResponseToken for AuthorizationResponseTokenImp {
    fn response_token(&self) -> &AuthorizationResponseTokenImp {
        &self
    }

    fn response_token_mut(&mut self) -> &mut AuthorizationResponseTokenImp {
        self
    }
}

impl JsonWebToken for AuthorizationResponseTokenImp {
    fn jwt(&self) -> &JsonWebTokenImp {
        &self.jwt
    }

    fn jwt_mut(&mut self) -> &mut JsonWebTokenImp {
        &mut self.jwt
    }
}

impl Token for AuthorizationResponseTokenImp {
    fn category(&self) -> TokenCategoryEnum {
        TokenCategoryEnum::AuthorizationResponse
    }
}

pub struct ActionToken {
    pub user_id: String,
    pub action_id: String,
    pub expiration_in_seconds: i64,
    pub action_verification_nonce: Option<String>,
    pub notes: Option<HashMap<String, String>>,
}

impl ActionToken {
    pub fn new(
        user_id: &str,
        action_id: &str,
        expiration_in_seconds: i64,
        action_verification_nonce: &str,
        notes: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            user_id: user_id.to_owned(),
            action_id: action_id.to_owned(),
            expiration_in_seconds: expiration_in_seconds,
            action_verification_nonce: Some(action_verification_nonce.to_owned()),
            notes: notes.clone(),
        }
    }

    pub fn serialize(&self) -> String {
        let verification_nonce = if let Some(n) = &self.action_verification_nonce {
            n.clone()
        } else {
            String::new()
        };

        let token = format!(
            "{}.{}.{}.{}",
            self.user_id, self.action_id, self.expiration_in_seconds, verification_nonce
        );
        base64_url::encode(&token)
    }

    pub fn deserialize(action_token: &str) -> Result<ActionToken, String> {
        let decoded_token = base64_url::decode(action_token);
        match decoded_token {
            Ok(res) => {
                let decoded_string = str::from_utf8(&res);
                match decoded_string {
                    Ok(decoded_token) => {
                        let tokens: Vec<_> = decoded_token.split(".").collect();
                        if tokens.len() == 4 {
                            let expiration_in_seconds = tokens[2].parse::<i64>();
                            if let Err(err) = expiration_in_seconds {
                                return Err(err.to_string());
                            }

                            let action = ActionToken::new(
                                tokens[0],
                                tokens[1],
                                expiration_in_seconds.unwrap(),
                                tokens[3],
                                None,
                            );
                            return Ok(action);
                        } else {
                            return Err("invalid action token".to_owned());
                        }
                    }
                    Err(err) => Err(err.to_string()),
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    pub fn set_note(&mut self, name: &str, value: &str) -> Option<String> {
        match &mut self.notes {
            Some(notes) => {
                let existing_note = notes.get(name).cloned();
                notes.insert(name.to_owned(), value.to_owned());
                if let Some(d) = existing_note {
                    return Some(d.clone());
                } else {
                    None
                }
            }
            None => {
                let mut notes: HashMap<String, String> = HashMap::new();
                notes.insert(name.to_owned(), value.to_owned());
                self.notes = Some(notes);
                None
            }
        }
    }

    pub fn remove_note(&mut self, name: &str) -> Option<String> {
        match &mut self.notes {
            Some(notes) => {
                let existing_note = notes.get(name).cloned();
                notes.remove(name);
                if let Some(d) = existing_note {
                    return Some(d.clone());
                } else {
                    None
                }
            }
            None => None,
        }
    }
}

pub trait TokenVerifier {
    fn verify(token: &Box<dyn JsonWebToken>) -> bool;
}
