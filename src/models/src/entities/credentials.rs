use super::realm::RealmModel;
use crate::{auditable::AuditableModel, credentials::otp::OTPPolicy};
use chrono::{DateTime, Utc};
use crypto::random::generate_random_bytes;
use postgres_types::ToSql;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub trait CredentialInput {
    fn credential_id(&self) -> String;

    fn credentialm_type(&self) -> String;

    fn challenge_response(&self) -> String;
}

enum CredentialDataEnum {
    HashAlgorithm,
    HashIteration,
    HashSalt,
    Secret,
    DerivedKeySize,
}

impl ToString for CredentialDataEnum {
    fn to_string(&self) -> String {
        match &self {
            CredentialDataEnum::DerivedKeySize => "derived_key_size".to_owned(),
            CredentialDataEnum::HashIteration => "hash_iteration".to_owned(),
            CredentialDataEnum::HashSalt => "hash_salt".to_owned(),
            CredentialDataEnum::Secret => "secret".to_owned(),
            CredentialDataEnum::HashAlgorithm => "hash_algorithm".to_owned(),
        }
    }
}

pub type CredentialFieldsMap = HashMap<String, CredentialFieldEnum>;

pub struct CredentialModel {
    pub credential_type: String,
    pub realm_id: String,
    pub user_id: String,
    pub credential_id: String,
    pub user_label: Option<String>,
    pub secret_data: Option<CredentialFieldsMap>,
    pub credential_data: Option<CredentialFieldsMap>,
    pub priority: i64,
    pub metadata: Option<AuditableModel>,
}

impl CredentialModel {
    pub fn credential_data(credential_data: Option<CredentialFieldsMap>) -> Self {
        CredentialModel {
            credential_type: Default::default(),
            realm_id: Default::default(),
            user_id: Default::default(),
            credential_id: String::new(),
            user_label: None,
            secret_data: None,
            credential_data: credential_data,
            priority: Default::default(),
            metadata: None,
        }
    }
    pub fn secret_data(secret_data: Option<CredentialFieldsMap>) -> Self {
        CredentialModel {
            credential_type: Default::default(),
            realm_id: Default::default(),
            user_id: Default::default(),
            credential_id: Default::default(),
            user_label: None,
            secret_data: secret_data,
            credential_data: None,
            priority: Default::default(),
            metadata: None,
        }
    }
}

impl Default for CredentialModel {
    fn default() -> Self {
        Self {
            credential_type: Default::default(),
            realm_id: Default::default(),
            user_id: Default::default(),
            credential_id: Default::default(),
            user_label: Default::default(),
            secret_data: Default::default(),
            credential_data: Default::default(),
            priority: Default::default(),
            metadata: Default::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, ToSql)]
pub enum CredentialTypeEnum {
    PASSWORD,
    PasswordHistory,
    SECRET,
    TOTP,
    HOTP,
}

impl ToString for CredentialTypeEnum {
    fn to_string(&self) -> String {
        match &self {
            CredentialTypeEnum::PASSWORD => "password".to_owned(),
            CredentialTypeEnum::PasswordHistory => "password-history".to_owned(),
            CredentialTypeEnum::SECRET => "secret".to_owned(),
            CredentialTypeEnum::TOTP => "totp".to_owned(),
            CredentialTypeEnum::HOTP => "hotp".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialFieldEnum {
    Str(String),
    Int(i64),
    Map(HashMap<String, String>),
}

pub struct OTPCredentialData {
    pub sub_type: Option<String>,
    pub digits: Option<i64>,
    pub counter: Option<i64>,
    pub period: Option<i64>,
    pub algorithm: Option<String>,
}

fn string_value_or_default(
    field: &str,
    configs: &HashMap<String, CredentialFieldEnum>,
) -> Option<String> {
    let field_value = configs.get(field);
    match field_value {
        Some(value) => match value {
            CredentialFieldEnum::Str(ref v) => Some(v.to_string()),
            _ => None,
        },
        None => None,
    }
}

fn int_value_or_default(
    field: &str,
    configs: &HashMap<String, CredentialFieldEnum>,
) -> Option<i64> {
    let field_value = configs.get(field);
    match field_value {
        Some(value) => match value {
            CredentialFieldEnum::Int(v) => Some(*v),
            _ => None,
        },
        None => None,
    }
}

fn map_value_or_default(
    field: &str,
    configs: &HashMap<String, CredentialFieldEnum>,
) -> Option<HashMap<String, String>> {
    let field_value = configs.get(field);
    match field_value {
        Some(value) => match value {
            CredentialFieldEnum::Map(v) => Some(v.clone()),
            _ => None,
        },
        None => None,
    }
}

impl OTPCredentialData {
    pub fn new(sub_type: &str, digits: i64, counter: i64, period: i64, algorithm: &str) -> Self {
        Self {
            sub_type: Some(sub_type.to_owned()),
            digits: Some(digits),
            counter: Some(counter),
            period: Some(period),
            algorithm: Some(algorithm.to_owned()),
        }
    }
    pub fn from(credential_data: &HashMap<String, CredentialFieldEnum>) -> Self {
        Self {
            sub_type: string_value_or_default("sub_type", &credential_data),
            digits: int_value_or_default("digits", &credential_data),
            counter: int_value_or_default("counter", &credential_data),
            period: int_value_or_default("period", &credential_data),
            algorithm: string_value_or_default("algorithm", &credential_data),
        }
    }
}

pub struct OTPSecretData(Option<String>);

impl OTPSecretData {
    pub fn new(value: String) -> Self {
        Self(Some(value))
    }

    pub fn from(credential_data: &HashMap<String, CredentialFieldEnum>) -> Self {
        Self(string_value_or_default("value", credential_data))
    }
}

pub struct OTPCredentialModel {
    model: CredentialModel,
    credential_data: OTPCredentialData,
    secret_data: OTPSecretData,
}

impl OTPCredentialModel {
    pub fn new(
        secret_value: &str,
        sub_type: &str,
        digits: i64,
        counter: i64,
        period: i64,
        algorithm: &str,
    ) -> Self {
        let mut model = OTPCredentialModel {
            model: CredentialModel::default(),
            credential_data: OTPCredentialData::new(sub_type, digits, counter, period, algorithm),
            secret_data: OTPSecretData::new(secret_value.to_owned()),
        };
        model.fill_credential_data();
        model
    }

    pub fn new_totp(secret_value: &str, digits: i64, period: i64, algorithm: &str) -> Self {
        let mut model = OTPCredentialModel {
            model: CredentialModel::default(),
            credential_data: OTPCredentialData::new("TOTP", digits, 0, period, algorithm),
            secret_data: OTPSecretData::new(secret_value.to_owned()),
        };
        model.fill_credential_data();
        model
    }

    pub fn new_hotp(secret_value: &str, digits: i64, period: i64, algorithm: &str) -> Self {
        let mut model = OTPCredentialModel {
            model: CredentialModel::default(),
            credential_data: OTPCredentialData::new("HOTP", digits, 0, period, algorithm),
            secret_data: OTPSecretData::new(secret_value.to_owned()),
        };
        model.fill_credential_data();
        model
    }

    pub fn from_policy(
        &self,
        realm: &RealmModel,
        secret_value: &str,
        user_label: &str,
    ) -> Result<Self, String> {
        if realm.password_policy.is_none() {
            return Err("Invalid password policy".to_string());
        } else {
            let otp_policy = OTPPolicy::from_realm(&realm);
            let credential_data = OTPCredentialData::new(
                otp_policy.otp_type(),
                otp_policy.digits(),
                otp_policy.initial_counter(),
                otp_policy.period(),
                otp_policy.algorithm(),
            );
            let secret_data = OTPSecretData(Some(secret_value.to_owned()));
            let mut otp_credential = Self {
                model: CredentialModel::default(),
                credential_data,
                secret_data,
            };
            otp_credential.fill_credential_data();
            otp_credential.set_user_label(user_label);
            Ok(otp_credential)
        }
    }

    pub fn update_counter(&mut self, counter: i64) {
        self.credential_data.counter = Some(counter);
        self.set_credential_data();
    }

    pub fn get_credential_data(&self) -> &OTPCredentialData {
        &self.credential_data
    }

    pub fn get_secret_data(&self) -> &OTPSecretData {
        &self.secret_data
    }

    fn set_credential_data(&mut self) {
        let mut credential_data = HashMap::new();
        if self.credential_data.sub_type.is_some() {
            credential_data.insert(
                "sub_type".to_string(),
                CredentialFieldEnum::Str(self.credential_data.sub_type.clone().unwrap()),
            );
        }
        if self.credential_data.digits.is_some() {
            credential_data.insert(
                "digits".to_string(),
                CredentialFieldEnum::Int(self.credential_data.digits.unwrap()),
            );
        }
        if self.credential_data.counter.is_some() {
            credential_data.insert(
                "counter".to_string(),
                CredentialFieldEnum::Int(self.credential_data.counter.unwrap()),
            );
        }
        if self.credential_data.period.is_some() {
            credential_data.insert(
                "period".to_string(),
                CredentialFieldEnum::Int(self.credential_data.period.unwrap()),
            );
        }
        if self.credential_data.algorithm.is_some() {
            credential_data.insert(
                "algorithm".to_string(),
                CredentialFieldEnum::Str(self.credential_data.algorithm.clone().unwrap()),
            );
        }
        self.model.credential_data = Some(credential_data);
    }

    fn set_secret_data(&mut self) {
        let mut secret_data = HashMap::new();
        if self.secret_data.0.is_some() {
            secret_data.insert(
                "value".to_owned(),
                CredentialFieldEnum::Str(self.secret_data.0.clone().unwrap()),
            );
        }
        self.model = CredentialModel::secret_data(Some(secret_data));
    }

    fn set_credential_type(&mut self, credential_type: &str) {
        self.credential_data.sub_type = Some(credential_type.to_owned());
    }

    fn fill_credential_data(&mut self) {
        self.set_credential_data();
        self.set_secret_data();
        self.set_credential_type("otp");
    }

    fn set_user_label(&mut self, user_label: &str) {
        self.model.user_label = Some(user_label.to_string());
    }
}

pub struct PasswordCredentialData {
    pub hash_iterations: Option<i64>,
    pub algorithm: Option<String>,
    pub additional_parameters: Option<HashMap<String, String>>,
}

impl PasswordCredentialData {
    pub fn new(
        hash_iterations: i64,
        algorithm: &str,
        additional_parameters: HashMap<String, String>,
    ) -> Self {
        Self {
            hash_iterations: Some(hash_iterations),
            algorithm: Some(algorithm.to_owned()),
            additional_parameters: Some(additional_parameters),
        }
    }

    pub fn from(credential_data: &HashMap<String, CredentialFieldEnum>) -> Self {
        Self {
            hash_iterations: int_value_or_default("hash_iterations", credential_data),
            algorithm: string_value_or_default("algorithm", credential_data),
            additional_parameters: map_value_or_default("additional_parameters", credential_data),
        }
    }
}

pub struct PasswordSecretData {
    pub value: Option<String>,
    pub salt: Option<String>,
    pub additional_parameters: Option<HashMap<String, String>>,
}

impl PasswordSecretData {
    pub fn new(value: &str, salt: &str, additional_parameters: HashMap<String, String>) -> Self {
        Self {
            value: Some(value.to_owned()),
            salt: Some(salt.to_owned()),
            additional_parameters: Some(additional_parameters),
        }
    }

    pub fn from(secret_data: &HashMap<String, CredentialFieldEnum>) -> Self {
        Self {
            value: string_value_or_default("value", secret_data),
            salt: string_value_or_default("salt", secret_data),
            additional_parameters: map_value_or_default("value", secret_data),
        }
    }
}

pub struct PasswordCredentialModel {
    model: CredentialModel,
    credential_data: PasswordCredentialData,
    secret_data: PasswordSecretData,
}

impl PasswordCredentialModel {
    pub const PASSWORD_CREDENTIAL_TYPE: &'static str = "password";
    pub const PASSWORD_HISTORY_CREDENTIAL_TYPE: &'static str = "password-history";

    pub fn new(credential_data: PasswordCredentialData, secret_data: PasswordSecretData) -> Self {
        let mut password = PasswordCredentialModel {
            model: CredentialModel::default(),
            credential_data: credential_data,
            secret_data: secret_data,
        };
        password.fill_credential_data();
        password
    }

    pub fn from(algorithm: &str, salt: &str, hash_iterations: i64, encoded_password: &str) -> Self {
        let credential_data =
            PasswordCredentialData::new(hash_iterations, algorithm, HashMap::new());
        let secret_data = PasswordSecretData::new(encoded_password, salt, HashMap::new());
        let mut password = PasswordCredentialModel::new(credential_data, secret_data);
        password.set_credential_data();
        password.set_secret_data();
        password.set_credential_type(PasswordCredentialModel::PASSWORD_CREDENTIAL_TYPE.to_owned());
        password
    }

    pub fn from_credential(credential_model: &CredentialModel) -> Self {
        let credential_data = PasswordCredentialData::from(
            &credential_model
                .credential_data
                .as_ref()
                .unwrap_or(&HashMap::new() as &HashMap<String, CredentialFieldEnum>),
        );
        let secret_data = PasswordSecretData::from(
            &credential_model
                .secret_data
                .as_ref()
                .unwrap_or(&HashMap::new() as &HashMap<String, CredentialFieldEnum>),
        );

        let mut password_credential_model =
            PasswordCredentialModel::new(credential_data, secret_data);

        password_credential_model.set_metadata(credential_model.metadata.clone());
        password_credential_model.set_credential_data_model(&credential_model.credential_data);
        password_credential_model.set_secret_data_model(&credential_model.secret_data);
        password_credential_model.set_credential_id(credential_model.credential_id.clone());
        password_credential_model.set_credential_type(credential_model.credential_type.clone());
        password_credential_model.set_user_label(credential_model.user_label.clone());

        return password_credential_model;
    }

    pub fn from_password(password: &str) -> Self {
        PasswordCredentialModel::from("", "", 0, password)
    }

    pub fn password_credential_data(&self) -> &PasswordCredentialData {
        &self.credential_data
    }

    pub fn password_secret_data(&self) -> &PasswordSecretData {
        &self.secret_data
    }

    fn set_credential_data(&mut self) {
        let mut credential_data = HashMap::new();
        if self.credential_data.hash_iterations.is_some() {
            credential_data.insert(
                "sub_type".to_string(),
                CredentialFieldEnum::Int(self.credential_data.hash_iterations.unwrap()),
            );
        }

        if self.credential_data.algorithm.is_some() {
            credential_data.insert(
                "algorithm".to_string(),
                CredentialFieldEnum::Str(self.credential_data.algorithm.as_ref().unwrap().clone()),
            );
        }

        if self.credential_data.additional_parameters.is_some() {
            credential_data.insert(
                "algorithm".to_string(),
                CredentialFieldEnum::Map(
                    self.credential_data
                        .additional_parameters
                        .as_ref()
                        .unwrap()
                        .clone(),
                ),
            );
        }
        self.model.credential_data = Some(credential_data);
    }

    fn set_secret_data(&mut self) {
        let mut secret_data = HashMap::new();
        if self.secret_data.value.is_some() {
            secret_data.insert(
                "value".to_owned(),
                CredentialFieldEnum::Str(self.secret_data.value.as_ref().unwrap().to_owned()),
            );
        }
        if self.secret_data.salt.is_some() {
            secret_data.insert(
                "salt".to_owned(),
                CredentialFieldEnum::Str(self.secret_data.salt.as_ref().unwrap().to_owned()),
            );
        }
        self.model = CredentialModel::secret_data(Some(secret_data));
    }

    fn fill_credential_data(&mut self) {
        self.set_credential_data();
        self.set_secret_data();
        self.set_credential_type(PasswordCredentialModel::PASSWORD_CREDENTIAL_TYPE.to_owned());
    }

    fn set_metadata(&mut self, metadata: Option<AuditableModel>) {
        self.model.metadata = metadata;
    }

    fn set_credential_id(&mut self, credential_id: String) {
        self.model.credential_id = credential_id;
    }

    fn set_credential_type(&mut self, credential_type: String) {
        self.model.credential_type = credential_type;
    }

    fn set_user_label(&mut self, user_label: Option<String>) {
        self.model.user_label = user_label;
    }

    fn set_secret_data_model(
        &mut self,
        secret_data: &Option<HashMap<String, CredentialFieldEnum>>,
    ) {
        self.model.secret_data = PasswordCredentialModel::clone_credential_map(secret_data);
    }

    fn set_credential_data_model(
        &mut self,
        credential_data: &Option<HashMap<String, CredentialFieldEnum>>,
    ) {
        self.model.credential_data = PasswordCredentialModel::clone_credential_map(credential_data);
    }

    fn clone_credential_map(
        data: &Option<HashMap<String, CredentialFieldEnum>>,
    ) -> Option<HashMap<String, CredentialFieldEnum>> {
        match data {
            None => None,
            Some(cr) => {
                let mut data: HashMap<String, CredentialFieldEnum> = HashMap::new();
                for (k, v) in cr.iter() {
                    data.insert(k.to_string(), v.clone());
                }
                Some(data)
            }
        }
    }
}

pub struct UserCredentialModel {
    credential_id: Option<String>,
    credential_type: Option<String>,
    challenge_response: Option<String>,
    device: Option<String>,
    algorithm: Option<String>,
    admin_request: Option<bool>,
    notes: Option<HashMap<String, String>>,
}

impl UserCredentialModel {
    pub fn new(
        credential_id: String,
        credential_type: String,
        challenge_response: String,
        device: Option<String>,
        algorithm: Option<String>,
        admin_request: Option<bool>,
    ) -> Self {
        Self {
            credential_id: Some(credential_id),
            credential_type: Some(credential_type),
            challenge_response: Some(challenge_response),
            device: device,
            algorithm: algorithm,
            admin_request: admin_request,
            notes: None,
        }
    }

    pub fn from_otp(
        credential_id: &str,
        credential_type: &str,
        challenge: &str,
    ) -> Result<Self, String> {
        let cred_type = credential_type.to_lowercase();
        match cred_type.as_str() {
            "totp" => {
                let mut cred = UserCredentialModel::from_totp(challenge);
                cred.credential_id = Some(credential_id.to_string());
                Ok(cred)
            }
            "hotp" => {
                let mut cred = UserCredentialModel::from_hotp(challenge);
                cred.credential_id = Some(credential_id.to_string());
                Ok(cred)
            }
            "otp" => {
                let mut cred = UserCredentialModel::from_hotp(challenge);
                cred.credential_id = Some(credential_id.to_string());
                cred.credential_type = Some("otp".to_string());
                Ok(cred)
            }
            _ => Err("Unknown OTP type".to_owned()),
        }
    }

    pub fn from_totp(challenge: &str) -> Self {
        Self {
            credential_id: Default::default(),
            credential_type: Some("totp".to_owned()),
            challenge_response: Some(challenge.to_string()),
            device: Default::default(),
            algorithm: Default::default(),
            admin_request: Default::default(),
            notes: Default::default(),
        }
    }

    pub fn from_hotp(challenge: &str) -> Self {
        Self {
            credential_id: Default::default(),
            credential_type: Some("hotp".to_owned()),
            challenge_response: Some(challenge.to_string()),
            device: Default::default(),
            algorithm: Default::default(),
            admin_request: Default::default(),
            notes: Default::default(),
        }
    }

    pub fn from_secret(secret: &str) -> Self {
        Self {
            credential_id: Default::default(),
            credential_type: Some("secret".to_owned()),
            challenge_response: Some(secret.to_string()),
            device: Default::default(),
            algorithm: Default::default(),
            admin_request: Default::default(),
            notes: Default::default(),
        }
    }

    pub fn from_password(password: &str) -> Self {
        Self {
            credential_id: Default::default(),
            credential_type: Some("password".to_owned()),
            challenge_response: Some(password.to_string()),
            device: Default::default(),
            algorithm: Default::default(),
            admin_request: Default::default(),
            notes: Default::default(),
        }
    }

    pub fn from_kerberos(kerberos: &str) -> Self {
        Self {
            credential_id: Default::default(),
            credential_type: Some("kerberos".to_owned()),
            challenge_response: Some(kerberos.to_string()),
            device: Default::default(),
            algorithm: Default::default(),
            admin_request: Default::default(),
            notes: Default::default(),
        }
    }

    pub fn generate_secret() -> UserCredentialModel {
        Self {
            credential_id: Default::default(),
            credential_type: Some("secret".to_owned()),
            challenge_response: Some(generate_random_bytes(10)),
            device: Default::default(),
            algorithm: Default::default(),
            admin_request: Default::default(),
            notes: Default::default(),
        }
    }

    pub fn is_otp(credential_type: &str) -> bool {
        credential_type == "totp" || credential_type == "hotp"
    }

    pub fn credential_id(&self) -> &Option<String> {
        &self.credential_id
    }

    pub fn credential_type(&self) -> &Option<String> {
        &self.credential_type
    }

    pub fn challenge_response(&self) -> &Option<String> {
        &self.challenge_response
    }

    pub fn is_admin_request(&self) -> Option<bool> {
        self.admin_request
    }

    pub fn value(&self) -> &Option<String> {
        &self.challenge_response
    }

    pub fn set_value(&mut self, value: &str) {
        self.challenge_response = Some(value.to_owned())
    }

    pub fn device(&self) -> &Option<String> {
        &self.device
    }

    pub fn set_device(&mut self, device: &str) {
        self.challenge_response = Some(device.to_owned())
    }

    pub fn algorithm(&self) -> &Option<String> {
        &self.device
    }

    pub fn set_algorithm(&mut self, algorithm: &str) {
        self.algorithm = Some(algorithm.to_owned())
    }

    pub fn set_note(&mut self, key: &str, note: &str) {
        if self.notes.is_none() {
            let mut map = HashMap::new();
            map.insert(key.to_owned(), note.to_owned());
            self.notes = Some(map)
        } else {
            if let Some(notes) = &mut self.notes {
                notes.insert(key.to_owned(), note.to_owned());
            }
        }
    }

    pub fn remove_note(&mut self, key: &str) {
        if let Some(notes) = &mut self.notes {
            notes.remove_entry(key);
        }
    }

    pub fn get_note(&self, key: &str) -> Option<&String> {
        if let Some(notes) = &self.notes {
            let value = notes.get(key);
            return value.clone();
        }
        None
    }

    pub fn notes(&self) -> &Option<HashMap<String, String>> {
        &self.notes
    }
}

#[derive(Serialize, Deserialize)]
pub struct CredentialRepresentation {
    pub credential_type: CredentialTypeEnum,
    pub is_temporary: Option<bool>,
    pub secret: String,
}

#[derive(Serialize, Deserialize)]
pub struct CredentialViewRepresentation {
    pub credential_id: Option<String>,
    pub credential_type: Option<String>,
    pub user_id: Option<String>,
    pub user_label: Option<String>,
    pub credential_data: HashMap<String, CredentialFieldEnum>,
    pub priority: Option<i64>,
    pub created_by: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize)]
pub struct UserCredentialCreateRepresentation {
    user_label: Option<String>,
    credential_type: CredentialTypeEnum,
    secret: Option<String>,
    is_temporary: Option<bool>,
    created_by: Option<String>,
}
