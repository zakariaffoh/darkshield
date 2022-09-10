use std::collections::HashMap;

use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};

use crate::auditable::AuditableModel;

const HASH_ALGORITHM_DEFAULT: &str = "pbkdf2-sha256";
const HASH_ITERATIONS_DEFAULT: u32 = 27500;

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub password_policy: String,
    pub not_email: Option<bool>,
    pub not_username: Option<bool>,
    pub not_birthdate: Option<bool>,
    pub black_list_passwords: Option<Vec<String>>,
    pub password_digits: Option<bool>,
    pub password_min_length: Option<bool>,
    pub password_expired_after_days: Option<u32>,
    pub password_max_length: Option<bool>,
    pub min_upper_case: Option<u32>,
    pub min_lower_case: Option<u32>,
    pub regex_pattern: Option<String>,
    pub special_chars: Option<u32>,
    pub history_look_back: Option<u32>,
    pub hash_algorithm: Option<String>,
    pub hash_iteration: u32,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            password_policy: Default::default(),
            not_email: Default::default(),
            not_username: Default::default(),
            not_birthdate: Default::default(),
            black_list_passwords: Default::default(),
            password_digits: Default::default(),
            password_min_length: Default::default(),
            password_expired_after_days: Default::default(),
            password_max_length: Default::default(),
            min_upper_case: Default::default(),
            min_lower_case: Default::default(),
            regex_pattern: Default::default(),
            special_chars: Default::default(),
            history_look_back: Default::default(),
            hash_algorithm: Some(HASH_ALGORITHM_DEFAULT.to_owned()),
            hash_iteration: HASH_ITERATIONS_DEFAULT,
        }
    }
}
#[derive(Debug, Serialize, Deserialize, ToSql, FromSql, PartialEq, Eq, Hash)]
#[postgres(name = "sslenforcementenum")]
pub enum SslEnforcementEnum {
    NONE,
    ALL,
    EXTERNAL,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RealmModel {
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
    pub registration_allowed: Option<bool>,
    pub register_email_as_username: Option<bool>,
    pub verify_email: Option<bool>,
    pub remember_me: Option<bool>,
    pub reset_password_allowed: Option<bool>,
    pub revoke_refresh_token: Option<bool>,
    pub login_with_email_allowed: Option<bool>,
    pub duplicated_email_allowed: Option<bool>,

    pub ssl_enforcement: Option<SslEnforcementEnum>,
    pub password_policy: Option<PasswordPolicy>,
    pub edit_user_name_allowed: Option<bool>,
    pub refresh_token_max_reuse: Option<i32>,
    pub access_token_lifespan: Option<i32>,

    pub action_tokens_lifespan: Option<i32>,
    pub access_code_lifespan: Option<i32>,
    pub access_code_lifespan_user_action: Option<i32>,
    pub access_code_lifespan_login: Option<i32>,
    pub master_admin_client: Option<String>,
    pub events_enabled: Option<bool>,
    pub admin_events_enabled: Option<bool>,
    pub not_before: Option<i32>,
    pub attributes: Option<HashMap<String, Option<String>>>,
    pub metadata: Option<AuditableModel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RealmCreateModel {
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
}

impl Into<RealmModel> for RealmCreateModel {
    fn into(self) -> RealmModel {
        RealmModel {
            realm_id: self.realm_id,
            name: self.name,
            display_name: self.display_name,
            enabled: self.enabled,
            registration_allowed: None,
            register_email_as_username: None,
            verify_email: None,
            remember_me: None,
            reset_password_allowed: None,
            revoke_refresh_token: None,
            login_with_email_allowed: None,
            duplicated_email_allowed: None,

            ssl_enforcement: None,
            password_policy: None,
            edit_user_name_allowed: None,
            refresh_token_max_reuse: None,
            access_token_lifespan: None,

            action_tokens_lifespan: None,
            access_code_lifespan: None,
            access_code_lifespan_user_action: None,
            access_code_lifespan_login: None,
            master_admin_client: None,
            events_enabled: None,
            admin_events_enabled: None,
            not_before: None,
            attributes: None,
            metadata: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RealmUpdateModel {
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
    pub registration_allowed: Option<bool>,
    pub register_email_as_username: Option<bool>,
    pub verify_email: Option<bool>,
    pub remember_me: Option<bool>,
    pub reset_password_allowed: Option<bool>,
    pub revoke_refresh_token: Option<bool>,
    pub login_with_email_allowed: Option<bool>,
    pub duplicated_email_allowed: Option<bool>,
    pub ssl_enforcement: Option<SslEnforcementEnum>,
    pub password_policy: Option<PasswordPolicy>,
    pub edit_user_name_allowed: Option<bool>,
    pub refresh_token_max_reuse: Option<i32>,
    pub access_token_lifespan: Option<i32>,
    pub action_tokens_lifespan: Option<i32>,
    pub access_code_lifespan: Option<i32>,
    pub access_code_lifespan_user_action: Option<i32>,
    pub access_code_lifespan_login: Option<i32>,
    pub master_admin_client: Option<String>,
    pub events_enabled: Option<bool>,
    pub admin_events_enabled: Option<bool>,
    pub not_before: Option<i32>,
    pub attributes: Option<HashMap<String, Option<String>>>,
}

impl Into<RealmModel> for RealmUpdateModel {
    fn into(self) -> RealmModel {
        RealmModel {
            realm_id: String::new(),
            name: self.name,
            display_name: self.display_name,
            enabled: self.enabled,
            registration_allowed: self.registration_allowed,
            register_email_as_username: self.register_email_as_username,
            verify_email: self.verify_email,
            remember_me: self.remember_me,
            reset_password_allowed: self.reset_password_allowed,
            revoke_refresh_token: self.revoke_refresh_token,
            login_with_email_allowed: self.login_with_email_allowed,
            duplicated_email_allowed: self.duplicated_email_allowed,
            ssl_enforcement: self.ssl_enforcement,
            password_policy: self.password_policy,
            edit_user_name_allowed: self.edit_user_name_allowed,
            refresh_token_max_reuse: self.refresh_token_max_reuse,
            access_token_lifespan: self.access_token_lifespan,
            action_tokens_lifespan: self.action_tokens_lifespan,
            access_code_lifespan: self.access_code_lifespan,
            access_code_lifespan_user_action: self.access_code_lifespan_user_action,
            access_code_lifespan_login: self.access_code_lifespan_login,
            master_admin_client: self.master_admin_client,
            events_enabled: self.events_enabled,
            admin_events_enabled: self.admin_events_enabled,
            not_before: self.not_before,
            attributes: self.attributes,
            metadata: None,
        }
    }
}
