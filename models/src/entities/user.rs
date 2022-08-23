use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::auditable::AuditableModel;

#[derive(Serialize, Deserialize)]
pub enum UserStorageEnum {
    Local,
    Ldap,
}

#[derive(Serialize, Deserialize)]
pub struct UserModel {
    pub user_id: String,
    pub realm_id: String,
    pub user_name: String,
    pub enabled: bool,
    pub email: String,
    pub email_verified: Option<bool>,
    pub required_actions: Option<Vec<String>>,
    pub not_before: Option<usize>,
    pub user_storage: Option<UserStorageEnum>,
    pub attributes: Option<HashMap<String, String>>,
    pub is_service_account: Option<bool>,
    pub service_account_client_link: Option<String>,
    pub metadata: Option<AuditableModel>,
}

#[derive(Serialize, Deserialize)]
pub struct UserCreateModel {
    pub user_id: String,
    pub realm_id: String,
    pub user_name: String,
    pub enabled: bool,
    pub email: String,
    pub email_verified: Option<bool>,
    pub required_actions: Option<Vec<String>>,
    pub not_before: Option<usize>,
    pub user_storage: Option<UserStorageEnum>,
    pub attributes: Option<HashMap<String, String>>,
    pub is_service_account: Option<bool>,
    pub service_account_client_link: Option<String>,
}

impl Into<UserModel> for UserCreateModel {
    fn into(self) -> UserModel {
        UserModel {
            user_id: self.user_id,
            realm_id: self.realm_id,
            user_name: self.user_name,
            enabled: self.enabled,
            email: self.email,
            email_verified: self.email_verified,
            required_actions: self.required_actions,
            not_before: self.not_before,
            user_storage: self.user_storage,
            attributes: self.attributes,
            is_service_account: self.is_service_account,
            service_account_client_link: self.service_account_client_link,
            metadata: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct UserUpdateModel {
    pub realm_id: String,
    pub enabled: bool,
    pub email: String,
    pub email_verified: Option<bool>,
    pub required_actions: Option<Vec<String>>,
    pub not_before: Option<usize>,
    pub attributes: Option<HashMap<String, String>>,
    pub is_service_account: Option<bool>,
    pub service_account_client_link: Option<String>,
}
