use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};

use crate::auditable::AuditableModel;

use super::{
    attributes::{AttributeHelper, AttributeValue, AttributesMap},
    auth::RequiredActionEnum,
    credentials::CredentialRepresentation,
    realm::RealmModel,
};

#[derive(Debug, Serialize, Deserialize, ToSql, FromSql)]
pub enum UserStorageEnum {
    Local,
    Ldap,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserModel {
    pub user_id: String,
    pub realm_id: String,
    pub user_name: String,
    pub enabled: bool,
    pub email: String,
    pub email_verified: Option<bool>,
    pub required_actions: Option<Vec<RequiredActionEnum>>,
    pub not_before: Option<i64>,
    pub user_storage: Option<UserStorageEnum>,
    pub attributes: Option<AttributesMap>,
    pub is_service_account: Option<bool>,
    pub service_account_client_link: Option<String>,
    pub metadata: AuditableModel,
}

impl Default for UserModel {
    fn default() -> Self {
        Self {
            user_id: Default::default(),
            realm_id: Default::default(),
            user_name: Default::default(),
            enabled: Default::default(),
            email: Default::default(),
            email_verified: Default::default(),
            required_actions: Default::default(),
            not_before: Default::default(),
            user_storage: Default::default(),
            attributes: Default::default(),
            is_service_account: Default::default(),
            service_account_client_link: Default::default(),
            metadata: Default::default(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct UserCreateModel {
    pub user_name: String,
    pub enabled: bool,
    pub email: String,
    pub email_verified: Option<bool>,
    pub required_actions: Option<Vec<RequiredActionEnum>>,
    pub not_before: Option<i64>,
    pub credential: CredentialRepresentation,
    pub user_storage: Option<UserStorageEnum>,
    pub attributes: Option<AttributesMap>,
    pub is_service_account: Option<bool>,
    pub service_account_client_link: Option<String>,
}

impl Into<UserModel> for UserCreateModel {
    fn into(self) -> UserModel {
        UserModel {
            user_id: Default::default(),
            realm_id: Default::default(),
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
            metadata: AuditableModel::default(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct UserUpdateModel {
    pub enabled: bool,
    pub email: String,
    pub email_verified: Option<bool>,
    pub required_actions: Option<Vec<RequiredActionEnum>>,
    pub not_before: Option<i64>,
    pub attributes: Option<AttributesMap>,
    pub is_service_account: Option<bool>,
    pub service_account_client_link: Option<String>,
}

impl Into<UserModel> for UserUpdateModel {
    fn into(self) -> UserModel {
        UserModel {
            user_id: Default::default(),
            realm_id: Default::default(),
            user_name: String::new(),
            enabled: self.enabled,
            email: self.email,
            email_verified: self.email_verified,
            required_actions: self.required_actions,
            not_before: self.not_before,
            user_storage: None,
            attributes: self.attributes,
            is_service_account: self.is_service_account,
            service_account_client_link: self.service_account_client_link,
            metadata: AuditableModel::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserPagingResult {
    pub page_size: Option<u64>,
    pub page_index: Option<u64>,
    pub total_count: Option<u64>,
    pub users: Vec<UserModel>,
}

#[derive(Serialize, Deserialize)]
pub struct UserConsentModel {
    pub consent_id: String,
    pub realm_id: String,
    pub user_id: String,
    pub granted_client_scopes: Vec<String>,
    pub expiry_timestamp: Option<i64>,
    pub last_updated_date_timestamp: Option<i64>,
}

pub struct UserProfileHelper;

impl UserProfileHelper {
    const REALM_USER_PROFILE_BASIC: &'static str = "user.profile.check.basic";

    pub fn validate_user_profile_and_attributes(
        realm: &RealmModel,
        user: &UserModel,
    ) -> Result<(), String> {
        let check_user_basic_profile = UserProfileHelper::check_user_basic_profile(&realm);
        if let Some(attributes) = &user.attributes {
            let mut invalid_attributes: Vec<String> = Vec::new();
            for (name, value) in attributes.iter() {
                if !AttributeHelper::is_valid_attribute(&value) {
                    invalid_attributes.push(name.to_string());
                }
            }
            if !invalid_attributes.is_empty() {
                return Err(serde_json::to_string(&invalid_attributes).unwrap());
            }
        } else {
            if check_user_basic_profile {
                return Err(
                    "first_name and last_name attributes mut be set in the user attributes map"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }

    fn check_user_basic_profile(realm: &RealmModel) -> bool {
        if let Some(attributes) = &realm.attributes {
            let user_profile_basic = attributes.get(UserProfileHelper::REALM_USER_PROFILE_BASIC);
            if let Some(user_profile) = user_profile_basic {
                return AttributeHelper::bool_value(&user_profile).unwrap_or_default();
            }
        }
        return false;
    }
}

pub struct UserAttributesHelper;

impl UserAttributesHelper {
    pub const USER_PROFILE_FIRST_NAME: &'static str = "user.profile.first_name";
    pub const USER_PROFILE_LAST_NAME: &'static str = "user.profile.last_name";
    pub const USER_PROFILE_NICK_NAME: &'static str = "user.profile.nick_name";
    pub const USER_PROFILE_GENDER: &'static str = "user.profile.gender";
    pub const USER_PROFILE_BIRTH_DATE: &'static str = "user.profile.birthdate";
    pub const USER_PROFILE_EMAIL: &'static str = "user.profile.email";
    pub const USER_PROFILE_MOBILE: &'static str = "user.profile.mobile";
    pub const USER_PROFILE_TELEPHONE: &'static str = "user.profile.telephone";
    pub const USER_PROFILE_PREFIX: &'static str = "user.profile.";
    pub const USER_ATTRIBUTES_PREFIX: &'static str = "user.attribute.";

    pub fn find_user_profile_attribute(
        _attributes: &Option<AttributesMap>,
        _attribute_name: &str,
    ) -> Result<AttributeValue, String> {
        todo!()
    }
}
