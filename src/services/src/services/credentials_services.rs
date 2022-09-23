use async_trait::async_trait;
use chrono::Utc;
use models::auditable::AuditableModel;
use models::credentials::password::PasswordHashFactory;
use models::entities::attributes::AttributeHelper;
use models::entities::credentials::*;
use models::entities::realm::RealmModel;
use models::entities::user::UserAttributesHelper;
use models::entities::user::UserModel;
use regex::Regex;
use shaku::Component;
use shaku::Interface;
use std::sync::Arc;
use store::providers::interfaces::auth_providers::IRequiredActionProvider;
use store::providers::interfaces::authz_provider::IGroupProvider;
use store::providers::interfaces::authz_provider::IRoleProvider;
use store::providers::interfaces::credential_provider::ICredentialProvider;
use store::providers::interfaces::realm_provider::IRealmProvider;
use store::providers::interfaces::user_provider::IUserProvider;

#[async_trait]
pub trait CredentialInputValidator {
    fn supports_credential_type(&self, credential_type: &str) -> bool;

    async fn is_configured_for(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_type: &str,
    ) -> bool;

    fn is_valid(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_input: &Box<dyn CredentialInput>,
    ) -> bool;

    async fn load_password_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
    ) -> Result<Option<PasswordCredentialModel>, String>;
}

#[async_trait]
pub trait CredentialInputUpdater {
    fn supports_credential_type(&self, credential_type: &str) -> bool;

    fn update_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_input: &Box<dyn CredentialInput>,
    ) -> bool;

    async fn disable_credential_type(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_type: &str,
    ) -> Result<(), String>;

    async fn get_disableable_credential_types(
        self,
        realm: RealmModel,
        user: UserModel,
    ) -> Vec<CredentialModel>;
}

#[async_trait]
pub trait CredentialProvider {
    fn get_credential_type(&self) -> &str;

    async fn create_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential: &CredentialModel,
    ) -> &str;

    async fn delete_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_id: &str,
    ) -> &str;

    async fn credential_from_model(&self, model: &UserCredentialModel) -> CredentialModel;
}

#[async_trait]
pub trait IUserCredentialStore: Interface {
    fn id(&self) -> String;

    async fn create_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        cred: CredentialModel,
    ) -> Result<CredentialModel, String>;

    async fn update_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        cred: &CredentialModel,
    ) -> Result<bool, String>;

    async fn remove_stored_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_id: &str,
    ) -> Result<bool, String>;

    async fn load_stored_credential_by_id(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_id: &str,
    ) -> Result<Option<CredentialModel>, String>;

    async fn load_stored_credentials_by_type(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_type: &str,
    ) -> Result<Vec<CredentialModel>, String>;

    async fn load_stored_credential_by_name_and_type(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_name: &str,
        credential_type: &str,
    ) -> Result<Option<CredentialModel>, String>;

    async fn move_credential_to(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_id: &str,
        new_previous_credential_id: &str,
    ) -> Result<bool, String>;

    async fn load_stored_credentials(
        &self,
        realm: &RealmModel,
        user: &UserModel,
    ) -> Result<Vec<CredentialModel>, String>;

    async fn load_stored_credentials_by_realm_id(
        &self,
        realm_id: &str,
    ) -> Result<Vec<CredentialModel>, String>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IUserCredentialStore)]
pub struct UserCredentialStore {
    #[shaku(inject)]
    credential_provider: Arc<dyn ICredentialProvider>,
}

impl UserCredentialStore {
    pub fn new(provider: &Arc<dyn ICredentialProvider>) -> Self {
        Self {
            credential_provider: Arc::clone(&provider),
        }
    }
}

const PRIORITY_DIFFERENCE: i64 = 10;

#[async_trait]
impl IUserCredentialStore for UserCredentialStore {
    fn id(&self) -> String {
        "local-user-credential-store".to_owned()
    }

    async fn create_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        cred: CredentialModel,
    ) -> Result<CredentialModel, String> {
        let mut credential = cred;
        let mut credentials = self.load_stored_credentials(&realm, &user).await;
        match &mut credentials {
            Ok(creds) => {
                if creds.is_empty() {
                    credential.priority = PRIORITY_DIFFERENCE;
                } else {
                    creds.sort_by(|a, b| a.priority.cmp(&b.priority));
                    credential.priority = creds[0].priority + PRIORITY_DIFFERENCE;
                }
            }
            Err(err) => {
                log::error!("Failed to load user: {} credentials", &user.user_id);
                return Err(err.to_owned());
            }
        }

        if credential.user_label.is_none() || credential.user_label.as_ref().unwrap().is_empty() {
            credential.user_label = Some(user.user_name.clone());
        }
        if credential.credential_id.is_empty() {
            credential.credential_id = uuid::Uuid::new_v4().to_string();
        }

        let mut credential_metadata = credential.metadata.as_ref().clone();
        match &mut credential_metadata {
            Some(res) => {
                let mut metadata = AuditableModel {
                    tenant: res.tenant.clone(),
                    created_by: None,
                    created_at: None,
                    updated_by: None,
                    updated_at: None,
                    version: res.version,
                };

                if res.created_by.is_none() {
                    metadata.created_by = Some(user.user_name.clone());
                }

                if res.created_at.is_none() {
                    metadata.created_at = Some(Utc::now());
                }
                credential.metadata = Some(metadata);
            }
            None => {
                credential.metadata = AuditableModel::from_creator(
                    user.metadata.as_ref().unwrap().tenant.clone(),
                    user.user_name.clone(),
                )
            }
        }
        self.credential_provider
            .create_credential(&realm.realm_id, &user.user_id, credential)
            .await
    }

    async fn update_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        cred: &CredentialModel,
    ) -> Result<bool, String> {
        let existing_credential = self
            .load_stored_credential_by_id(&realm, &user, &cred.credential_id)
            .await;

        match &existing_credential {
            Ok(res) => {
                if res.is_none() {
                    return Ok(true);
                }
            }
            Err(err) => return Err(err.to_owned()),
        }

        let mut credential = existing_credential.unwrap().unwrap();
        credential.secret_data = cred.secret_data.clone();
        credential.credential_type = cred.credential_type.clone();
        credential.user_label = cred.user_label.clone();
        credential.secret_data = cred.secret_data.clone();

        match &mut credential.metadata {
            Some(data) => {
                data.updated_by = Some(user.user_name.to_string());
                data.updated_at = Some(Utc::now());
            }
            None => {
                credential.metadata = AuditableModel::from_updator(
                    user.metadata.as_ref().unwrap().tenant.clone(),
                    user.user_name.to_string(),
                )
            }
        }
        self.credential_provider
            .update_credential(&realm.realm_id, &user.user_id, &credential)
            .await
    }

    async fn remove_stored_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_id: &str,
    ) -> Result<bool, String> {
        let credential = self
            .load_stored_credential_by_id(realm, user, credential_id)
            .await;
        match &credential {
            Ok(res) => {
                if res.is_none() {
                    return Ok(false);
                }
            }
            Err(err) => return Err(err.to_string()),
        }

        let credential = credential.unwrap().unwrap();
        self.credential_provider
            .remove_stored_credential(
                &realm.realm_id,
                &user.user_id,
                &credential_id,
                credential.priority,
                PRIORITY_DIFFERENCE,
            )
            .await
    }

    async fn load_stored_credential_by_id(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_id: &str,
    ) -> Result<Option<CredentialModel>, String> {
        self.credential_provider
            .load_stored_user_credential_by_id(&realm.realm_id, &user.user_id, &credential_id)
            .await
    }

    async fn load_stored_credentials_by_type(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_type: &str,
    ) -> Result<Vec<CredentialModel>, String> {
        self.credential_provider
            .load_stored_credentials_by_type(&realm.realm_id, &user.user_id, &credential_type)
            .await
    }

    async fn load_stored_credential_by_name_and_type(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        user_label: &str,
        credential_type: &str,
    ) -> Result<Option<CredentialModel>, String> {
        self.credential_provider
            .load_stored_credential_by_name_and_type(
                &realm.realm_id,
                &user.user_id,
                &user_label,
                &credential_type,
            )
            .await
    }

    async fn load_stored_credentials(
        &self,
        realm: &RealmModel,
        user: &UserModel,
    ) -> Result<Vec<CredentialModel>, String> {
        self.credential_provider
            .load_stored_credentials(&realm.realm_id, &user.user_id)
            .await
    }

    async fn load_stored_credentials_by_realm_id(
        &self,
        realm_id: &str,
    ) -> Result<Vec<CredentialModel>, String> {
        self.credential_provider
            .load_stored_credentials_by_realm_id(&realm_id)
            .await
    }

    async fn move_credential_to(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_id: &str,
        new_previous_credential_id: &str,
    ) -> Result<bool, String> {
        let credentials = self.load_stored_credentials(&realm, &user).await;
        if let Err(err) = credentials {
            return Err(err);
        }
        let mut user_credentials = credentials.unwrap();
        let user_credentials_ids: Vec<String> = user_credentials
            .iter()
            .map(|r| r.credential_id.clone())
            .collect();
        if !user_credentials_ids.contains(&credential_id.to_owned())
            || !user_credentials_ids.contains(&new_previous_credential_id.to_owned())
        {
            return Ok(false);
        }
        user_credentials.sort_by(|x, y| x.priority.cmp(&y.priority));

        let current_credential = user_credentials
            .iter()
            .find(|x| x.credential_id == credential_id)
            .unwrap();

        let mut credentials_by_priority: Vec<(String, i64)> = Vec::new();
        for credential in user_credentials.iter() {
            if credential.credential_id == new_previous_credential_id {
                credentials_by_priority
                    .push((credential.credential_id.to_owned(), credential.priority));

                credentials_by_priority.push((
                    current_credential.credential_id.to_owned(),
                    current_credential.priority,
                ));
            } else if credential.credential_id == current_credential.credential_id {
                continue;
            } else {
                credentials_by_priority
                    .push((credential.credential_id.to_owned(), credential.priority));
            }
        }
        let mut start_priority = PRIORITY_DIFFERENCE;
        for cr in credentials_by_priority.iter_mut() {
            cr.1 = start_priority;
            start_priority += PRIORITY_DIFFERENCE
        }

        let credential_data: Vec<(String, i64)> = credentials_by_priority
            .iter()
            .map(|cr| (cr.0.to_owned(), cr.1))
            .collect();

        self.credential_provider
            .update_credential_priorities(&realm.realm_id, &credential_data)
            .await
    }
}

#[async_trait]
pub trait IUserCredentialProvider: Interface {}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IUserCredentialProvider)]
pub struct UserCredentialProvider {}

impl IUserCredentialProvider for UserCredentialProvider {}

#[allow(dead_code)]
pub struct PasswordCredentialProvider {
    user_credential_provider: Arc<dyn IUserCredentialProvider>,
}

impl PasswordCredentialProvider {
    pub fn new(provider: Arc<dyn IUserCredentialProvider>) -> Self {
        Self {
            user_credential_provider: Arc::clone(&provider),
        }
    }
}

#[async_trait]
impl CredentialInputUpdater for PasswordCredentialProvider {
    fn supports_credential_type(&self, credential_type: &str) -> bool {
        credential_type.to_uppercase() == "PASSWORD"
    }

    fn update_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_input: &Box<dyn CredentialInput>,
    ) -> bool {
        todo!()
    }

    async fn disable_credential_type(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_type: &str,
    ) -> Result<(), String> {
        todo!()
    }

    async fn get_disableable_credential_types(
        self,
        _realm: RealmModel,
        _user: UserModel,
    ) -> Vec<CredentialModel> {
        Vec::new()
    }
}

#[async_trait]
impl CredentialInputValidator for PasswordCredentialProvider {
    fn supports_credential_type(&self, credential_type: &str) -> bool {
        todo!()
    }

    async fn is_configured_for(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_type: &str,
    ) -> bool {
        let password_credential = self.load_password_credential(&realm, &user).await;
        if let Ok(res) = password_credential {
            if res.is_none() {
                return false;
            }
        }
        return false;
    }

    async fn load_password_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
    ) -> Result<Option<PasswordCredentialModel>, String> {
        todo!()
    }

    fn is_valid(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_input: &Box<dyn CredentialInput>,
    ) -> bool {
        todo!()
    }
}

#[async_trait]
impl CredentialProvider for PasswordCredentialProvider {
    fn get_credential_type(&self) -> &str {
        return "PASSWORD";
    }

    async fn create_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential: &CredentialModel,
    ) -> &str {
        todo!()
    }

    async fn delete_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_id: &str,
    ) -> &str {
        self.user_credential_provider.re
    }

    async fn credential_from_model(&self, model: &UserCredentialModel) -> CredentialModel {
        todo!()
    }
}

#[async_trait]
pub trait IUserCredentialService: Interface {
    async fn user_disable_credential_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> Result<(), String>;

    async fn load_user_credentials(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<CredentialModel>, String>;

    async fn load_user_credentials_view(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<CredentialViewRepresentation>, String>;

    async fn move_credential_to_position(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
        previous_credential_id: &str,
    ) -> Result<(), String>;

    async fn move_credential_to_first(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
    ) -> Result<(), String>;

    async fn reset_user_password(
        &self,
        realm_id: &str,
        user_id: &str,
        password: &PasswordCredentialModel,
    ) -> Result<(), String>;

    async fn disable_credential_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> Result<(), String>;

    async fn user_credential_exists(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
    ) -> Result<bool, String>;

    async fn load_stored_credentials_by_type(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_type: &str,
    ) -> Result<Vec<CredentialModel>, String>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IUserCredentialService)]
pub struct UserCredentialService {
    #[shaku(inject)]
    group_provider: Arc<dyn IGroupProvider>,

    #[shaku(inject)]
    role_provider: Arc<dyn IRoleProvider>,

    #[shaku(inject)]
    user_provider: Arc<dyn IUserProvider>,

    #[shaku(inject)]
    realm_provider: Arc<dyn IRealmProvider>,

    #[shaku(inject)]
    required_actions_provider: Arc<dyn IRequiredActionProvider>,

    #[shaku(inject)]
    credential_store_provider: Arc<dyn IUserCredentialStore>,
}

impl UserCredentialService {
    fn user_storage_provider(&self) -> Arc<dyn IUserCredentialStore> {
        Arc::clone(&self.credential_store_provider)
    }
}

#[async_trait]
impl IUserCredentialStore for UserCredentialService {
    fn id(&self) -> String {
        "user-credential-manager".to_string()
    }

    async fn create_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        cred: CredentialModel,
    ) -> Result<CredentialModel, String> {
        self.user_storage_provider()
            .create_credential(&realm, &user, cred)
            .await
    }

    async fn update_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        cred: &CredentialModel,
    ) -> Result<bool, String> {
        self.user_storage_provider()
            .update_credential(&realm, &user, &cred)
            .await
    }

    async fn remove_stored_credential(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_id: &str,
    ) -> Result<bool, String> {
        if let Some(svc_link) = &user.service_account_client_link {
            if !svc_link.is_empty() {
                return Err("Cannot manage credential for this account".to_owned());
            }
        }

        self.user_storage_provider()
            .remove_stored_credential(&realm, &user, &credential_id)
            .await
    }

    async fn load_stored_credential_by_id(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_id: &str,
    ) -> Result<Option<CredentialModel>, String> {
        self.user_storage_provider()
            .load_stored_credential_by_id(&realm, &user, &credential_id)
            .await
    }

    async fn load_stored_credentials_by_type(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_type: &str,
    ) -> Result<Vec<CredentialModel>, String> {
        self.user_storage_provider()
            .load_stored_credentials_by_type(&realm, &user, &credential_type)
            .await
    }

    async fn load_stored_credential_by_name_and_type(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_name: &str,
        credential_type: &str,
    ) -> Result<Option<CredentialModel>, String> {
        self.user_storage_provider()
            .load_stored_credential_by_name_and_type(
                &realm,
                &user,
                &credential_name,
                &credential_type,
            )
            .await
    }

    async fn move_credential_to(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_id: &str,
        new_previous_credential_id: &str,
    ) -> Result<bool, String> {
        self.user_storage_provider()
            .move_credential_to(&realm, &user, &credential_id, &new_previous_credential_id)
            .await
    }

    async fn load_stored_credentials(
        &self,
        realm: &RealmModel,
        user: &UserModel,
    ) -> Result<Vec<CredentialModel>, String> {
        self.user_storage_provider()
            .load_stored_credentials(&realm, &user)
            .await
    }

    async fn load_stored_credentials_by_realm_id(
        &self,
        realm_id: &str,
    ) -> Result<Vec<CredentialModel>, String> {
        self.user_storage_provider()
            .load_stored_credentials_by_realm_id(&realm_id)
            .await
    }
}

#[async_trait]
impl IUserCredentialService for UserCredentialService {
    async fn user_disable_credential_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> Result<(), String> {
        todo!()
    }

    async fn load_user_credentials(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<CredentialModel>, String> {
        todo!()
    }

    async fn move_credential_to_position(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
        previous_credential_id: &str,
    ) -> Result<(), String> {
        todo!()
    }

    async fn move_credential_to_first(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
    ) -> Result<(), String> {
        todo!()
    }

    async fn reset_user_password(
        &self,
        realm_id: &str,
        user_id: &str,
        password: &PasswordCredentialModel,
    ) -> Result<(), String> {
        todo!()
    }

    async fn disable_credential_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> Result<(), String> {
        todo!()
    }

    async fn load_user_credentials_view(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<CredentialViewRepresentation>, String> {
        todo!()
    }

    async fn user_credential_exists(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
    ) -> Result<bool, String> {
        todo!()
    }

    async fn load_stored_credentials_by_type(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        credential_type: &str,
    ) -> Result<Vec<CredentialModel>, String> {
        self.user_storage_provider()
            .load_stored_credentials_by_type(&realm, &user, &credential_type)
            .await
    }
}

pub struct PolicyValidationError {
    pub message: String,
    pub parameters: Vec<String>,
}

impl ToString for PolicyValidationError {
    fn to_string(&self) -> String {
        todo!()
    }
}

#[async_trait]
pub trait PasswordPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError>;
}

pub struct BlackListPasswordPolicyProvider;

#[async_trait]
impl PasswordPolicyProvider for BlackListPasswordPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        _: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        let black_list_passwords = realm
            .password_policy
            .as_ref()
            .unwrap()
            .black_list_passwords
            .as_ref()
            .unwrap();

        if black_list_passwords.contains(&password.to_owned()) {
            return Err(PolicyValidationError {
                message: "invalidPasswordBlacklistedMessage".to_string(),
                parameters: Vec::new(),
            });
        }
        Ok(())
    }
}

pub struct PasswordDigitPolicyProvider;

#[async_trait]
impl PasswordPolicyProvider for PasswordDigitPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        _: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        let password_digits_count = *realm
            .password_policy
            .as_ref()
            .unwrap()
            .password_digits
            .as_ref()
            .unwrap() as i64;
        let mut count_digit: i64 = 0;
        for c in password.chars() {
            if c.is_digit(10) {
                count_digit += 1;
            }
        }
        if count_digit < password_digits_count {
            return Err(PolicyValidationError {
                message: "invalidPasswordMinDigitsMessage".to_string(),
                parameters: Vec::new(),
            });
        }
        Ok(())
    }
}

pub struct UpperCasePasswordPolicyProvider;

#[async_trait]
impl PasswordPolicyProvider for UpperCasePasswordPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        _: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        let min_upper_case = *realm
            .password_policy
            .as_ref()
            .unwrap()
            .min_upper_case
            .as_ref()
            .unwrap() as i64;
        let mut count_upper_case = 0;
        for c in password.chars() {
            if c.is_uppercase() {
                count_upper_case += 1;
            }
        }
        if count_upper_case < min_upper_case {
            return Err(PolicyValidationError {
                message: "invalidPasswordMinDigitsMessage".to_string(),
                parameters: Vec::new(),
            });
        }
        Ok(())
    }
}

pub struct LowerCasePasswordPolicyProvider;

#[async_trait]
impl PasswordPolicyProvider for LowerCasePasswordPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        _: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        let min_lower_case = *realm
            .password_policy
            .as_ref()
            .unwrap()
            .min_lower_case
            .as_ref()
            .unwrap() as i64;

        let mut count_lower_case = 0;
        for c in password.chars() {
            if c.is_lowercase() {
                count_lower_case += 1;
            }
        }
        if count_lower_case < min_lower_case {
            return Err(PolicyValidationError {
                message: "invalidPasswordMinLowerCaseCharsMessage".to_string(),
                parameters: Vec::new(),
            });
        }
        Ok(())
    }
}

pub struct SpecialCharsPasswordPolicyProvider;

#[async_trait]
impl PasswordPolicyProvider for SpecialCharsPasswordPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        _: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        let special_chars = *realm
            .password_policy
            .as_ref()
            .unwrap()
            .special_chars
            .as_ref()
            .unwrap() as i64;
        let mut count_special_chars = 0;
        for c in password.chars() {
            if !c.is_alphanumeric() {
                count_special_chars += 1;
            }
        }
        if count_special_chars < special_chars {
            return Err(PolicyValidationError {
                message: "invalidPasswordMinSpecialCharsMessage".to_string(),
                parameters: Vec::new(),
            });
        }
        Ok(())
    }
}

pub struct NotUsernamePasswordPolicyProvider;

#[async_trait]
impl PasswordPolicyProvider for NotUsernamePasswordPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        let not_username = *realm
            .password_policy
            .as_ref()
            .unwrap()
            .not_username
            .as_ref()
            .unwrap() as bool;
        if not_username {
            if password.to_lowercase() == user.user_name.to_lowercase() {
                return Err(PolicyValidationError {
                    message: "invalidPasswordNotUsernameMessage".to_string(),
                    parameters: Vec::new(),
                });
            }
        }
        Ok(())
    }
}

pub struct NotEmailPasswordPolicyProvider;

#[async_trait]
impl PasswordPolicyProvider for NotEmailPasswordPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        let not_email = *realm
            .password_policy
            .as_ref()
            .unwrap()
            .not_email
            .as_ref()
            .unwrap() as bool;
        if not_email {
            if password.to_lowercase() == user.email.to_lowercase() {
                return Err(PolicyValidationError {
                    message: "invalidPasswordNotUsernameMessage".to_string(),
                    parameters: Vec::new(),
                });
            }
        }
        Ok(())
    }
}

pub struct NotBirthDatePasswordPolicyProvider;

#[async_trait]
impl PasswordPolicyProvider for NotBirthDatePasswordPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        let birthdate_policy = *realm
            .password_policy
            .as_ref()
            .unwrap()
            .not_birthdate
            .as_ref()
            .unwrap() as bool;
        if birthdate_policy {
            let birth_date_attribute = UserAttributesHelper::find_user_profile_attribute(
                &user.attributes,
                UserAttributesHelper::USER_PROFILE_BIRTH_DATE,
            );
            if let Ok(res) = birth_date_attribute {
                let birth_date_value = AttributeHelper::string_value(&res);
                if let Ok(birth_date) = birth_date_value {
                    if password.to_lowercase() == birth_date.to_lowercase() {
                        return Err(PolicyValidationError {
                            message: "invalidPasswordNotBirthDateMessage".to_string(),
                            parameters: Vec::new(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

pub struct MaximumLengthPasswordPolicyProvider;

#[async_trait]
impl PasswordPolicyProvider for MaximumLengthPasswordPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        _: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        let password_max_length = *realm
            .password_policy
            .as_ref()
            .unwrap()
            .password_max_length
            .as_ref()
            .unwrap() as i64;
        if password_max_length < password.len() as i64 {
            return Err(PolicyValidationError {
                message: "invalidPasswordMaxLengthMessage".to_string(),
                parameters: Vec::new(),
            });
        }
        Ok(())
    }
}

pub struct MinimumLengthPasswordPolicyProvider;

#[async_trait]
impl PasswordPolicyProvider for MinimumLengthPasswordPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        _: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        let password_min_length = *realm
            .password_policy
            .as_ref()
            .unwrap()
            .password_min_length
            .as_ref()
            .unwrap() as i64;
        if password_min_length > password.len() as i64 {
            return Err(PolicyValidationError {
                message: "invalidPasswordMinLengthMessage".to_string(),
                parameters: Vec::new(),
            });
        }
        Ok(())
    }
}

pub struct RegexPatternsPasswordPolicyProvider;

#[async_trait]
impl PasswordPolicyProvider for RegexPatternsPasswordPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        _: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        let regex_pattern = realm
            .password_policy
            .as_ref()
            .unwrap()
            .regex_pattern
            .as_ref()
            .unwrap();

        let response = Regex::new(regex_pattern.as_str())
            .unwrap()
            .is_match(password);
        if !response {
            return Err(PolicyValidationError {
                message: "invalidPasswordRegexPatternMessage".to_string(),
                parameters: Vec::new(),
            });
        }
        Ok(())
    }
}

pub struct PasswordHistoryPolicyProvider {
    user_credential_service: Arc<dyn IUserCredentialService>,
}

impl PasswordHistoryPolicyProvider {
    pub fn new(user_credential_service: Arc<dyn IUserCredentialService>) -> Self {
        Self {
            user_credential_service: Arc::clone(&user_credential_service),
        }
    }

    fn check_any_credential_matches(
        &self,
        password_history: Vec<CredentialModel>,
        password: &str,
        limit: Option<usize>,
    ) -> Result<bool, String> {
        let mut password_history = password_history;
        password_history.sort_by(|x, y| {
            x.metadata
                .as_ref()
                .unwrap()
                .created_at
                .cmp(&y.metadata.as_ref().unwrap().created_at)
        });

        let mut credentials_to_check: Vec<CredentialModel> = Vec::new();
        if limit.is_some() {
            credentials_to_check = password_history
                .into_iter()
                .take(limit.unwrap())
                .collect::<Vec<_>>();
        } else {
            credentials_to_check = password_history;
        }

        let password_to_check: Vec<PasswordCredentialModel> = credentials_to_check
            .iter()
            .map(|credential_model| PasswordCredentialModel::from_credential(&credential_model))
            .collect();

        for password_credential in password_to_check.iter() {
            let validation = self.validate_credential(password_credential, &password);
            match validation {
                Ok(res) => {
                    return Ok(res);
                }
                Err(err) => return Err(err),
            }
        }

        return Ok(false);
    }

    fn validate_credential(
        &self,
        password_credential: &PasswordCredentialModel,
        password: &str,
    ) -> Result<bool, String> {
        let hash_provider = PasswordHashFactory::hash_algorithm(
            password_credential
                .password_credential_data()
                .algorithm
                .as_ref()
                .unwrap(),
        );
        match hash_provider {
            Ok(hasher) => Ok(hasher.verify(&password_credential, &password)),
            Err(err) => Err(err),
        }
    }
}

#[async_trait]
impl PasswordPolicyProvider for PasswordHistoryPolicyProvider {
    async fn validate(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        let password_history_look_back = realm
            .password_policy
            .as_ref()
            .unwrap()
            .history_look_back
            .unwrap();

        if password_history_look_back > 0 {
            let credentials = self
                .user_credential_service
                .load_stored_credentials_by_type(
                    &realm,
                    &user,
                    PasswordCredentialModel::PASSWORD_CREDENTIAL_TYPE,
                )
                .await;

            match credentials {
                Ok(creds) => {
                    let has_matched_password_credential =
                        self.check_any_credential_matches(creds, &password, None);

                    match has_matched_password_credential {
                        Ok(res) => {
                            if res {
                                return Err(PolicyValidationError {
                                    message: "invalidPasswordHistoryMessage".to_string(),
                                    parameters: vec![password_history_look_back.to_string()],
                                });
                            }
                        }
                        Err(_) => {
                            return Err(PolicyValidationError {
                                message: "invalidPasswordHistoryMessage".to_string(),
                                parameters: vec!["server error".to_owned()],
                            });
                        }
                    }
                }
                Err(_) => {
                    return Err(PolicyValidationError {
                        message: "invalidPasswordHistoryMessage".to_string(),
                        parameters: vec!["server error".to_owned()],
                    });
                }
            }

            let credentials = self
                .user_credential_service
                .load_stored_credentials_by_type(
                    &realm,
                    &user,
                    PasswordCredentialModel::PASSWORD_HISTORY_CREDENTIAL_TYPE,
                )
                .await;

            match credentials {
                Ok(creds) => {
                    let has_matched_password_histroic_credential =
                        self.check_any_credential_matches(creds, &password, None);

                    match has_matched_password_histroic_credential {
                        Ok(res) => {
                            if res {
                                return Err(PolicyValidationError {
                                    message: "invalidPasswordHistoryMessage".to_string(),
                                    parameters: vec![password_history_look_back.to_string()],
                                });
                            }
                        }
                        Err(err) => {
                            return Err(PolicyValidationError {
                                message: "invalidPasswordHistoryMessage".to_string(),
                                parameters: vec!["server error".to_owned()],
                            });
                        }
                    }
                }
                Err(_) => {
                    return Err(PolicyValidationError {
                        message: "invalidPasswordHistoryMessage".to_string(),
                        parameters: vec!["server error".to_owned()],
                    });
                }
            }
        }
        Ok(())
    }
}

pub struct PasswordPolicyManager {
    user_credential_service: Arc<dyn IUserCredentialService>,
}

impl PasswordPolicyManager {
    pub fn new(user_credential_service: Arc<dyn IUserCredentialService>) -> Self {
        Self {
            user_credential_service: Arc::clone(&user_credential_service),
        }
    }

    pub async fn validate(
        &self,
        realm: &RealmModel,
        user: &UserModel,
        password: &str,
    ) -> Result<(), PolicyValidationError> {
        for policy_provider in self.password_policies_provider(&realm).iter() {
            let result = policy_provider.validate(&realm, &user, &password).await;
            if let Err(err) = result {
                return Err(err);
            }
        }
        return Ok(());
    }

    fn password_policies_provider(
        &self,
        realm: &RealmModel,
    ) -> Vec<Box<dyn PasswordPolicyProvider>> {
        let mut providers: Vec<Box<dyn PasswordPolicyProvider>> = Vec::new();
        if let Some(policy) = &realm.password_policy {
            if *policy.not_email.as_ref().unwrap_or(&false) {
                providers.push(Box::new(NotEmailPasswordPolicyProvider {}));
            }
            if *policy.not_birthdate.as_ref().unwrap_or(&false) {
                providers.push(Box::new(NotBirthDatePasswordPolicyProvider {}));
            }
            if *policy.not_username.as_ref().unwrap_or(&false) {
                providers.push(Box::new(NotUsernamePasswordPolicyProvider {}));
            }
            if policy.password_max_length.is_some() {
                providers.push(Box::new(MaximumLengthPasswordPolicyProvider {}));
            }
            if policy.password_min_length.is_some() {
                providers.push(Box::new(MinimumLengthPasswordPolicyProvider {}));
            }
            if policy.password_digits.is_some() {
                providers.push(Box::new(PasswordDigitPolicyProvider {}));
            }
            if policy.regex_pattern.is_some() {
                providers.push(Box::new(RegexPatternsPasswordPolicyProvider {}));
            }
            if policy.special_chars.is_some() {
                providers.push(Box::new(SpecialCharsPasswordPolicyProvider {}));
            }
            if policy.history_look_back.is_some() {
                providers.push(Box::new(PasswordHistoryPolicyProvider::new(Arc::clone(
                    &self.user_credential_service,
                ))));
            }
            if policy.min_upper_case.is_some() {
                providers.push(Box::new(UpperCasePasswordPolicyProvider {}));
            }
            if policy.min_lower_case.is_some() {
                providers.push(Box::new(LowerCasePasswordPolicyProvider {}));
            }
            if policy.black_list_passwords.is_some() {
                providers.push(Box::new(BlackListPasswordPolicyProvider {}));
            }
        }

        return providers;
    }
}
