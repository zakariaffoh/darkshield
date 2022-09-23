use async_trait::async_trait;
use models::entities::credentials::CredentialModel;
use shaku::Interface;

#[async_trait]
pub trait ICredentialProvider: Interface {
    async fn create_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        credential: CredentialModel,
    ) -> Result<CredentialModel, String>;

    async fn update_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        credential: &CredentialModel,
    ) -> Result<bool, String>;

    async fn remove_stored_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
        priority: i64,
        priority_difference: i64,
    ) -> Result<bool, String>;

    async fn load_stored_user_credential_by_id(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
    ) -> Result<Option<CredentialModel>, String>;

    async fn load_stored_credential_by_name_and_type(
        &self,
        realm_id: &str,
        user_id: &str,
        user_label: &str,
        credential_type: &str,
    ) -> Result<Option<CredentialModel>, String>;

    async fn reset_password_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        credential: &CredentialModel,
    ) -> Result<bool, String>;

    async fn load_stored_credentials(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<CredentialModel>, String>;

    async fn load_stored_credentials_by_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> Result<Vec<CredentialModel>, String>;

    async fn load_stored_credentials_by_realm_id(
        &self,
        realm_id: &str,
    ) -> Result<Vec<CredentialModel>, String>;

    async fn update_credential_priorities(
        &self,
        realm_id: &str,
        credential_data: &Vec<(String, i64)>,
    ) -> Result<bool, String>;

    async fn update_user_credential_label(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
        user_label: &str,
    ) -> Result<(), String>;
}
