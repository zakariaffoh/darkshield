use async_trait::async_trait;
use models::entities::{credentials::UserCredentialModel, user::UserModel};
use shaku::Interface;

#[async_trait]
pub trait IUserProvider: Interface {
    async fn create_user(
        &self,
        user: &UserModel,
        credential: &UserCredentialModel,
    ) -> Result<(), String>;

    async fn udpate_user(&self, user: &UserModel) -> Result<(), String>;

    async fn delete_user(&self, realm_id: &str, user_id: &str) -> Result<(), String>;

    async fn user_exists_by_user_name(
        &self,
        realm_id: &str,
        user_name: &str,
    ) -> Result<bool, String>;

    async fn user_exists_by_email(&self, realm_id: &str, email: &str) -> Result<bool, String>;

    async fn user_exists_by_id(&self, realm_id: &str, user_id: &str) -> Result<bool, String>;

    async fn add_user_role(
        &self,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<(), String>;

    async fn remove_user_role(
        &self,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<(), String>;

    async fn add_user_group_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), String>;

    async fn remove_user_group_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), String>;

    async fn load_user_by_user_name_or_email(
        &self,
        realm_id: &str,
        user_name: &str,
        email: &str,
    ) -> Result<Option<UserModel>, String>;

    async fn load_user_by_user_name(
        &self,
        realm_id: &str,
        user_name: &str,
    ) -> Result<Option<UserModel>, String>;

    async fn load_user_by_email(
        &self,
        realm_id: &str,
        email: &str,
    ) -> Result<Option<UserModel>, String>;

    async fn load_user_by_id(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<UserModel>, String>;

    async fn load_user_by_ids(
        &self,
        realm_id: &str,
        user_ids: &[&str],
    ) -> Result<Vec<UserModel>, String>;

    async fn count_users(&self, realm_id: &str) -> Result<u64, String>;

    async fn load_users_by_realm_paging(
        &self,
        realm_id: &str,
        page_index: &Option<u64>,
        page_size: &Option<u64>,
    ) -> Result<Vec<UserModel>, String>;

    async fn load_users_by_realm_id(&self, realm_id: &str) -> Result<Vec<UserModel>, String>;

    async fn add_user_group(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), String>;

    async fn remove_user_group(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), String>;
}
