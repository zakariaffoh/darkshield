use async_trait::async_trait;
use models::entities::{realm::RealmModel, user::UserModel};
use shaku::Interface;

#[async_trait]
pub trait IUserProvider: Interface {
    async fn create_user(&self, user: UserModel) -> Result<(), String>;

    async fn update_user(&self, user: &UserModel) -> Result<(), String>;

    async fn user_exists_by_user_name(
        &self,
        realm_id: &str,
        user_name: &str,
    ) -> Result<bool, String>;

    async fn user_exists_by_email(&self, realm_id: &str, email: &str) -> Result<bool, String>;

    async fn load_user_by_user_name_or_email(
        &self,
        realm_id: &str,
        user_name: &str,
        email: &str,
    ) -> Result<Option<UserModel>, String>;

    async fn load_user_by_user_name(
        &self,
        realm_id: &str,
        email: &str,
    ) -> Result<Option<UserModel>, String>;
}
