use async_trait::async_trait;

use models::authentication::login_failure::UserLoginFailure;
use shaku::Interface;

#[async_trait]
pub trait IUserLoginFailureProvider: Interface {
    async fn add_user_login_failure(&self, login_failure: &UserLoginFailure) -> Result<(), String>;

    async fn increment_login_failure(&self, login_failure: &UserLoginFailure)
        -> Result<(), String>;

    async fn load_user_login_failure(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<UserLoginFailure>, String>;

    async fn remove_user_login_failure(&self, realm_id: &str, user_id: &str) -> Result<(), String>;

    async fn remove_all_user_login_failures(&self, realm_id: &str) -> Result<(), String>;
}
