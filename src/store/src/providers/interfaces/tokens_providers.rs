use async_trait::async_trait;
use models::authentication::auth_tokens::SingleUseToken;
use shaku::Interface;

#[async_trait]
pub trait ISingleUseTokenProvider: Interface {
    async fn add_token(
        &self,
        tenant: &str,
        realm_id: &str,
        token_id: &str,
        lifespan_in_secs: f64,
    ) -> Result<(), String>;

    async fn token_exists(&self, realm_id: &str, token_id: &str) -> Result<bool, String>;

    async fn delete_token(&self, realm_id: &str, token_id: &str) -> Result<(), String>;

    async fn load_token(
        &self,
        realm_id: &str,
        token_id: &str,
    ) -> Result<Option<SingleUseToken>, String>;
}

#[async_trait]
pub trait IRevokedTokenStoreProvider: Interface {
    async fn revoke_token(
        &self,
        tenant: &str,
        realm_id: &str,
        token_id: &str,
        current_time: f64,
        lifespan_in_secs: f64,
    ) -> Result<(), String>;

    async fn is_token_revoked(&self, realm_id: &str, token_id: &str) -> Result<bool, String>;
}
