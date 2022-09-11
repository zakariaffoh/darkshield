use async_trait::async_trait;
use models::authentication::auth_tokens::SingleUseToken;
use shaku::Component;
use shaku::Interface;
use std::sync::Arc;
use store::providers::interfaces::tokens_providers::IRevokedTokenStoreProvider;
use store::providers::interfaces::tokens_providers::ISingleUseTokenProvider;

#[async_trait]
pub trait ISingleUseTokenService: Interface {
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

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = ISingleUseTokenService)]
pub struct SingleUseTokenService {
    #[shaku(inject)]
    token_provider: Arc<dyn ISingleUseTokenProvider>,
}

#[async_trait]
impl ISingleUseTokenService for SingleUseTokenService {
    async fn add_token(
        &self,
        tenant: &str,
        realm_id: &str,
        token_id: &str,
        lifespan_in_secs: f64,
    ) -> Result<(), String> {
        self.token_provider
            .add_token(tenant, realm_id, token_id, lifespan_in_secs)
            .await
    }

    async fn token_exists(&self, realm_id: &str, token_id: &str) -> Result<bool, String> {
        self.token_provider.token_exists(realm_id, token_id).await
    }

    async fn delete_token(&self, realm_id: &str, token_id: &str) -> Result<(), String> {
        self.token_provider.delete_token(realm_id, token_id).await
    }

    async fn load_token(
        &self,
        realm_id: &str,
        token_id: &str,
    ) -> Result<Option<SingleUseToken>, String> {
        self.token_provider.load_token(realm_id, token_id).await
    }
}

#[async_trait]
pub trait IRevokedTokenStoreService: Interface {
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

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRevokedTokenStoreService)]
pub struct RevokedTokenStoreService {
    #[shaku(inject)]
    revoked_token_provider: Arc<dyn IRevokedTokenStoreProvider>,
}

#[async_trait]
impl IRevokedTokenStoreService for RevokedTokenStoreService {
    async fn revoke_token(
        &self,
        tenant: &str,
        realm_id: &str,
        token_id: &str,
        current_time: f64,
        lifespan_in_secs: f64,
    ) -> Result<(), String> {
        self.revoked_token_provider
            .revoke_token(tenant, realm_id, token_id, current_time, lifespan_in_secs)
            .await
    }

    async fn is_token_revoked(&self, realm_id: &str, token_id: &str) -> Result<bool, String> {
        self.revoked_token_provider
            .is_token_revoked(realm_id, token_id)
            .await
    }
}
