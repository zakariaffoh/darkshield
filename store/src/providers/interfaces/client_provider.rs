use async_trait::async_trait;
use models::entities::realm::RealmModel;
use shaku::Interface;

#[async_trait]
pub trait IClientProvider: Interface {}

#[async_trait]
pub trait IClientScopeProvider: Interface {}

#[async_trait]
pub trait IProtocolMapperProvider: Interface {
    async fn create_protocol_mapper(&self, realm: &RealmModel) -> Result<(), String>;

    async fn update_protocol_mapper(&self, realm: &RealmModel) -> Result<(), String>;

    async fn load_realms(&self) -> Result<Vec<RealmModel>, String>;

    async fn delete_realm(&self, tenant: &str, realm_id: &str) -> Result<(), String>;

    async fn load_protocol_mapper_by_protocol(&self, realm_id: &str, protocol: &str) -> Result<RealmModel, String>;

    async fn load_realm_mapper_by_protocol_id(&self, realm_id: &str, protocol_id: &str) -> Result<RealmModel, String>;

    async fn load_realm_mapper_by_protocol_by_client_scope_id(&self, realm_id: &str, client_scope_id: &str) -> Result<Vec<RealmModel>, String>;
}
