use async_trait::async_trait;
use models::entities::realm::RealmModel;
use shaku::Interface;

#[async_trait]
pub trait IRealmProvider: Interface {
    async fn create_realm(&self, realm: &RealmModel);

    async fn update_realm(&self, realm: &RealmModel);

    async fn load_realms(&self) -> Vec<RealmModel>;

    async fn delete_realm(&self, tenant: &str, realm_id: &str) -> Result<(), String>;

    async fn load_realm(&self, tenant: &str, realm_id: &str) -> Option<RealmModel>;

    async fn load_realm_by_name(&self, name: &str) -> Option<RealmModel>;

    async fn load_realm_by_display_name(&self, display_name: &str) -> Option<RealmModel>;
}
