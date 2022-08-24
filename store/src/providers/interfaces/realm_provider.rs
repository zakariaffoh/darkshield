use async_trait::async_trait;
use models::entities::realm::RealmModel;
use shaku::Interface;

#[async_trait]
pub trait IRealmProvider: Interface {
    async fn create_realm(&self, realm: &RealmModel) -> Result<(), String>;

    async fn update_realm(&self, realm: &RealmModel) -> Result<(), String>;

    async fn load_realms(&self) -> Result<Vec<RealmModel>, String>;

    async fn delete_realm(&self, realm_id: &str) -> Result<(), String>;

    async fn load_realm(&self, realm_id: &str) -> Result<Option<RealmModel>, String>;

    async fn load_realm_by_name(&self, name: &str) -> Result<Option<RealmModel>, String>;

    async fn load_realm_by_display_name(
        &self,
        display_name: &str,
    ) -> Result<Option<RealmModel>, String>;
}
