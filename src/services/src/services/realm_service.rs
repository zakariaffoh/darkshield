use async_trait::async_trait;
use crypto::{KeyTypeEnum, KeyUseEnum};
use models::entities::credentials::CredentialViewRepresentation;
use models::entities::realm::ExportedRealm;
use models::entities::realm::ImportedRealm;
use models::entities::realm::RealmModel;
use shaku::Component;
use shaku::Interface;
use std::sync::Arc;
use store::providers::interfaces::realm_provider::IRealmProvider;

#[async_trait]
pub trait IRealmService: Interface {
    async fn create_realm(&self, realm: &RealmModel) -> Result<(), String>;
    async fn udpate_realm(&self, realm: &RealmModel) -> Result<(), String>;
    async fn delete_realm(&self, realm_id: &str) -> Result<(), String>;
    async fn load_realm(&self, realm_id: &str) -> Result<Option<RealmModel>, String>;
    async fn load_realms(&self) -> Result<Vec<RealmModel>, String>;
    async fn export_realm(&self, realm_id: &str) -> Result<Option<ExportedRealm>, String>;
    async fn import_realm(&self, imported_realm: &ImportedRealm) -> Result<(), String>;
    async fn generate_realm_key(
        &self,
        realm_id: &str,
        key_type: &KeyTypeEnum,
        key_use: &KeyUseEnum,
        priority: &Option<i64>,
        algorithm: &str,
    ) -> Result<CredentialViewRepresentation, String>;
    async fn realm_exists_by_id(&self, realm_id: &str) -> Result<bool, String>;

    async fn realm_exists_by_criteria(
        &self,
        realm_id: &str,
        name: &str,
        display_name: &str,
    ) -> Result<bool, String>;

    async fn load_realm_keys(
        &self,
        realm_id: &str,
    ) -> Result<Vec<CredentialViewRepresentation>, String>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRealmService)]
pub struct RealmService {
    #[shaku(inject)]
    realm_provider: Arc<dyn IRealmProvider>,
}

#[async_trait]
impl IRealmService for RealmService {
    async fn create_realm(&self, realm: &RealmModel) -> Result<(), String> {
        self.realm_provider.create_realm(&realm).await
    }

    async fn udpate_realm(&self, realm: &RealmModel) -> Result<(), String> {
        self.realm_provider.update_realm(&realm).await
    }

    async fn delete_realm(&self, realm_id: &str) -> Result<(), String> {
        self.realm_provider.delete_realm(&realm_id).await
    }

    async fn load_realm(&self, realm_id: &str) -> Result<Option<RealmModel>, String> {
        self.realm_provider.load_realm(&realm_id).await
    }
    async fn load_realms(&self) -> Result<Vec<RealmModel>, String> {
        self.realm_provider.load_realms().await
    }

    async fn export_realm(&self, _realm_id: &str) -> Result<Option<ExportedRealm>, String> {
        todo!()
    }

    async fn import_realm(&self, _imported_realm: &ImportedRealm) -> Result<(), String> {
        todo!()
    }

    async fn realm_exists_by_id(&self, realm_id: &str) -> Result<bool, String> {
        self.realm_provider.realm_exists_by_id(realm_id).await
    }

    async fn realm_exists_by_criteria(
        &self,
        realm_id: &str,
        name: &str,
        display_name: &str,
    ) -> Result<bool, String> {
        self.realm_provider
            .realm_exists_by_criteria(realm_id, name, display_name)
            .await
    }

    async fn generate_realm_key(
        &self,
        _realm_id: &str,
        _key_type: &KeyTypeEnum,
        _key_use: &KeyUseEnum,
        _priority: &Option<i64>,
        _algorithm: &str,
    ) -> Result<CredentialViewRepresentation, String> {
        todo!()
    }

    async fn load_realm_keys(
        &self,
        _realm_id: &str,
    ) -> Result<Vec<CredentialViewRepresentation>, String> {
        todo!()
    }
}
