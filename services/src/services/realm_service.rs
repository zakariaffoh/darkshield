use async_trait::async_trait;
use shaku::Component;
use shaku::Interface;
use std::sync::Arc;

use models::entities::realm::RealmModel;
use store::providers::interfaces::realm_provider::IRealmProvider;

#[async_trait]
pub trait IRealmService: Interface {
    async fn create_realm(&self, realm: &RealmModel);
    async fn udpate_realm(&self, realm: &RealmModel);
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
    async fn create_realm(&self, _realm: &RealmModel) {}

    async fn udpate_realm(&self, _realm: &RealmModel) {}
}
