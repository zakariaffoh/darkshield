use async_trait::async_trait;
use commons::api_result::ApiResult;
use models::auditable::AuditableModel;
use models::entities::realm::*;
use shaku::Component;
use shaku::Interface;
use std::sync::Arc;

use models::entities::realm::RealmModel;
use store::providers::interfaces::realm_provider::IRealmProvider;

#[async_trait]
pub trait IRealmService: Interface {
    async fn create_realm(&self, realm: &RealmCreateModel) -> ApiResult<RealmModel>;
    async fn udpate_realm(&self, realm: &RealmUpdateModel) -> ApiResult<RealmModel>;
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
    async fn create_realm(&self, realm: &RealmCreateModel) -> ApiResult<RealmModel> {
        let response = models::entities::realm::RealmModel {
            realm_id: realm.realm_id.to_owned(),
            name: realm.name.to_owned(),
            display_name: realm.display_name.to_owned(),
            enabled: realm.enabled,
            metadata: AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned(), 0.0),
        };
        ApiResult::from_data(response)
    }

    async fn udpate_realm(&self, realm: &RealmUpdateModel) -> ApiResult<RealmModel> {
        let response = models::entities::realm::RealmModel {
            realm_id: realm.realm_id.to_owned(),
            name: realm.name.to_owned(),
            display_name: realm.display_name.to_owned(),
            enabled: realm.enabled,
            metadata: AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned(), 0.0),
        };
        ApiResult::from_data(response)
    }
}
