use async_trait::async_trait;
use commons::api_result::ApiError;
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
    async fn create_realm(&self, realm: RealmModel) -> ApiResult<RealmModel>;
    async fn udpate_realm(&self, realm: RealmModel) -> ApiResult<RealmModel>;
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
    async fn create_realm(&self, realm: RealmModel) -> ApiResult<RealmModel> {
        let existing_realm = self.realm_provider.load_realm("", &realm.realm_id).await;
        if let Ok(response) = existing_realm {
            if response.is_some() {
                return ApiResult::from_error(409, "500", "realm already exists");
            }
        }
        let mut realm = realm;
        realm.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        ApiResult::from_data(realm)
    }

    async fn udpate_realm(&self, realm: RealmModel) -> ApiResult<RealmModel> {
        let mut realm = realm;
        realm.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        ApiResult::from_data(realm)
    }
}
