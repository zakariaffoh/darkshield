use async_trait::async_trait;
use commons::ApiResult;
use models::auditable::AuditableModel;
use shaku::Component;
use shaku::Interface;
use std::sync::Arc;

use models::entities::realm::RealmModel;
use store::providers::interfaces::realm_provider::IRealmProvider;

#[async_trait]
pub trait IRealmService: Interface {
    async fn create_realm(&self, realm: RealmModel) -> ApiResult<RealmModel>;
    async fn udpate_realm(&self, realm: RealmModel) -> ApiResult<()>;
    async fn delete_realm(&self, realm_id: &str) -> ApiResult<()>;
    async fn load_realm(&self, realm_id: &str) -> ApiResult<RealmModel>;
    async fn load_realms(&self) -> ApiResult<Vec<RealmModel>>;
    async fn export_realm(&self, realm_id: &str) -> ApiResult<Option<RealmModel>>;
    async fn import_realm(&self, realm_id: &str) -> ApiResult<Option<RealmModel>>;
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
        let existing_realm = self
            .realm_provider
            .realm_exists_by_id(&realm.realm_id)
            .await;
        if let Ok(response) = existing_realm {
            if response {
                log::error!("realm: {} already", &realm.realm_id,);
                return ApiResult::from_error(409, "409", "realm already exists");
            }
        }
        let mut realm = realm;
        realm.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_realm = self.realm_provider.create_realm(&realm).await;
        match created_realm {
            Ok(_) => ApiResult::Data(realm),
            Err(_) => ApiResult::from_error(500, "500", "failed to create realm"),
        }
    }
    async fn udpate_realm(&self, realm: RealmModel) -> ApiResult<()> {
        let existing_realm = self
            .realm_provider
            .realm_exists_by_criteria(&realm.realm_id, &realm.name, &realm.display_name)
            .await;
        if let Ok(res) = existing_realm {
            if !res {
                log::error!("realm: {} not found", &realm.realm_id);
                return ApiResult::from_error(404, "404", "realm not found");
            }
        }
        let mut realm = realm;
        realm.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_realm = self.realm_provider.update_realm(&realm).await;
        match updated_realm {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to update realm"),
        }
    }
    async fn delete_realm(&self, realm_id: &str) -> ApiResult<()> {
        let existing_realm = self.realm_provider.realm_exists_by_id(&realm_id).await;
        if let Ok(res) = existing_realm {
            if !res {
                log::error!("realm: {} not found", &realm_id);
                return ApiResult::from_error(404, "404", "realm not found");
            }
        }
        let response = self.realm_provider.delete_realm(&realm_id).await;
        match response {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to delete realm"),
        }
    }
    async fn load_realm(&self, realm_id: &str) -> ApiResult<RealmModel> {
        let loaded_realm = self.realm_provider.load_realm(&realm_id).await;
        match loaded_realm {
            Ok(mappers) => ApiResult::<RealmModel>::from_option(mappers),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }
    async fn load_realms(&self) -> ApiResult<Vec<RealmModel>> {
        let loaded_realms = self.realm_provider.load_realms().await;
        match loaded_realms {
            Ok(realms) => {
                log::info!("[{}] realms loaded", realms.len());
                if realms.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(realms)
                }
            }
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }
    async fn export_realm(&self, _realm_id: &str) -> ApiResult<Option<RealmModel>> {
        todo!()
    }
    async fn import_realm(&self, _realm_id: &str) -> ApiResult<Option<RealmModel>> {
        todo!()
    }
}
