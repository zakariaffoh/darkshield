use commons::ApiResult;
use crypto::{KeyTypeEnum, KeyUseEnum};
use log;
use models::{
    auditable::AuditableModel,
    entities::{
        credentials::CredentialViewRepresentation,
        realm::{ExportedRealm, ImportedRealm, RealmModel},
    },
};
use services::session::session::DarkshieldSession;
pub struct ReamlApi;

impl ReamlApi {
    pub async fn create_realm(
        session: &DarkshieldSession,
        realm: RealmModel,
    ) -> ApiResult<RealmModel> {
        let existing_realm = session
            .services()
            .realm_service()
            .realm_exists_by_id(&realm.realm_id)
            .await;
        if let Ok(response) = existing_realm {
            if response {
                log::error!("realm: {} already", &realm.realm_id,);
                return ApiResult::from_error(409, "409", "realm already exists");
            }
        }

        let mut realm = realm;
        realm.metadata = AuditableModel::from_creator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .clone(),
            "zaffoh".to_owned(),
        );

        let created_realm = session
            .services()
            .realm_service()
            .create_realm(&realm)
            .await;
        match created_realm {
            _ => ApiResult::Data(realm),
            Err(err) => ApiResult::from_error(500, "500", err.as_str()),
        }
    }

    pub async fn update_realm(session: &DarkshieldSession, realm: RealmModel) -> ApiResult {
        let existing_realm = session
            .services()
            .realm_service()
            .realm_exists_by_criteria(&realm.realm_id, &realm.name, &realm.display_name)
            .await;
        if let Ok(res) = existing_realm {
            if !res {
                log::error!("realm: {} not found", &realm.realm_id);
                return ApiResult::from_error(404, "404", "realm not found");
            }
        }
        let mut realm = realm;
        realm.metadata = AuditableModel::from_updator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );

        let updated_realm = session
            .services()
            .realm_service()
            .udpate_realm(&realm)
            .await;
        match updated_realm {
            Err(err) => ApiResult::from_error(500, "500", err.as_str()),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn delete_realm(session: &DarkshieldSession, realm_id: &str) -> ApiResult<()> {
        let response = session
            .services()
            .realm_service()
            .delete_realm(&realm_id)
            .await;
        match response {
            Err(err) => ApiResult::from_error(500, "500", err.as_str()),
            _ => ApiResult::Data(()),
        }
    }

    pub async fn load_realm_by_id(
        session: &DarkshieldSession,
        realm_id: &str,
    ) -> ApiResult<RealmModel> {
        let loaded_realm = session
            .services()
            .realm_service()
            .load_realm(&realm_id)
            .await;
        match loaded_realm {
            Ok(realm) => ApiResult::<RealmModel>::from_option(realm),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_realms(session: &DarkshieldSession) -> ApiResult<Vec<RealmModel>> {
        let loaded_realms = session.services().realm_service().load_realms().await;
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

    pub async fn export_realm(
        session: &DarkshieldSession,
        realm_id: &str,
    ) -> ApiResult<ExportedRealm> {
        let exported_realm = session
            .services()
            .realm_service()
            .export_realm(&realm_id)
            .await;
        match exported_realm {
            Ok(realm) => ApiResult::<ExportedRealm>::from_option(realm),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn import_realm(
        session: &DarkshieldSession,
        imported_realm: &ImportedRealm,
    ) -> ApiResult<()> {
        let import_realm_response = session
            .services()
            .realm_service()
            .import_realm(imported_realm)
            .await;
        match import_realm_response {
            Err(err) => ApiResult::from_error(500, "500", &err),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn generate_realm_key(
        session: &DarkshieldSession,
        realm_id: &str,
        key_type: &KeyTypeEnum,
        key_use: &KeyUseEnum,
        priority: &Option<i64>,
        algorithm: &str,
    ) -> ApiResult<CredentialViewRepresentation> {
        let realm_keys = session
            .services()
            .realm_service()
            .generate_realm_key(&realm_id, &key_type, &key_use, &priority, &algorithm)
            .await;
        match realm_keys {
            Ok(key) => ApiResult::<CredentialViewRepresentation>::from_data(key),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_realm_keys(
        session: &DarkshieldSession,
        realm_id: &str,
    ) -> ApiResult<Vec<CredentialViewRepresentation>> {
        let loaded_realm_keys = session
            .services()
            .realm_service()
            .load_realm_keys(&realm_id)
            .await;
        match loaded_realm_keys {
            Ok(keys) => {
                log::info!("[{}] realm keys loaded", keys.len());
                if keys.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(keys)
                }
            }
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }
}
