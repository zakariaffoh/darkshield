use crate::context::DarkShieldContext;
use crypto::keys::{KeyTypeEnum, KeyUseEnum};
use log;
use models::entities::realm::{RealmCreateModel, RealmModel, RealmUpdateModel};
use services::services::realm_service::IRealmService;
use shaku::HasComponent;

use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

#[post("/realm/create")]
pub async fn create_realm(
    realm: web::Json<RealmCreateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    log::info!("Creating realm request {}", realm.realm_id);
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    let ream_model: RealmModel = realm.0.into();
    realm_service.create_realm(ream_model).await
}

#[put("/realm/{realm_id}/update")]
pub async fn update_realm(
    realm_id: web::Path<String>,
    realm: web::Json<RealmUpdateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    let mut ream_model: RealmModel = realm.0.into();
    ream_model.realm_id = realm_id.to_string();
    log::info!("Updating realm {}", &ream_model.realm_id);
    realm_service.udpate_realm(ream_model).await
}

#[delete("/realm/{realm_id}")]
pub async fn delete_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    log::info!("Deleting realm {}", realm_id.as_str());
    realm_service.delete_realm(realm_id.as_str()).await
}

#[get("/realm/{realm_id}")]
pub async fn load_realm_by_id(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    log::info!("Loading realm {}", realm_id.as_str());
    realm_service.load_realm(realm_id.as_str()).await
}

#[get("/realms/load_all")]
pub async fn load_realms(context: web::Data<DarkShieldContext>) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    log::info!("Loading all realms");
    realm_service.load_realms().await
}

#[post("/realm/export")]
pub async fn export_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    log::info!("Exporting realm: {}", realm_id.as_str());
    realm_service.export_realm(realm_id.as_str()).await
}

#[post("/realm/import")]
pub async fn import_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    log::info!("Importing realm: {}", realm_id.as_str());
    realm_service.export_realm(realm_id.as_str()).await
}

#[post("/realm/{realm_id}/keys/generate-key")]
pub async fn generate_realm_key(
    realm_id: web::Path<String>,
    key_type: web::Query<KeyTypeEnum>,
    key_use: web::Query<KeyUseEnum>,
    priority: web::Query<Option<i64>>,
    algorithm: web::Query<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    log::info!(
        "Generate realm {} keys with for key_type: {}, key_use: {},",
        realm_id.as_str(),
        key_type.to_string(),
        key_use.to_string()
    );
    realm_service
        .generate_realm_key(
            realm_id.as_str(),
            &key_type.0,
            &key_use.0,
            &priority.0,
            &algorithm.0,
        )
        .await
}

#[get("/realm/{realm_id}/realm-keys")]
pub async fn load_realm_keys(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    log::info!("Loading realm {} keys", realm_id.as_str());
    realm_service.load_realm_keys(realm_id.as_str()).await
}
