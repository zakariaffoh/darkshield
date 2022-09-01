use crate::context::context::DarkShieldContext;
use log;
use models::entities::realm::{RealmCreateModel, RealmModel, RealmUpdateModel};
use services::services::realm_service::IRealmService;
use shaku::HasComponent;

use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

#[allow(dead_code)]
#[post("/admin/realm/create")]
pub async fn create_realm(
    realm: web::Json<RealmCreateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    log::info!("Creating realm request {}", realm.realm_id);
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    let ream_model: RealmModel = realm.0.into();
    realm_service.create_realm(ream_model).await
}

#[allow(dead_code)]
#[put("/admin/realm/{realm_id}")]
pub async fn update_realm(
    realm: web::Json<RealmUpdateModel>,
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    let mut ream_model: RealmModel = realm.0.into();
    ream_model.realm_id = realm_id.to_string();
    log::info!("Updating realm {}", &ream_model.realm_id);
    realm_service.udpate_realm(ream_model).await
}

#[delete("/admin/realm/{realm_id}")]
pub async fn delete_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    log::info!("Deleting realm {}", realm_id.as_str());
    realm_service.delete_realm(realm_id.as_str()).await
}

#[get("/admin/realm/{realm_id}")]
pub async fn load_realm_by_id(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    log::info!("Loading realm {}", realm_id.as_str());
    realm_service.load_realm(realm_id.as_str()).await
}

#[get("/admin/realms/load_all")]
pub async fn load_realms(context: web::Data<DarkShieldContext>) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    log::info!("Loading all realms");
    realm_service.load_realms().await
}

#[post("/admin/realms/realm-export")]
pub async fn export_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    log::info!("Exporting realm: {}", realm_id.as_str());
    realm_service.export_realm(realm_id.as_str()).await
}

#[post("/admin/realms/import_realm")]
pub async fn import_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    log::info!("Importing realm: {}", realm_id.as_str());
    realm_service.export_realm(realm_id.as_str()).await
}
