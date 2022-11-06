use crate::api::services::realm_api::ReamlApi;
use crypto::{KeyTypeEnum, KeyUseEnum};
use log;
use models::entities::realm::{RealmCreateModel, RealmModel, RealmUpdateModel};
use services::session::session::DarkshieldSession;

use actix_web::{delete, get, post, put, web, Responder};

#[post("/realm/create")]
pub async fn create_realm(
    realm: web::Json<RealmCreateModel>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    log::info!("Creating realm request {}", realm.realm_id);
    let ream_model: RealmModel = realm.0.into();
    ReamlApi::create_realm(&session, ream_model).await
}

#[put("/realm/{realm_id}/update")]
pub async fn update_realm(
    realm_id: web::Path<String>,
    realm: web::Json<RealmUpdateModel>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let mut ream_model: RealmModel = realm.0.into();
    ream_model.realm_id = realm_id.to_string();
    log::info!("Updating realm {}", &ream_model.realm_id);
    ReamlApi::update_realm(&session, ream_model).await
}

#[delete("/realm/{realm_id}")]
pub async fn delete_realm(
    realm_id: web::Path<String>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    log::info!("Deleting realm {}", realm_id.as_str());
    ReamlApi::delete_realm(&session, &realm_id).await
}

#[get("/realm/{realm_id}")]
pub async fn load_realm_by_id(
    realm_id: web::Path<String>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    log::info!("Loading realm {}", realm_id.as_str());
    ReamlApi::load_realm_by_id(&session, &realm_id).await
}

#[get("/realms/load_all")]
pub async fn load_realms(session: web::ReqData<DarkshieldSession>) -> impl Responder {
    log::info!("Loading all realms");
    ReamlApi::load_realms(&session).await
}

#[post("/realm/export")]
pub async fn export_realm(
    realm_id: web::Path<String>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    log::info!("Exporting realm: {}", realm_id.as_str());
    ReamlApi::export_realm(&session, &realm_id).await
}

#[post("/realm/import")]
pub async fn import_realm(
    realm_id: web::Path<String>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    log::info!("Importing realm: {}", realm_id.as_str());
    ReamlApi::export_realm(&session, &realm_id).await
}

#[post("/realm/{realm_id}/keys/generate-key")]
pub async fn generate_realm_key(
    realm_id: web::Path<String>,
    key_type: web::Query<KeyTypeEnum>,
    key_use: web::Query<KeyUseEnum>,
    priority: web::Query<Option<i64>>,
    algorithm: web::Query<String>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    log::info!(
        "Generate realm {} keys with for key_type: {}, key_use: {},",
        realm_id.as_str(),
        key_type.to_string(),
        key_use.to_string()
    );
    ReamlApi::generate_realm_key(
        &session,
        &realm_id,
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
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    log::info!("Loading realm {} keys", &realm_id);
    ReamlApi::load_realm_keys(&session, &realm_id).await
}
