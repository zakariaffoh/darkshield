use crate::{
    api::rest::models::realm::{RealmCreateModel, RealmUpdateModel},
    context::context::DarkShieldContext,
};

use super::super::models::api_response;
use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};
use services::services::relam_service::RealmService;

#[allow(dead_code)]
#[post("/realm/create")]
pub async fn create_realm(
    realm: web::Json<RealmCreateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service = RealmService::new(context.database());
    api_response::ApiResponse::from_data(realm)
}

#[allow(dead_code)]
#[put("/realm/update")]
pub async fn update_realm(
    realm: web::Json<RealmUpdateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service = RealmService::new(context.database());
    api_response::ApiResponse::from_data(realm)
}

#[allow(dead_code)]
#[delete("/realm/{realm_id}")]
pub async fn delete_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service = RealmService::new(context.database());
    format!("delete realm {realm_id}")
}

#[allow(dead_code)]
#[get("/realm/{realm_id}")]
pub async fn load_realm_by_id(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let path = realm_id.as_str();
    let database = context.database();
    api_response::ApiResponse::from_data(String::from(path))
}

#[allow(dead_code)]
#[get("/realm/load_all")]
pub async fn load_realms(context: web::Data<DarkShieldContext>) -> impl Responder {
    let database = context.database();
    format!("load all realms")
}
