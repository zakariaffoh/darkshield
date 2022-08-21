use crate::context::context::DarkShieldContext;
use models::{
    auditable::AuditableModel,
    entities::realm::{RealmCreateModel, RealmUpdateModel},
};
use services::services::realm_service::IRealmService;
use shaku::HasComponent;

use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

#[allow(dead_code)]
#[post("/realm/create")]
pub async fn create_realm(
    realm: web::Json<RealmCreateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    let response = realm_service.create_realm(&realm.0).await;
    response
}

#[allow(dead_code)]
#[put("/realm/update")]
pub async fn update_realm(
    realm: web::Json<RealmUpdateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_service: &dyn IRealmService = context.services().resolve_ref();
    let response = realm_service.udpate_realm(&realm.0).await;
    response
}

#[allow(dead_code)]
#[delete("/realm/{realm_id}")]
pub async fn delete_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    format!("delete realm {realm_id}")
}

#[allow(dead_code)]
#[get("/realm/{realm_id}")]
pub async fn load_realm_by_id(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let path = realm_id.as_str();
    format!("delete realm {path}")
}

#[allow(dead_code)]
#[get("/realm/load_all")]
pub async fn load_realms(context: web::Data<DarkShieldContext>) -> impl Responder {
    format!("load all realms")
}
