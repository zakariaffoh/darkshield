use crate::api::rest::models::realm::{RealmCreateModel, RealmUpdateModel};

use super::super::models::api_response;
use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

#[allow(dead_code)]
#[post("/realm/create")]
pub async fn create_realm(realm: web::Json<RealmCreateModel>) -> impl Responder {
    api_response::ApiResponse::from_data(realm)
}

#[allow(dead_code)]
#[put("/realm/update")]
pub async fn update_realm(realm: web::Json<RealmUpdateModel>) -> impl Responder {
    api_response::ApiResponse::from_data(realm)
}

#[allow(dead_code)]
#[delete("/realm/{realm_id}")]
pub async fn delete_realm(realm_id: web::Path<String>) -> impl Responder {
    format!("delete realm {realm_id}")
}

#[allow(dead_code)]
#[get("/realm/{realm_id}")]
pub async fn load_realm_by_id(realm_id: web::Path<String>) -> impl Responder {
    let path = realm_id.as_str();
    api_response::ApiResponse::from_data(String::from(path))
}

#[allow(dead_code)]
#[get("/realm/load_all")]
pub async fn load_realms() -> impl Responder {
    format!("load all realms")
}
