use super::super::models::api_response;
use actix_web::{
    delete, get, post, put,
    web::{self, Data},
    Responder,
};

#[post("/realm/create")]
pub async fn create_realm() -> impl Responder {
    api_response::ApiResponse::from_data("My Restponse".to_string())
}

#[put("/realm/update")]
pub async fn update_realm() -> impl Responder {
    format!("update client")
}

#[delete("/realm/{realm_id}")]
pub async fn delete_realm(realm_id: web::Path<String>) -> impl Responder {
    format!("delete realm {realm_id}")
}

#[get("/realm/{realm_id}")]
pub async fn load_realm_by_id(realm_id: web::Path<String>) -> impl Responder {
    let path = realm_id.as_str();
    api_response::ApiResponse::from_data(String::from(path))
}

#[get("/realm/load_all")]
pub async fn load_realms() -> impl Responder {
    format!("load all realms")
}
