use actix_web::{post, Responder};

#[post("/client/create")]
pub async fn create_client() -> impl Responder {
    format!("create client")
}
