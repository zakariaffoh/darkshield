use actix_web::{
    get,
    web::{self},
    Responder,
};
use log;
use services::{services::health_check::IHealthCheckService, session::session::DarkshieldSession};
#[allow(unused)]
use shaku::HasComponent;

#[get("/health_check")]
pub async fn health_check(context: web::Data<DarkshieldSession>) -> impl Responder {
    let heath_check_service: &dyn IHealthCheckService = context.services().resolve_ref();
    log::info!("Running health check");
    heath_check_service.health_check().await
}
