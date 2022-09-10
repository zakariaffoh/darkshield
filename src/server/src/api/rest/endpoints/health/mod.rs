use crate::context::DarkShieldContext;
use actix_web::{
    get,
    web::{self},
    Responder,
};

use log;
use services::services::health_check::IHealthCheckService;
use shaku::HasComponent;

#[get("/health_check")]
pub async fn health_check(context: web::Data<DarkShieldContext>) -> impl Responder {
    let heath_check_service: &dyn IHealthCheckService = context.services().resolve_ref();
    log::info!("Running health check");
    heath_check_service.health_check().await
}
