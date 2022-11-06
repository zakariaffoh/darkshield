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
pub async fn health_check(session: web::ReqData<DarkshieldSession>) -> impl Responder {
    log::info!("Running health check");
    session
        .services()
        .health_check_service()
        .health_check()
        .await
}
