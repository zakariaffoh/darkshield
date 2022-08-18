use actix_web::{web, HttpResponse};

use super::metrics_api::metrics_handler;
use super::realm_api;

pub fn register_apis(api_config: &mut web::ServiceConfig) {
    api_config
        .service(realm_api::update_realm)
        .service(realm_api::load_realm_by_id)
        .service(realm_api::load_realms)
        .service(realm_api::create_realm)
        .service(realm_api::delete_realm)
        .service(
            web::resource("/health_check")
                .route(web::get().to(|| async { HttpResponse::Ok().body("running") })),
        )
        .service(metrics_handler);
}
