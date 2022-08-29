use actix_web::{web, HttpResponse};

use super::{metrics_api::metrics_handler, admin::realm::realm_api, admin::authz::*};

pub fn register_apis(api_config: &mut web::ServiceConfig) {
    api_config
        .service(realm_api::update_realm)
        .service(realm_api::load_realm_by_id)
        .service(realm_api::load_realms)
        .service(realm_api::create_realm)
        .service(realm_api::delete_realm)

        .service(role_api::create_role)
        .service(role_api::update_role)
        .service(role_api::load_role_by_id)
        .service(role_api::delete_role_by_id)
        .service(role_api::load_roles_by_realm)
        .service(role_api::count_roles_by_realm)

        .service(group_api::create_group)
        .service(group_api::update_role)
        .service(group_api::load_groups_by_realm)
        .service(group_api::delete_group_by_id)
        .service(group_api::load_groups_by_realm)
        .service(group_api::count_groups_by_realm)


        .service(
            web::resource("/health_check")
                .route(web::get().to(|| async { HttpResponse::Ok().body("running") })),
        )
        .service(metrics_handler);
}
