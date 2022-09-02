use actix_web::{web, HttpResponse};

use super::{admin::auth, admin::authz, admin::realm, metrics_api::metrics_handler};

pub fn register_apis(api_config: &mut web::ServiceConfig) {
    api_config
        /* Realm Api */
        .service(realm::update_realm)
        .service(realm::load_realm_by_id)
        .service(realm::load_realms)
        .service(realm::create_realm)
        .service(realm::delete_realm)
        .service(realm::export_realm)
        .service(realm::import_realm)
        /* Role Api */
        .service(authz::create_role)
        .service(authz::update_role)
        .service(authz::load_role_by_id)
        .service(authz::delete_role_by_id)
        .service(authz::load_roles_by_realm)
        .service(authz::count_roles_by_realm)
        /* Group Api */
        .service(authz::create_group)
        .service(authz::update_role)
        .service(authz::load_groups_by_realm)
        .service(authz::delete_group_by_id)
        .service(authz::load_groups_by_realm)
        .service(authz::count_groups_by_realm)
        /* Authentication Execution API */
        .service(auth::create_authentication_execution)
        .service(auth::update_authentication_execution)
        .service(auth::load_authentication_execution_by_id)
        .service(auth::load_authentication_execution_by_realm)
        .service(auth::remove_authentication_execution_by_id)
        /* Authentication flow API */
        .service(auth::create_authentication_flow)
        .service(auth::update_authentication_flow)
        .service(auth::load_authentication_flow_by_id)
        .service(auth::load_authentication_flows_by_realm)
        .service(auth::remove_authentication_flow_by_id)
        /* Authenticator config API */
        .service(auth::create_authenticator_config)
        .service(auth::update_authenticator_config)
        .service(auth::load_authenticator_config_by_id)
        .service(auth::load_authenticator_configs_by_realm)
        .service(auth::remove_authenticator_config_by_id)
        /* Required Action API */
        .service(auth::register_required_action)
        .service(auth::update_required_action)
        .service(auth::load_requied_action_by_id)
        .service(auth::load_requied_action_by_realm)
        .service(auth::remove_requied_action_by_id)
        .service(
            web::resource("/health_check")
                .route(web::get().to(|| async { HttpResponse::Ok().body("running") })),
        )
        .service(metrics_handler);
}
