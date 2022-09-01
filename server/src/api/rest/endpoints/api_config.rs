use actix_web::{web, HttpResponse};

use super::{admin::auth::*, admin::authz::*, admin::realm, metrics_api::metrics_handler};

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
        .service(create_role)
        .service(update_role)
        .service(load_role_by_id)
        .service(delete_role_by_id)
        .service(load_roles_by_realm)
        .service(count_roles_by_realm)
        /* Group Api */
        .service(create_group)
        .service(update_role)
        .service(load_groups_by_realm)
        .service(delete_group_by_id)
        .service(load_groups_by_realm)
        .service(count_groups_by_realm)
        /* Authentication Execution API */
        .service(create_authentication_execution)
        .service(update_authentication_execution)
        .service(load_authentication_execution_by_id)
        .service(load_authentication_execution_by_realm)
        .service(remove_authentication_execution_by_id)
        /* Authentication flow API */
        .service(create_authentication_flow)
        .service(update_authentication_flow)
        .service(load_authentication_flow_by_id)
        .service(load_authentication_flows_by_realm)
        .service(remove_authentication_flow_by_id)
        /* Authenticator config API */
        .service(create_authenticator_config)
        .service(update_authenticator_config)
        .service(load_authenticator_config_by_id)
        .service(load_authenticator_configs_by_realm)
        .service(remove_authenticator_config_by_id)
        /* Required Action API */
        .service(register_required_action)
        .service(update_required_action)
        .service(load_requied_action_by_id)
        .service(load_requied_action_by_realm)
        .service(remove_requied_action_by_id)
        .service(
            web::resource("/health_check")
                .route(web::get().to(|| async { HttpResponse::Ok().body("running") })),
        )
        .service(metrics_handler);
}
