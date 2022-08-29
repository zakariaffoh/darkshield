use actix_web::{web, HttpResponse};

use super::{
    metrics_api::metrics_handler, 
    admin::realm::realm_api,
    admin::authz::*,
    admin::auth::*,
};

pub fn register_apis(api_config: &mut web::ServiceConfig) {
    api_config
        /* Realm Api */
        .service(realm_api::update_realm)
        .service(realm_api::load_realm_by_id)
        .service(realm_api::load_realms)
        .service(realm_api::create_realm)
        .service(realm_api::delete_realm)

        /* Role Api */
        .service(authorization_api::create_role)
        .service(authorization_api::update_role)
        .service(authorization_api::load_role_by_id)
        .service(authorization_api::delete_role_by_id)
        .service(authorization_api::load_roles_by_realm)
        .service(authorization_api::count_roles_by_realm)

        /* Group Api */
        .service(authorization_api::create_group)
        .service(authorization_api::update_role)
        .service(authorization_api::load_groups_by_realm)
        .service(authorization_api::delete_group_by_id)
        .service(authorization_api::load_groups_by_realm)
        .service(authorization_api::count_groups_by_realm)

        /* Authentication Execution API */
        .service(authentication_api::create_authentication_execution)
        .service(authentication_api::update_authentication_execution)
        .service(authentication_api::load_authentication_execution_by_id)
        .service(authentication_api::load_authentication_execution_by_realm)
        .service(authentication_api::remove_authentication_execution_by_id)
        /* Authentication flow API */
        .service(authentication_api::create_authentication_flow)
        .service(authentication_api::update_authentication_flow)
        .service(authentication_api::load_authentication_flow_by_id)
        .service(authentication_api::load_authentication_flows_by_realm)
        .service(authentication_api::remove_authentication_flow_by_id)
        /* Authenticator config API */
        .service(authentication_api::create_authenticator_config)
        .service(authentication_api::update_authenticator_config)
        .service(authentication_api::load_authenticator_config_by_id)
        .service(authentication_api::load_authenticator_configs_by_realm)
        .service(authentication_api::remove_authenticator_config_by_id)
        /* Required Action API */
        .service(authentication_api::register_required_action)
        .service(authentication_api::update_required_action)
        .service(authentication_api::load_requied_action_by_id)
        .service(authentication_api::load_requied_action_by_realm)
        .service(authentication_api::remove_requied_action_by_id)

        .service(
            web::resource("/health_check")
                .route(web::get().to(|| async { HttpResponse::Ok().body("running") })),
        )
        .service(metrics_handler);
}
