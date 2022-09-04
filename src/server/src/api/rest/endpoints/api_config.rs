use actix_web::web;

use super::{
    admin::auth,
    admin::authz,
    admin::{client, realm},
    metrics_api::metrics_handler,
};

pub fn register_apis(api_config: &mut web::ServiceConfig) {
    api_config
        .service(
            web::scope("/api/v1/darkshield").service(
                web::scope("/admin")
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
                    .service(authz::update_group)
                    .service(authz::load_group_by_id)
                    .service(authz::load_groups_by_realm)
                    .service(authz::delete_group_by_id)
                    .service(authz::load_groups_by_realm)
                    .service(authz::count_groups_by_realm)
                    .service(authz::add_group_role)
                    .service(authz::remove_group_role)
                    /* Scope Api */
                    .service(authz::create_scope)
                    .service(authz::update_scope)
                    .service(authz::load_scope)
                    .service(authz::load_scope_by_realm_and_server)
                    .service(authz::delete_scope_by_id)
                    /* Resource Server Api */
                    .service(authz::create_resource_server)
                    .service(authz::update_resource_server)
                    .service(authz::load_resource_server)
                    .service(authz::load_resource_servers_by_realms)
                    .service(authz::delete_resource_server_by_id)
                    /* Resource Server Api */
                    .service(authz::create_resource)
                    .service(authz::update_resource)
                    .service(authz::load_resource)
                    .service(authz::load_resources_by_server)
                    .service(authz::delete_resource_by_id)
                    .service(authz::add_scope_to_resource)
                    .service(authz::remove_resource_scope)
                    /* Create Scope Api */
                    .service(authz::create_scope)
                    .service(authz::update_scope)
                    .service(authz::load_scope)
                    .service(authz::load_scope_by_realm_and_server)
                    .service(authz::delete_scope_by_id)
                    /* Identity Provider API*/
                    .service(authz::create_identity_provider)
                    .service(authz::update_identity_provider)
                    .service(authz::load_identity_provider)
                    .service(authz::delete_identity_provider)
                    .service(authz::load_identity_providers_by_realm)
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
                    /* Client API */
                    .service(client::create_client)
                    .service(client::update_client)
                    .service(client::load_client_by_id)
                    .service(client::delete_client_by_id)
                    .service(client::add_client_roles_mapping)
                    .service(client::remove_client_roles_mapping)
                    .service(client::load_client_roles_mapping)
                    .service(client::add_client_scope_mapping)
                    .service(client::remove_client_scope_mapping)
                    .service(client::load_client_scopes_by_client_id)
                    .service(client::add_client_protocol_mapper)
                    .service(client::remove_client_protocol_mapper)
                    .service(client::load_client_protocol_mappers)
                    .service(client::load_client_associated_service_account)
                    /* Client Scope APi */
                    .service(client::create_client_scope)
                    .service(client::update_client_scope)
                    .service(client::load_client_scope_by_id)
                    .service(client::delete_client_scope_by_id)
                    .service(client::add_client_scope_protocol_mapper)
                    .service(client::remove_client_protocol_mapper)
                    .service(client::add_client_scope_role_mapping)
                    .service(client::remove_client_scope_role_mapping)
                    /* Protocol Mapper APi */
                    .service(client::create_protocol_mapper)
                    .service(client::update_protocol_mapper)
                    .service(client::load_protocol_mapper_by_id)
                    .service(client::delete_protocol_mappers_by_id)
                    .service(client::remove_client_protocol_mapper)
                    .service(client::load_protocol_mappers_by_client_id)
                    .service(client::load_protocol_mappers_by_protocol),
            ),
        )
        .service(metrics_handler);
}
