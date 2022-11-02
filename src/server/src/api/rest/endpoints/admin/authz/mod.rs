use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};
use log;
use shaku::HasComponent;

use crate::{api::services::authz_api::AuthorizationModelApi, context::DarkShieldContext};
use models::entities::authz::{
    GroupModel, GroupMutationModel, IdentityProviderModel, IdentityProviderMutationModel,
    PolicyRepresentation, ResourceModel, ResourceMutationModel, ResourceServerModel,
    ResourceServerMutationModel, RoleModel, RoleMutationModel, ScopeModel, ScopeMutationModel,
};

#[post("/realm/{realm_id}/role/create")]
pub async fn create_role(
    realm_id: web::Path<String>,
    role: web::Json<RoleMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let mut role_model: RoleModel = role.0.into();
    role_model.realm_id = realm_id.to_string();
    log::info!("Creating role: {}, realm: {}", &role_model.name, &realm_id);
    AuthorizationModelApi::create_role(&context, role_model).await
}

#[put("/realm/{realm_id}/role/{role_id}")]
pub async fn update_role(
    params: web::Path<(String, String)>,
    role: web::Json<RoleMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, role_id) = params.into_inner();
    let mut role_model: RoleModel = role.0.into();
    role_model.realm_id = realm_id.to_string();
    role_model.role_id = role_id.to_string();
    log::info!(
        "Creating role: {}, realm: {}",
        &role_model.name,
        &realm_id.as_str()
    );
    AuthorizationModelApi::update_role(&context, role_model).await
}

#[get("/realm/{realm_id}/role/{role_id}")]
pub async fn load_role_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, role_id) = params.into_inner();
    log::info!(
        "Loading role: {}, for realm: {}",
        &realm_id.as_str(),
        &realm_id
    );
    AuthorizationModelApi::load_role_by_id(&context, &realm_id, &role_id).await
}

#[delete("/realm/{realm_id}/role/{role_id}")]
pub async fn delete_role_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, role_id) = params.into_inner();
    log::info!(
        "Deleting role: {}, for realm: {}",
        &role_id.as_str(),
        &realm_id.as_str()
    );
    AuthorizationModelApi::delete_role(&context, &realm_id, &role_id).await
}

#[get("/realm/{realm_id}/roles/load_all")]
pub async fn load_roles_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    log::info!("Loading roles for realm: {}", &realm_id.as_str());
    AuthorizationModelApi::load_roles_by_realm(&context, &realm_id).await
}

#[get("/realm/{realm_id}/roles/count_all")]
pub async fn count_roles_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    log::info!("Counting roles for realm: {}", &realm_id.as_str());
    AuthorizationModelApi::count_roles_by_realm(&context, &realm_id).await
}

#[post("/realm/{realm_id}/group/create")]
pub async fn create_group(
    realm_id: web::Path<String>,
    group: web::Json<GroupMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let mut group_model: GroupModel = group.0.into();
    group_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating group: {}, realm: {}",
        &group_model.name,
        &realm_id
    );
    AuthorizationModelApi::create_group(&context, group_model).await
}

#[put("/realm/{realm_id}/group/{group_id}")]
pub async fn update_group(
    params: web::Path<(String, String)>,
    group: web::Json<GroupMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, group_id) = params.into_inner();
    let mut group_model: GroupModel = group.0.into();
    group_model.realm_id = realm_id.to_string();
    group_model.group_id = group_id.to_string();
    log::info!(
        "Updating group: {}, realm: {}",
        &group_model.name,
        &realm_id
    );
    AuthorizationModelApi::udpate_group(&context, group_model).await
}

#[get("/realm/{realm_id}/group/{group_id}")]
pub async fn load_group_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, group_id) = params.into_inner();
    log::info!(
        "Loading group: {}, for realm: {}",
        &group_id.as_str(),
        &realm_id.as_str()
    );
    AuthorizationModelApi::load_group_by_id(&context, &realm_id, &group_id).await
}

#[delete("/realm/{realm_id}/group/{group_id}")]
pub async fn delete_group_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, group_id) = params.into_inner();
    log::info!(
        "Deleting group: {}, for realm: {}",
        &group_id.as_str(),
        &realm_id.as_str()
    );
    AuthorizationModelApi::delete_group(&context, &realm_id, &group_id).await
}

#[get("/realm/{realm_id}/groups/load_all")]
pub async fn load_groups_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    log::info!("Loading roles for realm: {}", &realm_id.as_str());
    AuthorizationModelApi::load_groups_by_realm(&context, &realm_id).await
}

#[get("/realm/{realm_id}/groups/count_all")]
pub async fn count_groups_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    log::info!("Counting groups for realm: {}", &realm_id.as_str());
    AuthorizationModelApi::count_groups(&context, &realm_id).await
}

#[post("/realm/{realm_id}/group/{group_id}/role/{role_id}")]
pub async fn add_group_role(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, group_id, role_id) = params.into_inner();
    log::info!(
        "Adding role:{} to group: {} for realm: {}",
        role_id.as_str(),
        group_id.as_str(),
        realm_id.as_str()
    );
    AuthorizationModelApi::add_group_role(&context, &realm_id, &group_id, &role_id).await
}

#[put("/realm/{realm_id}/group/{group_id}/role/{role_id}")]
pub async fn remove_group_role(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, group_id, role_id) = params.into_inner();
    log::info!(
        "Adding role:{} to group: {} for realm: {}",
        role_id.as_str(),
        group_id.as_str(),
        realm_id.as_str()
    );
    AuthorizationModelApi::remove_group_role(&context, &realm_id, &group_id, &role_id).await
}

#[post("/realm/{realm_id}/identity_provider/create")]
pub async fn create_identity_provider(
    realm_id: web::Path<String>,
    identity_provider: web::Json<IdentityProviderMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let mut idp_model: IdentityProviderModel = identity_provider.0.into();
    idp_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating identity provider: {}, realm: {}",
        &idp_model.name,
        realm_id.as_str()
    );
    AuthorizationModelApi::create_identity_provider(&context, idp_model).await
}

#[put("/realm/{realm_id}/identity_provider/{internal_id}")]
pub async fn update_identity_provider(
    params: web::Path<(String, String)>,
    identity_provider: web::Json<IdentityProviderMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, internal_id) = params.into_inner();
    let mut idp_model: IdentityProviderModel = identity_provider.0.into();
    idp_model.realm_id = realm_id.to_string();
    idp_model.internal_id = internal_id.to_string();
    log::info!(
        "Updating identity provider: {}, realm: {}",
        &idp_model.name,
        realm_id.as_str()
    );
    AuthorizationModelApi::udpate_identity_provider(&context, idp_model).await
}

#[get("/realm/{realm_id}/identity_provider/{internal_id}")]
pub async fn load_identity_provider(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, internal_id) = params.into_inner();
    log::info!(
        "Loading identity provider: {}, realm: {}",
        internal_id.as_str(),
        realm_id.as_str()
    );
    AuthorizationModelApi::load_identity_provider(&context, &realm_id, &internal_id).await
}

#[get("/realm/{realm_id}/identity_providers/load_all")]
pub async fn load_identity_providers_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    log::info!(
        "Loading identity providers for realm: {}",
        realm_id.as_str()
    );
    AuthorizationModelApi::load_identity_providers_by_realm(&context, &realm_id).await
}

#[delete("/realm/{realm_id}/identity_provider/{internal_id}")]
pub async fn delete_identity_provider(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, internal_id) = params.into_inner();
    log::info!(
        "Deleting identity provider: {}, realm: {}",
        internal_id.as_str(),
        realm_id.as_str()
    );
    AuthorizationModelApi::delete_identity_provider(&context, &realm_id, &internal_id).await
}

#[post("/realm/{realm_id}/resource-server/create")]
pub async fn create_resource_server(
    realm_id: web::Path<String>,
    resource_server: web::Json<ResourceServerMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let mut resource_server_model: ResourceServerModel = resource_server.0.into();
    resource_server_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating resource server: {}, realm: {}",
        &resource_server_model.name,
        realm_id.as_str()
    );
    AuthorizationModelApi::create_resource_server(&context, resource_server_model).await
}

#[put("/realm/{realm_id}/resource-server/{server_id}")]
pub async fn update_resource_server(
    params: web::Path<(String, String)>,
    resource_server: web::Json<ResourceServerMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id) = params.into_inner();
    let mut resource_server_model: ResourceServerModel = resource_server.0.into();
    log::info!(
        "Updating resource server: {}, realm: {}",
        server_id.as_str(),
        realm_id.as_str(),
    );
    resource_server_model.realm_id = realm_id;
    resource_server_model.server_id = server_id;

    AuthorizationModelApi::udpate_resource_server(&context, resource_server_model).await
}

#[get("/realm/{realm_id}/resource-server/{server_id}")]
pub async fn load_resource_server(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id) = params.into_inner();
    log::info!(
        "Updating resource server: {}, realm: {}",
        server_id.as_str(),
        realm_id.as_str()
    );

    AuthorizationModelApi::load_resource_server_by_id(&context, &realm_id, &server_id).await
}

#[get("/realm/{realm_id}/resources_servers/all")]
pub async fn load_resource_servers_by_realms(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    log::info!("Loading resources servers by realm: {}", realm_id.as_str());
    AuthorizationModelApi::load_resource_servers_by_realm(&context, &realm_id).await
}

#[delete("/realm/{realm_id}/resource-server/{server_id}")]
pub async fn delete_resource_server_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id) = params.into_inner();
    log::info!(
        "Deleting resource server: {}, realm: {}",
        server_id.as_str(),
        realm_id.as_str()
    );
    AuthorizationModelApi::delete_resource_server_by_id(&context, &realm_id, &server_id).await
}

#[post("/realm/{realm_id}/resource-server/{server_id}/resource/create")]
pub async fn create_resource(
    params: web::Path<(String, String)>,
    resource: web::Json<ResourceMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id) = params.into_inner();
    let mut resource_model: ResourceModel = resource.0.into();
    resource_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating resource: {}, server: {}, realm: {}",
        &resource_model.name,
        &resource_model.server_id,
        realm_id.as_str()
    );
    resource_model.realm_id = realm_id;
    resource_model.server_id = server_id;
    AuthorizationModelApi::create_resource(&context, resource_model).await
}

#[put("/realm/{realm_id}/resource-server/{server_id}/resource/{resource_id}")]
pub async fn update_resource(
    params: web::Path<(String, String, String)>,
    resource: web::Json<ResourceMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let mut resource_model: ResourceModel = resource.0.into();
    let (realm_id, server_id, resource_id) = params.into_inner();
    log::info!(
        "Updating resource: {}, server: {}, realm: {}",
        resource_id.as_str(),
        server_id.as_str(),
        realm_id.as_str(),
    );
    resource_model.realm_id = realm_id;
    resource_model.server_id = server_id;
    resource_model.resource_id = resource_id;
    AuthorizationModelApi::udpate_resource(&context, resource_model).await
}

#[get("/realm/{realm_id}/resource-server/{server_id}/resource/{resource_id}")]
pub async fn load_resource(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, resource_id) = params.into_inner();
    log::info!(
        "Updating resource: {}, server: {}, realm: {}",
        resource_id.as_str(),
        server_id.as_str(),
        realm_id.as_str()
    );
    AuthorizationModelApi::load_resource_by_id(&context, &realm_id, &server_id, &resource_id).await
}

#[get("/realm/{realm_id}/resource-server/{server_id}/resources/load_all")]
pub async fn load_resources_by_server(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id) = params.into_inner();
    log::info!(
        "Loading resources server: {}, realm: {}",
        server_id.as_str(),
        realm_id.as_str()
    );
    AuthorizationModelApi::load_resources_by_server(&context, &realm_id, &server_id).await
}

#[delete("/realm/{realm_id}/resource-server/{server_id}/resource/{resource_id}")]
pub async fn delete_resource_by_id(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, resource_id) = params.into_inner();
    log::info!(
        "Deleting resource: {}, server: {}, realm: {}",
        resource_id.as_str(),
        server_id.as_str(),
        realm_id.as_str()
    );
    AuthorizationModelApi::delete_resource_by_id(&context, &realm_id, &server_id, &resource_id)
        .await
}

#[post("/realm/{realm_id}/resource-server/{server_id}/resource/{resource_id}/scope/{scope_id}")]
pub async fn add_scope_to_resource(
    params: web::Path<(String, String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, resource_id, scope_id) = params.into_inner();
    log::info!(
        "Adding scope:{} to resource: {}, server: {} for realm: {}",
        &scope_id,
        &resource_id,
        &server_id,
        &realm_id
    );
    AuthorizationModelApi::add_resource_scope(
        &context,
        &realm_id,
        &server_id,
        &resource_id,
        &scope_id,
    )
    .await
}

#[put("/realm/{realm_id}/resource-server/{server_id}/resource/{resource_id}/scope/{scope_id}")]
pub async fn remove_resource_scope(
    params: web::Path<(String, String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, resource_id, scope_id) = params.into_inner();
    log::info!(
        "Removing scope:{} to resource: {}, server: {} for realm: {}",
        scope_id.as_str(),
        resource_id.as_str(),
        server_id.as_str(),
        realm_id.as_str()
    );
    AuthorizationModelApi::remove_resource_scope(
        &context,
        &realm_id,
        &server_id,
        &resource_id,
        &scope_id,
    )
    .await
}

#[post("/realm/{realm_id}/resource-server/{server_id}/scope/create")]
pub async fn create_scope(
    params: web::Path<(String, String)>,
    scope: web::Json<ScopeMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id) = params.into_inner();
    let mut scope_model: ScopeModel = scope.0.into();
    scope_model.server_id = server_id;
    scope_model.realm_id = realm_id;

    log::info!(
        "Creating scope: {}, resource server: {}, realm: {}",
        &scope_model.name,
        &scope_model.server_id,
        &scope_model.realm_id,
    );
    AuthorizationModelApi::create_scope(&context, scope_model).await
}

#[put("/realm/{realm_id}/resource-server/{server_id}/scope/{scope_id}")]
pub async fn update_scope(
    params: web::Path<(String, String, String)>,
    scope: web::Json<ScopeMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, scope_id) = params.into_inner();
    let mut scope_model: ScopeModel = scope.0.into();
    scope_model.server_id = server_id;
    scope_model.realm_id = realm_id;
    scope_model.scope_id = scope_id;

    log::info!(
        "Updating scope {}, server: {}, realm: {}",
        &scope_model.scope_id,
        &scope_model.server_id,
        &scope_model.realm_id,
    );
    AuthorizationModelApi::udpate_scope(&context, scope_model).await
}

#[get("/realm/{realm_id}/resource-server/{server_id}/scope/{scope_id}")]
pub async fn load_scope_by_id(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, scope_id) = params.into_inner();
    log::info!(
        "Loading scope: {} resource server: {}, realm: {}",
        scope_id.as_str(),
        server_id.as_str(),
        realm_id.as_str()
    );
    AuthorizationModelApi::load_scope_by_id(&context, &realm_id, &server_id, &scope_id).await
}

#[get("/realm/{realm_id}/resource-server/{server_id}/scopes/load_all")]
pub async fn load_scope_by_realm_and_server(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id) = params.into_inner();
    log::info!(
        "Loading scopes server: {}, realm: {}",
        server_id.as_str(),
        realm_id.as_str()
    );
    AuthorizationModelApi::load_scopes_by_realm(&context, &realm_id, &server_id).await
}

#[delete("/realm/{realm_id}/resource-server/{server_id}/scope/{scope_id}")]
pub async fn delete_scope_by_id(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, scope_id) = params.into_inner();
    log::info!(
        "Deleting scope {}, resource server: {}, realm: {}",
        scope_id.as_str(),
        server_id.as_str(),
        realm_id.as_str()
    );

    AuthorizationModelApi::delete_scope_by_id(&context, &realm_id, &server_id, &scope_id).await
}

#[post("/realm/{realm_id}/resource-server/{server_id}/policy/create")]
pub async fn create_policy(
    params: web::Path<(String, String)>,
    policy: web::Json<PolicyRepresentation>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id) = params.into_inner();
    let policy_model: PolicyRepresentation = policy.0;
    log::info!(
        "Creating new policy, realm: {}, server: {}",
        &realm_id,
        &server_id
    );
    AuthorizationModelApi::create_policy(&context, &realm_id, &server_id, policy_model).await
}

#[put("/realm/{realm_id}/resource-server/{server_id}/policy/{policy_id}")]
pub async fn update_policy(
    params: web::Path<(String, String, String)>,
    policy: web::Json<PolicyRepresentation>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, policy_id) = params.into_inner();
    let policy_model: PolicyRepresentation = policy.0;
    log::info!(
        "Updating policy: {}, realm: {}, server: {}",
        &policy_id,
        &realm_id,
        &server_id
    );
    AuthorizationModelApi::update_policy(&context, &realm_id, &server_id, &policy_id, policy_model)
        .await
}

#[get("/realm/{realm_id}/resource-server/{server_id}/policy/{policy_id}")]
pub async fn load_policy_by_id(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, policy_id) = params.into_inner();
    log::info!(
        "loading policy: {}, realm: {}, server: {}",
        &policy_id,
        &realm_id,
        &server_id
    );
    AuthorizationModelApi::load_policy_by_id(&context, &realm_id, &server_id, &policy_id).await
}

#[get("/realm/{realm_id}/resource-server/{server_id}/policy/{policy_id}/scopes")]
pub async fn load_policy_scopes_by_policy_id(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, policy_id) = params.into_inner();
    log::info!(
        "loading policy: {}, realm: {}, server: {} scopes",
        &policy_id,
        &realm_id,
        &server_id
    );
    AuthorizationModelApi::load_policy_scopes_by_policy_id(
        &context, &realm_id, &server_id, &policy_id,
    )
    .await
}

#[get("/realm/{realm_id}/resource-server/{server_id}/policy/{policy_id}/resources")]
pub async fn load_policy_resources_by_policy_id(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, policy_id) = params.into_inner();
    log::info!(
        "loading policy: {}, realm: {}, server: {} scopes",
        &policy_id,
        &realm_id,
        &server_id
    );
    AuthorizationModelApi::load_policy_resources_by_policy_id(
        &context, &realm_id, &server_id, &policy_id,
    )
    .await
}

#[get("/realm/{realm_id}/resource-server/{server_id}/policy/{policy_id}/associated-policies")]
pub async fn load_associates_policies_by_policy_id(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, policy_id) = params.into_inner();
    log::info!(
        "loading associated policies for policy: {}, realm: {}, server: {} scopes",
        &policy_id,
        &realm_id,
        &server_id
    );
    AuthorizationModelApi::load_associates_policies_by_policy_id(
        &context, &realm_id, &server_id, &policy_id,
    )
    .await
}

#[get("/realm/{realm_id}/resource-server/{server_id}/policies/all")]
pub async fn load_policies_by_server_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id) = params.into_inner();
    log::info!(
        "loading policies for realm: {}, server: {}",
        &realm_id,
        &server_id
    );
    AuthorizationModelApi::load_policies_by_server_id(&context, &realm_id, &server_id).await
}

#[get("/realm/{realm_id}/resource-server/{server_id}/policies/count")]
pub async fn count_policies_by_query(
    params: web::Path<String>,
    query: web::Query<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_id = params.into_inner();
    let count_query = query.into_inner();
    log::info!(
        "counting policies for realm: {}, query: {}",
        &realm_id,
        &count_query
    );
    AuthorizationModelApi::count_policies_by_query(&context, &realm_id, &count_query).await
}

#[get("/realm/{realm_id}/resource-server/{server_id}/policies/search")]
pub async fn search_policies_by_query(
    params: web::Path<String>,
    query: web::Query<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let realm_id = params.into_inner();
    let search_query = query.into_inner();
    log::info!(
        "Searching policies for realm: {}, query: {}",
        &realm_id,
        &search_query
    );
    AuthorizationModelApi::search_policies_by_query(&context, &realm_id, &search_query).await
}

#[delete("/realm/{realm_id}/resource-server/{server_id}/policy/{policy_id}")]
pub async fn delete_policy_by_id(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let (realm_id, server_id, policy_id) = params.into_inner();
    log::info!(
        "deleting policy: {}, realm: {}, server: {}",
        &policy_id,
        &realm_id,
        &server_id
    );
    AuthorizationModelApi::delete_policy_by_id(&context, &realm_id, &server_id, &policy_id).await
}
