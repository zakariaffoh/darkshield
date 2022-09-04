use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};
use log;
use shaku::HasComponent;

use crate::context::DarkShieldContext;
use models::entities::authz::{
    GroupModel, GroupMutationModel, IdentityProviderModel, IdentityProviderMutationModel,
    ResourceServerModel, ResourceServerMutationModel, RoleModel, RoleMutationModel, ScopeModel,
    ScopeMutationModel,
};
use services::services::authz_services::{
    IGroupService, IIdentityProviderService, IResourceServerService, IRoleService, IScopeService,
};

#[post("/realm/{realm_id}/role/create")]
pub async fn create_role(
    realm_id: web::Path<String>,
    role: web::Json<RoleMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    let mut role_model: RoleModel = role.0.into();
    role_model.realm_id = realm_id.to_string();
    log::info!("Creating role: {}, realm: {}", &role_model.name, &realm_id);
    role_service.create_role(role_model).await
}

#[put("/realm/{realm_id}/role/{role_id}")]
pub async fn update_role(
    params: web::Path<(String, String)>,
    role: web::Json<RoleMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    let (realm_id, role_id) = params.into_inner();
    let mut role_model: RoleModel = role.0.into();
    role_model.realm_id = realm_id.to_string();
    role_model.role_id = role_id.to_string();
    log::info!(
        "Creating role: {}, realm: {}",
        &role_model.name,
        &realm_id.as_str()
    );
    role_service.update_role(role_model).await
}

#[get("/realm/{realm_id}/role/{role_id}")]
pub async fn load_role_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    let (realm_id, role_id) = params.into_inner();
    log::info!(
        "Loading role: {}, for realm: {}",
        &realm_id.as_str(),
        &realm_id
    );
    role_service
        .load_role_by_id(&realm_id.as_str(), &role_id.as_str())
        .await
}

#[delete("/realm/{realm_id}/role/{role_id}")]
pub async fn delete_role_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    let (realm_id, role_id) = params.into_inner();
    log::info!(
        "Deleting role: {}, for realm: {}",
        &role_id.as_str(),
        &realm_id.as_str()
    );
    role_service
        .delete_role(&realm_id.as_str(), &role_id.as_str())
        .await
}

#[get("/realm/{realm_id}/roles/load_all")]
pub async fn load_roles_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    log::info!("Loading roles for realm: {}", &realm_id.as_str());
    role_service.load_roles_by_realm(&realm_id.as_str()).await
}

#[get("/realm/{realm_id}/roles/count_all")]
pub async fn count_roles_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    log::info!("Counting roles for realm: {}", &realm_id.as_str());
    role_service.count_roles_by_realm(&realm_id.as_str()).await
}

#[post("/realm/{realm_id}/group/create")]
pub async fn create_group(
    realm_id: web::Path<String>,
    group: web::Json<GroupMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    let mut group_model: GroupModel = group.0.into();
    group_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating group: {}, realm: {}",
        &group_model.name,
        &realm_id
    );
    group_service.create_group(group_model).await
}

#[put("/realm/{realm_id}/group/{group_id}")]
pub async fn update_group(
    params: web::Path<(String, String)>,
    group: web::Json<GroupMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    let (realm_id, group_id) = params.into_inner();
    let mut group_model: GroupModel = group.0.into();
    group_model.realm_id = realm_id.to_string();
    group_model.group_id = group_id.to_string();
    log::info!(
        "Updating group: {}, realm: {}",
        &group_model.name,
        &realm_id
    );
    group_service.udpate_group(group_model).await
}

#[get("/realm/{realm_id}/group/{group_id}")]
pub async fn load_group_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    let (realm_id, group_id) = params.into_inner();
    log::info!(
        "Loading group: {}, for realm: {}",
        &group_id.as_str(),
        &realm_id.as_str()
    );
    group_service
        .load_group_by_id(&realm_id.as_str(), &group_id.as_str())
        .await
}

#[delete("/realm/{realm_id}/group/{group_id}")]
pub async fn delete_group_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    let (realm_id, group_id) = params.into_inner();
    log::info!(
        "Deleting group: {}, for realm: {}",
        &group_id.as_str(),
        &realm_id.as_str()
    );
    group_service
        .delete_group(&realm_id.as_str(), &group_id.as_str())
        .await
}

#[get("/realm/{realm_id}/groups/load_all")]
pub async fn load_groups_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    log::info!("Loading roles for realm: {}", &realm_id.as_str());
    group_service.load_groups_by_realm(&realm_id.as_str()).await
}

#[get("/realm/{realm_id}/groups/count_all")]
pub async fn count_groups_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    log::info!("Counting groups for realm: {}", &realm_id.as_str());
    group_service.count_groups(&realm_id.as_str()).await
}

#[post("/realm/{realm_id}/group/{group_id}/role/{role_id}")]
pub async fn add_group_role(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    let (realm_id, group_id, role_id) = params.into_inner();
    log::info!(
        "Adding role:{} to group: {} for realm: {}",
        role_id.as_str(),
        group_id.as_str(),
        realm_id.as_str()
    );
    group_service
        .add_group_role(realm_id.as_str(), group_id.as_str(), role_id.as_str())
        .await
}

#[put("/realm/{realm_id}/group/{group_id}/role/{role_id}")]
pub async fn remove_group_role(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    let (realm_id, group_id, role_id) = params.into_inner();
    log::info!(
        "Adding role:{} to group: {} for realm: {}",
        role_id.as_str(),
        group_id.as_str(),
        realm_id.as_str()
    );
    group_service
        .remove_group_role(realm_id.as_str(), group_id.as_str(), role_id.as_str())
        .await
}

#[post("/realm/{realm_id}/identity_provider/create")]
pub async fn create_identity_provider(
    realm_id: web::Path<String>,
    identity_provider: web::Json<IdentityProviderMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let identity_provider_service: &dyn IIdentityProviderService = context.services().resolve_ref();
    let mut idp_model: IdentityProviderModel = identity_provider.0.into();
    idp_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating identity provider: {}, realm: {}",
        &idp_model.name,
        realm_id.as_str()
    );
    identity_provider_service
        .create_identity_provider(idp_model)
        .await
}

#[put("/realm/{realm_id}/identity_provider/{internal_id}")]
pub async fn update_identity_provider(
    params: web::Path<(String, String)>,
    identity_provider: web::Json<IdentityProviderMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let identity_provider_service: &dyn IIdentityProviderService = context.services().resolve_ref();
    let (realm_id, internal_id) = params.into_inner();
    let mut idp_model: IdentityProviderModel = identity_provider.0.into();
    idp_model.realm_id = realm_id.to_string();
    idp_model.internal_id = internal_id.to_string();
    log::info!(
        "Updating identity provider: {}, realm: {}",
        &idp_model.name,
        realm_id.as_str()
    );
    identity_provider_service
        .udpate_identity_provider(idp_model)
        .await
}

#[get("/realm/{realm_id}/identity_provider/{internal_id}")]
pub async fn load_identity_provider(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let identity_provider_service: &dyn IIdentityProviderService = context.services().resolve_ref();
    let (realm_id, internal_id) = params.into_inner();
    log::info!(
        "Loading identity provider: {}, realm: {}",
        internal_id.as_str(),
        realm_id.as_str()
    );
    identity_provider_service
        .load_identity_provider(realm_id.as_str(), internal_id.as_str())
        .await
}

#[get("/realm/{realm_id}/identity_providers/load_all")]
pub async fn load_identity_providers_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let identity_provider_service: &dyn IIdentityProviderService = context.services().resolve_ref();
    log::info!(
        "Loading identity providers for realm: {}",
        realm_id.as_str()
    );
    identity_provider_service
        .load_identity_providers_by_realm(realm_id.as_str())
        .await
}

#[delete("/realm/{realm_id}/identity_provider/{internal_id}")]
pub async fn delete_identity_provider(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let identity_provider_service: &dyn IIdentityProviderService = context.services().resolve_ref();
    let (realm_id, internal_id) = params.into_inner();
    log::info!(
        "Deleting identity provider: {}, realm: {}",
        internal_id.as_str(),
        realm_id.as_str()
    );
    identity_provider_service
        .delete_identity_provider(realm_id.as_str(), internal_id.as_str())
        .await
}

#[post("/realm/{realm_id}/resource_server/create")]
pub async fn create_resource_server(
    realm_id: web::Path<String>,
    resource_server: web::Json<ResourceServerMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let resource_server_server: &dyn IResourceServerService = context.services().resolve_ref();
    let mut resource_server_model: ResourceServerModel = resource_server.0.into();
    resource_server_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating resource server: {}, realm: {}",
        &resource_server_model.name,
        realm_id.as_str()
    );
    resource_server_server
        .create_resource_server(resource_server_model)
        .await
}

#[put("/realm/{realm_id}/resource_server/{server_id}")]
pub async fn update_resource_server(
    params: web::Path<(String, String)>,
    resource_server: web::Json<ResourceServerMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let resource_server_service: &dyn IResourceServerService = context.services().resolve_ref();
    let (realm_id, server_id) = params.into_inner();
    let mut resource_server_model: ResourceServerModel = resource_server.0.into();
    log::info!(
        "Updating resource server: {}, realm: {}",
        server_id.as_str(),
        realm_id.as_str(),
    );
    resource_server_model.realm_id = realm_id;
    resource_server_model.server_id = server_id;
    resource_server_service
        .udpate_resource_server(resource_server_model)
        .await
}

#[get("/realm/{realm_id}/resource_server/{server_id}")]
pub async fn load_resource_server(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let resource_server_service: &dyn IResourceServerService = context.services().resolve_ref();
    let (realm_id, server_id) = params.into_inner();
    log::info!(
        "Updating resource server: {}, realm: {}",
        server_id.as_str(),
        realm_id.as_str()
    );
    resource_server_service
        .load_resource_server_by_id(realm_id.as_str(), server_id.as_str())
        .await
}

#[get("/realm/{realm_id}/resources_servers/all")]
pub async fn load_resource_servers_by_realms(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let resource_server_service: &dyn IResourceServerService = context.services().resolve_ref();
    log::info!("Loading resources servers by realm: {}", realm_id.as_str());
    resource_server_service
        .load_resource_servers_by_realm(realm_id.as_str())
        .await
}

#[delete("/realm/{realm_id}/resource_server/{server_id}")]
pub async fn delete_resource_server_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let resource_server_service: &dyn IResourceServerService = context.services().resolve_ref();
    let (realm_id, server_id) = params.into_inner();
    log::info!(
        "Deleting resource server: {}, realm: {}",
        server_id.as_str(),
        realm_id.as_str()
    );
    resource_server_service
        .delete_resource_server_by_id(realm_id.as_str(), server_id.as_str())
        .await
}

#[post("/realm/{realm_id}/resource_server/{server_id}/scope/create")]
pub async fn create_scope(
    params: web::Path<(String, String)>,
    scope: web::Json<ScopeMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let scope_service: &dyn IScopeService = context.services().resolve_ref();
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
    scope_service.create_scope(scope_model).await
}

#[put("/realm/{realm_id}/resource_server/{server_id}/scope/{scope_id}")]
pub async fn update_scope(
    params: web::Path<(String, String, String)>,
    scope: web::Json<ScopeMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let scope_service: &dyn IScopeService = context.services().resolve_ref();
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
    scope_service.udpate_scope(scope_model).await
}

#[get("/realm/{realm_id}/resource_server/{server_id}/scope/{scope_id}")]
pub async fn load_scope(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let scope_service: &dyn IScopeService = context.services().resolve_ref();
    let (realm_id, server_id, scope_id) = params.into_inner();
    log::info!(
        "Loading scope: {} resource server: {}, realm: {}",
        scope_id.as_str(),
        server_id.as_str(),
        realm_id.as_str()
    );
    scope_service
        .load_scope_by_id(realm_id.as_str(), server_id.as_str(), scope_id.as_str())
        .await
}

#[get("/realm/{realm_id}/resource_server/{server_id}/scopes/load_all")]
pub async fn load_scope_by_realm_and_server(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let scope_service: &dyn IScopeService = context.services().resolve_ref();
    let (realm_id, server_id) = params.into_inner();
    log::info!(
        "Loading scopes server: {}, realm: {}",
        server_id.as_str(),
        realm_id.as_str()
    );
    scope_service
        .load_scopes_by_realm(realm_id.as_str(), server_id.as_str())
        .await
}

#[delete("/realm/{realm_id}/resource_server/{server_id}/scope/{scope_id}")]
pub async fn delete_scope_by_id(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let scope_service: &dyn IScopeService = context.services().resolve_ref();
    let (realm_id, server_id, scope_id) = params.into_inner();
    log::info!(
        "Deleting scope {}, resource server: {}, realm: {}",
        scope_id.as_str(),
        server_id.as_str(),
        realm_id.as_str()
    );
    scope_service
        .delete_scope_by_id(realm_id.as_str(), server_id.as_str(), &scope_id.as_str())
        .await
}
