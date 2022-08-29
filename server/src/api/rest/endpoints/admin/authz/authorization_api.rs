use log;
use shaku::HasComponent;
use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

use crate::context::context::DarkShieldContext;
use models::entities::authz::{
    GroupMutationModel, 
    GroupModel, 
    RoleMutationModel, 
    RoleModel,
    IdentityProviderModel, 
    IdentityProviderMutationModel
};
use services::services::authz_services::{
    IGroupService, 
    IRoleService, 
    IIdentityProviderService
};

#[post("/admin/realms/{realm_id}/role/create")]
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


#[put("/admin/realms/{realm_id}/role/{role_id}")]
pub async fn update_role(
    realm_id: web::Path<String>,
    role_id: web::Path<String>,
    role: web::Json<RoleMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    let mut role_model: RoleModel = role.0.into();
    role_model.realm_id = realm_id.to_string();
    role_model.role_id = role_id.to_string();
    log::info!("Creating role: {}, realm: {}", &role_model.name, &realm_id.as_str());
    role_service.update_role(role_model).await
}


#[get("/admin/realms/{realm_id}/role/{role_id}")]
pub async fn load_role_by_id(
    realm_id: web::Path<String>,
    role_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    log::info!("Loading role: {}, for realm: {}", &realm_id.as_str(), &realm_id);
    role_service.load_role_by_id(&realm_id.as_str(), &role_id.as_str()).await
}

#[delete("/admin/realms/{realm_id}/role/{role_id}")]
pub async fn delete_role_by_id(
    realm_id: web::Path<String>,
    role_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    log::info!("Deleting role: {}, for realm: {}", &role_id.as_str(), &realm_id.as_str());
    role_service.delete_role(&realm_id.as_str(), &role_id.as_str()).await
}


#[get("/admin/realms/{realm_id}/roles/load_all")]
pub async fn load_roles_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    log::info!("Loading roles for realm: {}", &realm_id.as_str());
    role_service.load_roles_by_realm(&realm_id.as_str()).await
}


#[get("/admin/realms/{realm_id}/roles/count_all")]
pub async fn count_roles_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    log::info!("Counting roles for realm: {}", &realm_id.as_str());
    role_service.count_roles_by_realm(&realm_id.as_str()).await
}

#[post("/admin/realms/{realm_id}/group/create")]
pub async fn create_group(
    realm_id: web::Path<String>,
    group: web::Json<GroupMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    let mut group_model: GroupModel = group.0.into();
    group_model.realm_id = realm_id.to_string();
    log::info!("Creating group: {}, realm: {}", &group_model.name, &realm_id);
    group_service.create_group(group_model).await
}

#[put("/admin/realms/{realm_id}/role/update")]
pub async fn update_group(
    realm_id: web::Path<String>,
    group_id: web::Path<String>,
    group: web::Json<GroupMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    let mut group_model: GroupModel = group.0.into();
    group_model.realm_id = realm_id.to_string();
    group_model.group_id = group_id.to_string();
    log::info!("Updating group: {}, realm: {}", &group_model.name, &realm_id);
    group_service.create_group(group_model).await
}

#[get("/admin/realms/{realm_id}/group/{group_id}")]
pub async fn load_group_by_id(
    realm_id: web::Path<String>,
    group_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    log::info!("Loading group: {}, for realm: {}", &realm_id.as_str(), &realm_id);
    group_service.load_group_by_id(&realm_id.as_str(), &group_id.as_str()).await
}

#[delete("/admin/realms/{realm_id}/group/{group_id}")]
pub async fn delete_group_by_id(
    realm_id: web::Path<String>,
    group_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    log::info!("Deleting group: {}, for realm: {}", &group_id.as_str(), &realm_id.as_str());
    group_service.delete_group(&realm_id.as_str(), &group_id.as_str()).await
}

#[get("/admin/realms/{realm_id}/groups/load_all")]
pub async fn load_groups_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    log::info!("Loading roles for realm: {}", &realm_id.as_str());
    group_service.load_groups_by_realm(&realm_id.as_str()).await
}

#[get("/admin/realms/{realm_id}/roles/count_all")]
pub async fn count_groups_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    log::info!("Counting groups for realm: {}", &realm_id.as_str());
    group_service.count_groups(&realm_id.as_str()).await
}


#[post("/admin/realms/{realm_id}/identity_provider/create")]
pub async fn create_identity_provider(
    realm_id: web::Path<String>,
    identity_provider: web::Json<IdentityProviderMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let identity_provider_service: &dyn IIdentityProviderService = context.services().resolve_ref();
    let mut idp_model: IdentityProviderModel = identity_provider.0.into();
    idp_model.realm_id = realm_id.to_string();
    log::info!("Creating identity provider: {}, realm: {}", &idp_model.name, realm_id.as_str());
    identity_provider_service.create_identity_provider(idp_model).await
}

#[put("/admin/realms/{realm_id}/identity_provider/{internal_id}")]
pub async fn update_identity_provider(
    realm_id: web::Path<String>,
    internal_id: web::Path<String>,
    identity_provider: web::Json<IdentityProviderMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let identity_provider_service: &dyn IIdentityProviderService = context.services().resolve_ref();
    let mut idp_model: IdentityProviderModel = identity_provider.0.into();
    idp_model.realm_id = realm_id.to_string();
    idp_model.internal_id = internal_id.to_string();
    log::info!("Updating identity provider: {}, realm: {}", &idp_model.name, realm_id.as_str());
    identity_provider_service.udpate_identity_provider(idp_model).await
}

#[get("/admin/realms/{realm_id}/identity_provider/{internal_id}")]
pub async fn load_identity_provider(
    realm_id: web::Path<String>,
    internal_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let identity_provider_service: &dyn IIdentityProviderService = context.services().resolve_ref();
    log::info!("Loading identity provider: {}, realm: {}", internal_id.as_str(), realm_id.as_str());
    identity_provider_service.load_identity_provider(realm_id.as_str(), internal_id.as_str()).await
}

#[get("/admin/realms/{realm_id}/identity_providers/load_all")]
pub async fn load_identity_providers_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let identity_provider_service: &dyn IIdentityProviderService = context.services().resolve_ref();
    log::info!("Loading identity providers for realm: {}", realm_id.as_str());
    identity_provider_service.load_identity_providers_by_realm(realm_id.as_str()).await
}

#[delete("/admin/realms/{realm_id}/identity_provider/{internal_id}")]
pub async fn delete_identity_provider(
    realm_id: web::Path<String>,
    internal_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let identity_provider_service: &dyn IIdentityProviderService = context.services().resolve_ref();
    log::info!("Deleting identity provider: {}, realm: {}", internal_id.as_str(), realm_id.as_str());
    identity_provider_service.delete_identity_provider(realm_id.as_str(), internal_id.as_str()).await
}