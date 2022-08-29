use log;
use crate::context::context::DarkShieldContext;
use models::entities::authz::{RoleCreateModel, RoleModel};
use services::services::authz_services::IRoleService;
use shaku::HasComponent;

use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

#[post("/admin/realms/{realm_id}/role/create")]
pub async fn create_role(
    realm_id: web::Path<String>,
    role: web::Json<RoleCreateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    let mut role_model: RoleModel = role.0.into();
    role_model.realm_id = realm_id.to_string();
    log::info!("Creating role: {}, realm: {}", &role_model.name, &realm_id);
    role_service.create_role(role_model).await
}


#[put("/admin/realms/{realm_id}/role/update")]
pub async fn update_role(
    realm_id: web::Path<String>,
    role: web::Json<RoleCreateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let role_service: &dyn IRoleService = context.services().resolve_ref();
    let mut role_model: RoleModel = role.0.into();
    role_model.realm_id = realm_id.to_string();
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
