use log;
use crate::context::context::DarkShieldContext;
use models::entities::authz::{GroupCreateModel, GroupModel, GroupUpdateModel};
use services::services::authz_services::{IGroupService};
use shaku::HasComponent;

use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

#[post("/admin/realms/{realm_id}/group/create")]
pub async fn create_group(
    realm_id: web::Path<String>,
    group: web::Json<GroupCreateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    let mut group_model: GroupModel = group.0.into();
    group_model.realm_id = realm_id.to_string();
    log::info!("Creating group: {}, realm: {}", &group_model.name, &realm_id);
    group_service.create_group(group_model).await
}


#[put("/admin/realms/{realm_id}/role/update")]
pub async fn update_role(
    realm_id: web::Path<String>,
    group: web::Json<GroupUpdateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let group_service: &dyn IGroupService = context.services().resolve_ref();
    let mut group_model: GroupModel = group.0.into();
    group_model.realm_id = realm_id.to_string();
    log::info!("Creating group: {}, realm: {}", &group_model.name, &realm_id);
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
