use log;
use crate::context::context::DarkShieldContext;
use models::entities::auth::{AuthenticationFlowMutationModel,AuthenticationFlowModel};
use services::services::auth_services::IAuthenticationFlowService;
use shaku::HasComponent;

use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

#[post("/admin/realms/{realm_id}/auth/flow/create")]
pub async fn create_authentication_flow(
    realm_id: web::Path<String>,
    flow: web::Json<AuthenticationFlowMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authentication_flow_service: &dyn IAuthenticationFlowService = context.services().resolve_ref();
    let mut flow_model: AuthenticationFlowModel = flow.0.into();
    flow_model.realm_id = realm_id.to_string();
    log::info!("Creating authentication flow: {}, realm: {}", &flow_model.alias, realm_id.as_str());
    authentication_flow_service.create_authentication_flow(flow_model).await
}


#[put("/admin/realms/{realm_id}/auth/flow/{flow_id}")]
pub async fn update_authentication_flow(
    realm_id: web::Path<String>,
    flow_id: web::Path<String>,
    flow: web::Json<AuthenticationFlowMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authentication_flow_service: &dyn IAuthenticationFlowService = context.services().resolve_ref();
    let mut flow_model: AuthenticationFlowModel = flow.0.into();
    flow_model.realm_id = realm_id.to_string();
    flow_model.flow_id = flow_id.to_string();
    log::info!("Updating authentication flow: {}, realm: {}", &flow_model.flow_id, realm_id.as_str());
    authentication_flow_service.update_authentication_flow(flow_model).await
}


#[get("/admin/realms/{realm_id}/auth/flow/{flow_id}")]
pub async fn load_authentication_flow_by_id(
    realm_id: web::Path<String>,
    flow_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authentication_flow_service: &dyn IAuthenticationFlowService = context.services().resolve_ref();
    log::info!("Loading authentication flow: {}, realm: {}", flow_id.as_str(), realm_id.as_str());
    authentication_flow_service.load_authentication_flow_by_flow_id(realm_id.as_str(), flow_id.as_str()).await
}


#[get("/admin/realms/{realm_id}/auth/flows/load_all")]
pub async fn load_authentication_flows_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authentication_flow_service: &dyn IAuthenticationFlowService = context.services().resolve_ref();
    log::info!("Loading authentication flows realm: {}", realm_id.as_str());
    authentication_flow_service.load_authentication_flow_by_realm_id(realm_id.as_str()).await
}

#[delete("/admin/realms/{realm_id}/auth/flow/{flow_id}")]
pub async fn remove_authentication_flow_by_id(
    realm_id: web::Path<String>,
    flow_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authentication_flow_service: &dyn IAuthenticationFlowService = context.services().resolve_ref();
    log::info!("Deleting authentication flow: {}, realm: {}", flow_id.as_str(), realm_id.as_str());
    authentication_flow_service.remove_authentication_flow(realm_id.as_str(), flow_id.as_str()).await
}
