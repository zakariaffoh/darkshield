use log;
use crate::context::context::DarkShieldContext;
use models::entities::auth::{AuthenticationExecutionMutationModel,AuthenticationExecutionModel};
use services::services::auth_services::IAuthenticationExecutionService;
use shaku::HasComponent;

use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

#[post("/admin/realms/{realm_id}/auth/execution/create")]
pub async fn create_authentication_execution(
    realm_id: web::Path<String>,
    execution: web::Json<AuthenticationExecutionMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authentication_execution_service: &dyn IAuthenticationExecutionService = context.services().resolve_ref();
    let mut execution_model: AuthenticationExecutionModel = execution.0.into();
    execution_model.realm_id = realm_id.to_string();
    log::info!("Creating authentication execution: {}, realm: {}", &execution_model.alias, realm_id.as_str());
    authentication_execution_service.create_authentication_execution(execution_model).await
}


#[put("/admin/realms/{realm_id}/auth/execution/{execution_id}")]
pub async fn update_authentication_execution(
    realm_id: web::Path<String>,
    execution_id: web::Path<String>,
    execution: web::Json<AuthenticationExecutionMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authentication_execution_service: &dyn IAuthenticationExecutionService = context.services().resolve_ref();
    let mut execution_model: AuthenticationExecutionModel = execution.0.into();
    execution_model.realm_id = realm_id.to_string();
    execution_model.execution_id = execution_id.to_string();
    log::info!("Updating authentication execution: {}, realm: {}", &execution_model.execution_id, realm_id.as_str());
    authentication_execution_service.update_authentication_execution(execution_model).await
}


#[get("/admin/realms/{realm_id}/auth/execution/{execution_id}")]
pub async fn load_authentication_execution_by_id(
    realm_id: web::Path<String>,
    execution_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authentication_execution_service: &dyn IAuthenticationExecutionService = context.services().resolve_ref();
    log::info!("Loading authentication execution: {}, realm: {}", execution_id.as_str(), realm_id.as_str());
    authentication_execution_service.load_authentication_execution(realm_id.as_str(), execution_id.as_str()).await
}


#[get("/admin/realms/{realm_id}/auth/executions/load_all")]
pub async fn load_authentication_execution_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authentication_execution_service: &dyn IAuthenticationExecutionService = context.services().resolve_ref();
    log::info!("Loading authentication execution realm: {}", realm_id.as_str());
    authentication_execution_service.load_authentication_execution_by_realm_id(realm_id.as_str()).await
}

#[delete("/admin/realms/{realm_id}/auth/execution/{flow_id}")]
pub async fn remove_authentication_execution_by_id(
    realm_id: web::Path<String>,
    execution_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authentication_execution_service: &dyn IAuthenticationExecutionService = context.services().resolve_ref();
    log::info!("Deleting authentication execution: {}, realm: {}", execution_id.as_str(), realm_id.as_str());
    authentication_execution_service.remove_authentication_execution(realm_id.as_str(), execution_id.as_str()).await
}
