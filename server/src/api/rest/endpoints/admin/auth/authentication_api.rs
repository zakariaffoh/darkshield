use log;
use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};
use shaku::HasComponent;
use crate::context::context::DarkShieldContext;
use services::services::auth_services::{
    IAuthenticationExecutionService, 
    IAuthenticationFlowService, 
    IAuthenticatorConfigService,
    IRequiredActionService
};

use models::entities::auth::{
    AuthenticationExecutionMutationModel,
    AuthenticationExecutionModel,
    AuthenticationFlowMutationModel,
    AuthenticationFlowModel, 
    AuthenticatorConfigModel,
    AuthenticatorConfigMutationModel,
    RequiredActionMutationModel, 
    RequiredActionModel, 
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

#[post("/admin/realms/{realm_id}/auth/config/create")]
pub async fn create_authenticator_config(
    realm_id: web::Path<String>,
    config: web::Json<AuthenticatorConfigMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authenticator_config_service: &dyn IAuthenticatorConfigService = context.services().resolve_ref();
    let mut config_model: AuthenticatorConfigModel = config.0.into();
    config_model.realm_id = realm_id.to_string();
    log::info!("Creating authenticator config: {}, realm: {}", &config_model.alias, realm_id.as_str());
    authenticator_config_service.create_authenticator_config(config_model).await
}


#[put("/admin/realms/{realm_id}/auth/config/{execution_id}")]
pub async fn update_authenticator_config(
    realm_id: web::Path<String>,
    config_id: web::Path<String>,
    config: web::Json<AuthenticatorConfigMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authenticator_config_service: &dyn IAuthenticatorConfigService = context.services().resolve_ref();
    let mut config_model: AuthenticatorConfigModel = config.0.into();
    config_model.realm_id = realm_id.to_string();
    config_model.config_id = config_id.to_string();
    log::info!("Updating authenticator config: {}, realm: {}", &config_model.config_id, realm_id.as_str());
    authenticator_config_service.update_authenticator_config(config_model).await
}


#[get("/admin/realms/{realm_id}/auth/config/{config_id}")]
pub async fn load_authenticator_config_by_id(
    realm_id: web::Path<String>,
    config_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authenticator_config_service: &dyn IAuthenticatorConfigService = context.services().resolve_ref();
    log::info!("Loading authenticator config: {}, realm: {}", config_id.as_str(), realm_id.as_str());
    authenticator_config_service.load_authenticator_config(realm_id.as_str(), config_id.as_str()).await
}

#[get("/admin/realms/{realm_id}/auth/config/load_all")]
pub async fn load_authenticator_configs_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authenticator_config_service: &dyn IAuthenticatorConfigService = context.services().resolve_ref();
    log::info!("Loading authenticator configs realm: {}", realm_id.as_str());
    authenticator_config_service.load_authenticator_config_by_realm_id(realm_id.as_str()).await
}

#[delete("/admin/realms/{realm_id}/auth/config/{flow_id}")]
pub async fn remove_authenticator_config_by_id(
    realm_id: web::Path<String>,
    config_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let authenticator_config_service: &dyn IAuthenticatorConfigService = context.services().resolve_ref();
    log::info!("Deleting authenticator config: {}, realm: {}", config_id.as_str(), realm_id.as_str());
    authenticator_config_service.remove_authenticator_config(realm_id.as_str(), config_id.as_str()).await
}

#[post("/admin/realms/{realm_id}/required_actions/create")]
pub async fn register_required_action(
    realm_id: web::Path<String>,
    action: web::Json<RequiredActionMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();
    let mut action_model: RequiredActionModel = action.0.into();
    action_model.realm_id = realm_id.to_string();
    log::info!("Creating required action: {}, realm: {}", &action_model.name, &realm_id);
    required_action_service.register_required_action(action_model).await
}

#[put("/admin/realms/{realm_id}/required_actions/{action_id}")]
pub async fn update_required_action(
    realm_id: web::Path<String>,
    action_id: web::Path<String>,
    action: web::Json<RequiredActionMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();
    let mut action_model: RequiredActionModel = action.0.into();
    action_model.realm_id = realm_id.to_string();
    action_model.action_id = action_id.to_string();
    log::info!("Updating required action: {}, realm: {}", &action_model.name, &realm_id);
    required_action_service.update_required_action(action_model).await
}

#[get("/admin/realms/{realm_id}/actions/{action_id}")]
pub async fn load_requied_action_by_id(
    realm_id: web::Path<String>,
    action_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();
    log::info!("Loading role: {}, for realm: {}", &realm_id.as_str(), &realm_id);
    required_action_service.load_required_action(&realm_id.as_str(), &action_id.as_str()).await
}

#[delete("/admin/realms/{realm_id}/actions/{action_id}")]
pub async fn remove_requied_action_by_id(
    realm_id: web::Path<String>,
    action_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();
    log::info!("Deleting required action: {}, for realm: {}", &action_id.as_str(), &realm_id.as_str());
    required_action_service.remove_required_action(&realm_id.as_str(), &action_id.as_str()).await
}

#[get("/admin/realms/{realm_id}/actions/load_all")]
pub async fn load_requied_action_by_realm(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();
    log::info!("Loading required actions for realm: {}", &realm_id.as_str());
    required_action_service.load_required_action_by_realm_id(&realm_id.as_str()).await
}


