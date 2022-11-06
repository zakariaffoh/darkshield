use crate::api::services::auth_api::AuthenticationModelApi;
use services::session::session::DarkshieldSession;

use actix_web::{delete, get, post, put, web, Responder};
use log;
use models::entities::auth::{
    AuthenticationExecutionModel, AuthenticationExecutionMutationModel, AuthenticationFlowModel,
    AuthenticationFlowMutationModel, AuthenticatorConfigModel, AuthenticatorConfigMutationModel,
    RequiredActionModel, RequiredActionMutationModel,
};

#[post("/realm/{realm_id}/auth/execution/create")]
pub async fn create_authentication_execution(
    realm_id: web::Path<String>,
    execution: web::Json<AuthenticationExecutionMutationModel>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let mut execution_model: AuthenticationExecutionModel = execution.0.into();
    execution_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating authentication execution: {}, realm: {}",
        &execution_model.alias,
        realm_id.as_str()
    );
    AuthenticationModelApi::create_authentication_execution(&session, execution_model).await
}

#[put("/realm/{realm_id}/auth/execution/{execution_id}")]
pub async fn update_authentication_execution(
    params: web::Path<(String, String)>,
    execution: web::Json<AuthenticationExecutionMutationModel>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, execution_id) = params.into_inner();

    let mut execution_model: AuthenticationExecutionModel = execution.0.into();
    execution_model.realm_id = realm_id.to_string();
    execution_model.execution_id = execution_id.to_string();
    log::info!(
        "Updating authentication execution: {}, realm: {}",
        &execution_model.execution_id,
        realm_id.as_str()
    );
    AuthenticationModelApi::update_authentication_execution(&session, execution_model).await
}

#[get("/realm/{realm_id}/auth/execution/{execution_id}")]
pub async fn load_authentication_execution_by_id(
    params: web::Path<(String, String)>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, execution_id) = params.into_inner();
    log::info!(
        "Loading authentication execution: {}, realm: {}",
        execution_id.as_str(),
        realm_id.as_str()
    );
    AuthenticationModelApi::load_authentication_execution(&session, &realm_id, &execution_id).await
}

#[get("/realm/{realm_id}/auth/executions/load_all")]
pub async fn load_authentication_execution_by_realm(
    realm_id: web::Path<String>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    log::info!(
        "Loading authentication execution realm: {}",
        realm_id.as_str()
    );
    AuthenticationModelApi::load_authentication_execution_by_realm_id(&session, &realm_id).await
}

#[delete("/realm/{realm_id}/auth/execution/{execution_id}")]
pub async fn remove_authentication_execution_by_id(
    params: web::Path<(String, String)>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, execution_id) = params.into_inner();
    log::info!(
        "Deleting authentication execution: {}, realm: {}",
        execution_id.as_str(),
        realm_id.as_str()
    );
    AuthenticationModelApi::remove_authentication_execution(&session, &realm_id, &execution_id)
        .await
}

#[post("/realm/{realm_id}/auth/flow/create")]
pub async fn create_authentication_flow(
    realm_id: web::Path<String>,
    flow: web::Json<AuthenticationFlowMutationModel>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let mut flow_model: AuthenticationFlowModel = flow.0.into();
    flow_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating authentication flow: {}, realm: {}",
        &flow_model.alias,
        realm_id.as_str()
    );
    AuthenticationModelApi::create_authentication_flow(&session, flow_model).await
}

#[put("/realm/{realm_id}/auth/flow/{flow_id}")]
pub async fn update_authentication_flow(
    params: web::Path<(String, String)>,
    flow: web::Json<AuthenticationFlowMutationModel>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, flow_id) = params.into_inner();
    let mut flow_model: AuthenticationFlowModel = flow.0.into();
    flow_model.realm_id = realm_id.to_string();
    flow_model.flow_id = flow_id.to_string();
    log::info!(
        "Updating authentication flow: {}, realm: {}",
        &flow_model.flow_id,
        realm_id.as_str()
    );
    AuthenticationModelApi::update_authentication_flow(&session, flow_model).await
}

#[get("/realm/{realm_id}/auth/flow/{flow_id}")]
pub async fn load_authentication_flow_by_id(
    params: web::Path<(String, String)>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, flow_id) = params.into_inner();
    log::info!(
        "Loading authentication flow: {}, realm: {}",
        flow_id.as_str(),
        realm_id.as_str()
    );
    AuthenticationModelApi::load_authentication_flow_by_flow_id(&session, &realm_id, &flow_id).await
}

#[get("/realm/{realm_id}/auth/flows/load_all")]
pub async fn load_authentication_flows_by_realm(
    realm_id: web::Path<String>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    log::info!("Loading authentication flows realm: {}", realm_id.as_str());
    AuthenticationModelApi::load_authentication_flow_by_realm_id(&session, &realm_id).await
}

#[delete("/realm/{realm_id}/auth/flow/{flow_id}")]
pub async fn remove_authentication_flow_by_id(
    params: web::Path<(String, String)>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, flow_id) = params.into_inner();
    log::info!(
        "Deleting authentication flow: {}, realm: {}",
        flow_id.as_str(),
        realm_id.as_str()
    );
    AuthenticationModelApi::remove_authentication_flow(&session, &realm_id, &flow_id).await
}

#[post("/realm/{realm_id}/auth/config/create")]
pub async fn create_authenticator_config(
    realm_id: web::Path<String>,
    config: web::Json<AuthenticatorConfigMutationModel>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let mut config_model: AuthenticatorConfigModel = config.0.into();
    config_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating authenticator config: {}, realm: {}",
        &config_model.alias,
        realm_id.as_str()
    );
    AuthenticationModelApi::create_authenticator_config(&session, config_model).await
}

#[put("/realm/{realm_id}/auth/config/{config_id}")]
pub async fn update_authenticator_config(
    params: web::Path<(String, String)>,
    config: web::Json<AuthenticatorConfigMutationModel>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, config_id) = params.into_inner();
    let mut config_model: AuthenticatorConfigModel = config.0.into();
    config_model.realm_id = realm_id.to_string();
    config_model.config_id = config_id.to_string();
    log::info!(
        "Updating authenticator config: {}, realm: {}",
        &config_model.config_id,
        realm_id.as_str()
    );
    AuthenticationModelApi::update_authenticator_config(&session, config_model).await
}

#[get("/realm/{realm_id}/auth/config/{config_id}")]
pub async fn load_authenticator_config_by_id(
    params: web::Path<(String, String)>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, config_id) = params.into_inner();
    log::info!(
        "Loading authenticator config: {}, realm: {}",
        config_id.as_str(),
        realm_id.as_str()
    );
    AuthenticationModelApi::load_authenticator_config(&session, &realm_id, &config_id).await
}

#[get("/realm/{realm_id}/auth/configs/load_all")]
pub async fn load_authenticator_configs_by_realm(
    realm_id: web::Path<String>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    log::info!("Loading authenticator configs realm: {}", realm_id.as_str());

    AuthenticationModelApi::load_authenticator_config_by_realm_id(&session, &realm_id).await
}

#[delete("/realm/{realm_id}/auth/config/{flow_id}")]
pub async fn remove_authenticator_config_by_id(
    params: web::Path<(String, String)>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, config_id) = params.into_inner();
    log::info!(
        "Deleting authenticator config: {}, realm: {}",
        config_id.as_str(),
        realm_id.as_str()
    );
    AuthenticationModelApi::remove_authenticator_config(&session, &realm_id, &config_id).await
}

#[post("/realm/{realm_id}/required_actions/create")]
pub async fn register_required_action(
    realm_id: web::Path<String>,
    action: web::Json<RequiredActionMutationModel>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let mut action_model: RequiredActionModel = action.0.into();
    action_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating required action: {}, realm: {}",
        &action_model.name,
        &realm_id
    );
    AuthenticationModelApi::register_required_action(&session, action_model).await
}

#[put("/realm/{realm_id}/required_actions/{action_id}")]
pub async fn update_required_action(
    params: web::Path<(String, String)>,
    action: web::Json<RequiredActionMutationModel>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let mut action_model: RequiredActionModel = action.0.into();
    let (realm_id, action_id) = params.into_inner();
    action_model.realm_id = realm_id.to_string();
    action_model.action_id = action_id.to_string();
    log::info!(
        "Updating required action: {}, realm: {}",
        &action_model.name,
        &realm_id
    );

    AuthenticationModelApi::update_required_action(&session, action_model).await
}

#[get("/realm/{realm_id}/actions/{action_id}")]
pub async fn load_required_action_by_id(
    params: web::Path<(String, String)>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, action_id) = params.into_inner();
    log::info!(
        "Loading role: {}, for realm: {}",
        &realm_id.as_str(),
        &realm_id
    );
    AuthenticationModelApi::load_required_action_by_id(&session, &realm_id, &action_id).await
}

#[delete("/realm/{realm_id}/actions/{action_id}")]
pub async fn remove_requied_action_by_id(
    params: web::Path<(String, String)>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, action_id) = params.into_inner();
    log::info!(
        "Deleting required action: {}, for realm: {}",
        &action_id.as_str(),
        &realm_id.as_str()
    );
    AuthenticationModelApi::remove_required_action(&session, &realm_id, &action_id).await
}

#[get("/realm/{realm_id}/actions/load_all")]
pub async fn load_requied_action_by_realm(
    realm_id: web::Path<String>,
    session: web::ReqData<DarkshieldSession>,
) -> impl Responder {
    log::info!("Loading required actions for realm: {}", &realm_id.as_str());
    AuthenticationModelApi::load_required_action_by_realm_id(&session, &realm_id).await
}
