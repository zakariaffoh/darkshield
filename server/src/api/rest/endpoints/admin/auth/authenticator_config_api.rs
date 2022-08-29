use log;
use crate::context::context::DarkShieldContext;
use models::entities::auth::{AuthenticatorConfigModel,AuthenticatorConfigMutationModel};
use services::services::auth_services::IAuthenticatorConfigService;
use shaku::HasComponent;

use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

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
