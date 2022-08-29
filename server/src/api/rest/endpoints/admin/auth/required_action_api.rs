use log;
use crate::context::context::DarkShieldContext;
use models::entities::auth::{RequiredActionCreateModel, RequiredActionModel, RequiredActionUpdateModel};
use services::services::auth_services::IRequiredActionService;
use shaku::HasComponent;

use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

#[post("/admin/realms/{realm_id}/required_actions/create")]
pub async fn register_required_action(
    realm_id: web::Path<String>,
    action: web::Json<RequiredActionCreateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();
    let mut action_model: RequiredActionModel = action.0.into();
    action_model.realm_id = realm_id.to_string();
    log::info!("Creating required action: {}, realm: {}", &action_model.name, &realm_id);
    required_action_service.register_required_action(action_model).await
}


#[put("/admin/realms/{realm_id}/required_actions/update")]
pub async fn update_required_action(
    realm_id: web::Path<String>,
    action: web::Json<RequiredActionUpdateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();
    let mut action_model: RequiredActionModel = action.0.into();
    action_model.realm_id = realm_id.to_string();
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
