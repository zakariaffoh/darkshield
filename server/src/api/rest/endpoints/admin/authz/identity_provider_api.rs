use log;
use crate::context::context::DarkShieldContext;
use models::entities::authz::{IdentityProviderModel, IdentityProviderMutationModel};
use services::services::authz_services::{IIdentityProviderService};
use shaku::HasComponent;

use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

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