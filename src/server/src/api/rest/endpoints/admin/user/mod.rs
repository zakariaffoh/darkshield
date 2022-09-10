use crate::context::DarkShieldContext;
use log;
use models::entities::user::{UserCreateModel, UserModel, UserUpdateModel};
use services::services::user_service::IUserService;
use shaku::HasComponent;

use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

#[post("/realm/{realm_id}/user/{user_id}")]
pub async fn create_user(
    params: web::Path<(String, String)>,
    user: web::Json<UserCreateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();
    let mut user_model: UserModel = user.0.into();
    log::info!(
        "Creating user {}, realm: {}",
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_model.user_id = user_id;
    user_model.realm_id = realm_id;
    user_service.create_user(user_model).await
}

#[put("/realm/{realm_id}/user/{user_id}")]
pub async fn update_user(
    params: web::Path<(String, String)>,
    user: web::Json<UserCreateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();
    let mut user_model: UserModel = user.0.into();
    log::info!(
        "Updating user {}, realm: {}",
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_model.user_id = user_id;
    user_model.realm_id = realm_id;
    user_service.udpate_user(user_model).await
}

#[delete("/realm/{realm_id}/user/{user_id}")]
pub async fn delete_user(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();
    log::info!(
        "Deleting user {}, realm: {}",
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .delete_user(realm_id.as_str(), user_id.as_str())
        .await
}

#[get("/realm/{realm_id}/user/{user_id}/load")]
pub async fn load_user(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();
    log::info!(
        "Loading user {}, realm: {}",
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .load_user(realm_id.as_str(), user_id.as_str())
        .await
}

#[get("/realm/{realm_id}/user/{user_id}/count")]
pub async fn count_users(
    realm_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    log::info!("Counting users realm: {}", realm_id.as_str(),);
    user_service.count_users(realm_id.as_str()).await
}

#[put("/realm/{realm_id}/user/{user_id}/role/{role_id}")]
pub async fn user_add_role(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id, role_id) = params.into_inner();

    log::info!(
        "Adding role: {} to user: {}, realm: {}",
        role_id.as_str(),
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .add_user_role(realm_id.as_str(), user_id.as_str(), role_id.as_str())
        .await
}

#[delete("/realm/{realm_id}/user/{user_id}/role/{role_id}")]
pub async fn user_remove_role(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id, role_id) = params.into_inner();

    log::info!(
        "Removing role: {} to user: {}, realm: {}",
        role_id.as_str(),
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .remove_user_role(realm_id.as_str(), user_id.as_str(), role_id.as_str())
        .await
}

#[get("/realm/{realm_id}/user/{user_id}/roles/load_all")]
pub async fn load_user_roles(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();

    log::info!(
        "Loading roles for user: {}, realm: {}",
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .load_user_roles(realm_id.as_str(), user_id.as_str())
        .await
}

#[put("/realm/{realm_id}/user/{user_id}/group/{group_id}")]
pub async fn user_add_group(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id, group_id) = params.into_inner();

    log::info!(
        "Adding group: {} to user: {}, realm: {}",
        group_id.as_str(),
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .add_user_group(realm_id.as_str(), user_id.as_str(), group_id.as_str())
        .await
}

#[delete("/realm/{realm_id}/user/{user_id}/group/{group_id}")]
pub async fn user_remove_group(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id, group_id) = params.into_inner();

    log::info!(
        "Removing group: {} from user: {}, realm: {}",
        group_id.as_str(),
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .remove_user_group(realm_id.as_str(), user_id.as_str(), group_id.as_str())
        .await
}

#[get("/realm/{realm_id}/user/{user_id}/groups/load_all")]
pub async fn load_user_groups(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();

    log::info!(
        "Loading groups for user: {}, realm: {}",
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .load_user_groups(realm_id.as_str(), user_id.as_str())
        .await
}

#[get("/realm/{realm_id}/user/{user_id}/groups/load_paging")]
pub async fn load_user_groups_paging(
    params: web::Path<(String, String)>,
    page_index: web::Query<i64>,
    page_size: web::Query<i64>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();

    log::info!(
        "Loading groups for user: {}, realm: {} with paging (page_index: {}, page_size: {})",
        user_id.as_str(),
        realm_id.as_str(),
        page_index.to_owned(),
        page_size.to_owned(),
    );
    user_service
        .load_user_groups_paging(
            realm_id.as_str(),
            user_id.as_str(),
            page_index.0,
            page_size.0,
        )
        .await
}

#[get("/realm/{realm_id}/user/{user_id}/groups/count")]
pub async fn user_count_groups(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();

    log::info!(
        "Counting user: {} groups for realm: {}",
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .user_count_groups(realm_id.as_str(), user_id.as_str())
        .await
}

#[get("/realm/{realm_id}/user/{user_id}/consents/load")]
pub async fn load_user_consents(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();

    log::info!(
        "Loading user: {} consents for realm: {}",
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .load_user_consents(realm_id.as_str(), user_id.as_str())
        .await
}

#[delete("/realm/{realm_id}/user/{user_id}/consent/client/{client_id}")]
pub async fn revoke_user_consent_for_client(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id, client_id) = params.into_inner();

    log::info!(
        "Loading user: {} consents for realm: {}",
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .revoke_user_consent_for_client(realm_id.as_str(), user_id.as_str(), client_id.as_str())
        .await
}

#[get("/realm/{realm_id}/user/{user_id}/credentials/load_all")]
pub async fn load_user_credentials(
    params: web::Path<(String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();

    log::info!(
        "Loading user: {} credentials for realm: {}",
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .load_user_credentials(realm_id.as_str(), user_id.as_str())
        .await
}

#[put("/realm/{realm_id}/user/{user_id}/credential/disable")]
pub async fn user_disable_credential_type(
    params: web::Path<(String, String)>,
    credential_type: web::Query<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();

    log::info!(
        "Disabling user: {} credential_type: {} for realm: {}",
        user_id.as_str(),
        credential_type.as_str(),
        realm_id.as_str(),
    );
    user_service
        .user_disable_credential_type(
            realm_id.as_str(),
            user_id.as_str(),
            credential_type.as_str(),
        )
        .await
}
