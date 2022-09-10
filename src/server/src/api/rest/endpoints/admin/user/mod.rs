use crate::context::DarkShieldContext;
use log;
use models::entities::{
    credentials::CredentialRepresentation,
    user::{UserCreateModel, UserModel},
};
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

#[put("/realm/{realm_id}/user/{user_id}/credential/disabled-credential-type")]
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

#[post("/realm/{realm_id}/user/{user_id}/impersonate")]
pub async fn impersonate_user(
    params: web::Path<(String, String)>,
    client_id: web::Query<String>,
    scope: web::Query<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();
    log::info!(
        "Impersonating user: {} for client_id: {}, scope: {} for realm: {}",
        user_id.as_str(),
        client_id.as_str(),
        scope.as_str(),
        realm_id.as_str(),
    );
    user_service
        .impersonate_user(
            realm_id.as_str(),
            user_id.as_str(),
            client_id.as_str(),
            scope.as_str(),
        )
        .await
}

#[post("/realm/{realm_id}/user/{user_id}/reset-password")]
pub async fn user_reset_password(
    params: web::Path<(String, String)>,
    password: web::Json<CredentialRepresentation>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();
    log::info!(
        "Reset user: {}, realm: {} password",
        user_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .reset_user_password(realm_id.as_str(), user_id.as_str(), &password.0)
        .await
}

#[put("/realm/{realm_id}/user/{user_id}/credential/{credential_id}/remove-credential")]
pub async fn remove_credential(
    params: web::Path<(String, String, String)>,
    client_id: web::Query<String>,
    previous_credential_id: web::Query<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id, credential_id) = params.into_inner();
    log::info!(
        "Move user: {} credential: {} for client_id: {}, scope: {}, realm: {}",
        user_id.as_str(),
        credential_id.as_str(),
        client_id.as_str(),
        previous_credential_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .move_credential_to_position(
            realm_id.as_str(),
            user_id.as_str(),
            credential_id.as_str(),
            previous_credential_id.as_str(),
        )
        .await
}

#[put("/realm/{realm_id}/user/{user_id}/credential/{credential_id}/move-to-first")]
pub async fn move_credential_to_first(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id, credential_id) = params.into_inner();
    log::info!(
        "Move user: {} credential: {}, realm: {} to first position",
        user_id.as_str(),
        credential_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .move_credential_to_first(realm_id.as_str(), user_id.as_str(), credential_id.as_str())
        .await
}

#[put("/realm/{realm_id}/user/{user_id}/credential/{credential_id}/move-to-position")]
pub async fn move_credential_to_position(
    params: web::Path<(String, String, String)>,
    previous_credential_id: web::Query<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id, credential_id) = params.into_inner();
    log::info!(
        "Move user: {} credential: {} for after credential {} realm: {}",
        user_id.as_str(),
        credential_id.as_str(),
        previous_credential_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .move_credential_to_position(
            realm_id.as_str(),
            user_id.as_str(),
            credential_id.as_str(),
            previous_credential_id.as_str(),
        )
        .await
}

#[post("/realm/{realm_id}/user/{user_id}/credential/reset-password-email")]
pub async fn reset_password_email(
    params: web::Path<(String, String)>,
    client_id: web::Query<String>,
    redirect_uri: web::Query<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();
    log::info!(
        "Sending reset password email to user: {}, client_id: {} and realm_id: {}",
        user_id.as_str(),
        client_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .send_reset_password_email(
            realm_id.as_str(),
            user_id.as_str(),
            client_id.as_str(),
            redirect_uri.as_str(),
        )
        .await
}

#[post("/realm/{realm_id}/user/{user_id}/credential/send-verify-email")]
pub async fn send_verify_email(
    params: web::Path<(String, String)>,
    client_id: web::Query<String>,
    redirect_uri: web::Query<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let user_service: &dyn IUserService = context.services().resolve_ref();
    let (realm_id, user_id) = params.into_inner();
    log::info!(
        "Sending verify email to user: {}, client_id: {} and realm_id: {}",
        user_id.as_str(),
        client_id.as_str(),
        realm_id.as_str(),
    );
    user_service
        .send_verify_email(
            realm_id.as_str(),
            user_id.as_str(),
            client_id.as_str(),
            redirect_uri.as_str(),
        )
        .await
}
