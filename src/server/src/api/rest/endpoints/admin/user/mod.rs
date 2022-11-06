use crate::api::services::user_api::UserApi;
use log;
use models::{
    entities::{
        credentials::CredentialRepresentation,
        user::{UserCreateModel, UserModel, UserUpdateModel},
    },
    PagingParams,
};
use services::session::session::DarkshieldSession;

use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

#[post("/realm/{realm_id}/user/{user_id}")]
pub async fn create_user(
    params: web::Path<(String, String)>,
    user: web::Json<UserCreateModel>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();
    log::info!("Creating user {}, realm: {}", &user_id, &realm_id);
    UserApi::create_user(&session, &realm_id, &user_id, user.0).await
}

#[put("/realm/{realm_id}/user/{user_id}")]
pub async fn update_user(
    params: web::Path<(String, String)>,
    user: web::Json<UserUpdateModel>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();
    let mut user_model: UserModel = user.0.into();
    log::info!("Updating user {}, realm: {}", &user_id, &realm_id);
    user_model.user_id = user_id;
    user_model.realm_id = realm_id;
    UserApi::udpate_user(&session, user_model).await
}

#[delete("/realm/{realm_id}/user/{user_id}")]
pub async fn delete_user(
    params: web::Path<(String, String)>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();
    log::info!("Deleting user {}, realm: {}", &user_id, &realm_id,);
    UserApi::delete_user(&session, &realm_id, &user_id).await
}

#[get("/realm/{realm_id}/user/{user_id}/load")]
pub async fn load_user(
    params: web::Path<(String, String)>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();
    log::info!("Loading user {}, realm: {}", &user_id, &realm_id);
    UserApi::load_user(&session, &realm_id, &user_id).await
}

#[get("/realm/{realm_id}/users/load_all")]
pub async fn load_users_paging(
    params: web::Path<String>,
    paging: web::Query<PagingParams>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let realm_id = params.into_inner();
    log::info!("Loading users, realm: {}", &realm_id);
    UserApi::load_users_by_realm_paging(&session, &realm_id, &paging.0).await
}

#[get("/realm/{realm_id}/user/{user_id}/count")]
pub async fn count_users(
    realm_id: web::Path<String>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    log::info!("Counting users realm: {}", &realm_id);
    UserApi::count_users(&session, &realm_id).await
}

#[put("/realm/{realm_id}/user/{user_id}/role/{role_id}")]
pub async fn user_add_role(
    params: web::Path<(String, String, String)>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id, role_id) = params.into_inner();

    log::info!(
        "Adding role: {} to user: {}, realm: {}",
        &role_id,
        &user_id,
        &realm_id,
    );
    UserApi::add_user_role(&session, &realm_id, &user_id, &role_id).await
}

#[delete("/realm/{realm_id}/user/{user_id}/role/{role_id}")]
pub async fn user_remove_role(
    params: web::Path<(String, String, String)>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id, role_id) = params.into_inner();

    log::info!(
        "Removing role: {} to user: {}, realm: {}",
        &role_id,
        &user_id,
        &realm_id,
    );
    UserApi::remove_user_role(&session, &realm_id, &user_id, &role_id).await
}

#[get("/realm/{realm_id}/user/{user_id}/roles/load_all")]
pub async fn load_user_roles_paging(
    params: web::Path<(String, String)>,
    paging: web::Query<PagingParams>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();

    log::info!("Loading roles for user: {}, realm: {}", &user_id, &realm_id);
    UserApi::load_user_roles(&session, &realm_id, &user_id, &paging.0).await
}

#[put("/realm/{realm_id}/user/{user_id}/group/{group_id}")]
pub async fn user_add_group(
    params: web::Path<(String, String, String)>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id, group_id) = params.into_inner();

    log::info!(
        "Adding group: {} to user: {}, realm: {}",
        &group_id,
        &user_id,
        &realm_id,
    );
    UserApi::add_user_group(&session, &realm_id, &user_id, &group_id).await
}

#[delete("/realm/{realm_id}/user/{user_id}/group/{group_id}")]
pub async fn user_remove_group(
    params: web::Path<(String, String, String)>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id, group_id) = params.into_inner();

    log::info!(
        "Removing group: {} from user: {}, realm: {}",
        &group_id,
        &user_id,
        &realm_id,
    );
    UserApi::remove_user_group(&session, &realm_id, &user_id, &group_id).await
}

#[get("/realm/{realm_id}/user/{user_id}/groups/load_paging")]
pub async fn load_user_groups_paging(
    params: web::Path<(String, String)>,
    paging: web::Query<PagingParams>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();

    log::info!(
        "Loading groups for user: {}, realm: {}",
        &user_id,
        &realm_id,
    );
    UserApi::load_user_groups_paging(&session, &realm_id, &user_id, &paging.0).await
}

#[get("/realm/{realm_id}/user/{user_id}/groups/count")]
pub async fn user_count_groups(
    params: web::Path<(String, String)>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();

    log::info!(
        "Counting user: {} groups for realm: {}",
        &user_id,
        &realm_id
    );
    UserApi::user_count_groups(&session, &realm_id, &user_id).await
}

#[get("/realm/{realm_id}/user/{user_id}/credentials/load_all")]
pub async fn load_user_credentials(
    params: web::Path<(String, String)>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();

    log::info!(
        "Loading user: {} credentials for realm: {}",
        &user_id,
        &realm_id,
    );
    UserApi::load_user_credentials(&session, &realm_id, &user_id).await
}

#[put("/realm/{realm_id}/user/{user_id}/credential/disabled-credential-type")]
pub async fn user_disable_credential_type(
    params: web::Path<(String, String)>,
    credential_type: web::Query<String>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();
    let credential_type = credential_type.into_inner();
    log::info!(
        "Disabling user: {} credential_type: {} for realm: {}",
        &user_id,
        &credential_type,
        &realm_id,
    );
    UserApi::user_disable_credential_type(&session, &realm_id, &user_id, &credential_type).await
}

#[post("/realm/{realm_id}/user/{user_id}/reset-password")]
pub async fn user_reset_password(
    params: web::Path<(String, String)>,
    password: web::Json<CredentialRepresentation>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();
    let credential = password.0;
    log::info!("Reset user: {}, realm: {} password", user_id, realm_id,);
    UserApi::reset_user_password(&session, &realm_id, &user_id, &credential).await
}

#[put("/realm/{realm_id}/user/{user_id}/credential/{credential_id}/remove-credential")]
pub async fn remove_credential(
    params: web::Path<(String, String, String)>,
    client_id: web::Query<String>,
    previous_credential_id: web::Query<String>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id, credential_id) = params.into_inner();
    let previous_credential_id = previous_credential_id.into_inner();
    log::info!(
        "Move user: {} credential: {} for client_id: {}, scope: {}, realm: {}",
        &user_id,
        &credential_id,
        &client_id,
        &previous_credential_id,
        &realm_id,
    );
    UserApi::move_credential_to_position(
        &session,
        &realm_id,
        &user_id,
        &credential_id,
        &previous_credential_id,
    )
    .await
}

#[put("/realm/{realm_id}/user/{user_id}/credential/{credential_id}/move-to-first")]
pub async fn move_credential_to_first(
    params: web::Path<(String, String, String)>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id, credential_id) = params.into_inner();
    log::info!(
        "Move user: {} credential: {}, realm: {} to first position",
        &user_id,
        &credential_id,
        &realm_id,
    );
    UserApi::move_credential_to_first(&session, &realm_id, &user_id, &credential_id).await
}

#[put("/realm/{realm_id}/user/{user_id}/credential/{credential_id}/move-to-position")]
pub async fn move_credential_to_position(
    params: web::Path<(String, String, String)>,
    previous_credential_id: web::Query<String>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id, credential_id) = params.into_inner();
    let previous_credential_id = previous_credential_id.into_inner();
    log::info!(
        "Move user: {} credential: {} for after credential {} realm: {}",
        &user_id,
        &credential_id,
        previous_credential_id,
        &realm_id,
    );
    UserApi::move_credential_to_position(
        &session,
        &realm_id,
        &user_id,
        &credential_id,
        &previous_credential_id,
    )
    .await
}

#[post("/realm/{realm_id}/user/{user_id}/credential/reset-password-email")]
pub async fn reset_password_email(
    params: web::Path<(String, String)>,
    client_id: web::Query<String>,
    redirect_uri: web::Query<String>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();
    log::info!(
        "Sending reset password email to user: {}, client_id: {} and realm_id: {}",
        &user_id,
        &client_id,
        &realm_id,
    );
    UserApi::send_reset_password_email(&session, &realm_id, &user_id, &client_id, &redirect_uri)
        .await
}

#[post("/realm/{realm_id}/user/{user_id}/credential/send-verify-email")]
pub async fn send_verify_email(
    params: web::Path<(String, String)>,
    query: web::Query<(String, String)>,
    redirect_uri: web::Query<String>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();
    let (client_id, redirect_uri) = query.into_inner();
    log::info!(
        "Sending verify email to user: {}, client_id: {} and realm_id: {}",
        &user_id,
        &client_id,
        &realm_id,
    );
    UserApi::send_verify_email(&session, &realm_id, &user_id, &client_id, &redirect_uri).await
}

#[get("/realm/{realm_id}/user/{user_id}/consents/load")]
pub async fn load_user_consents(
    params: web::Path<(String, String)>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();

    log::info!(
        "Loading user: {} consents for realm: {}",
        &user_id,
        &realm_id,
    );
    UserApi::load_user_consents(&session, &realm_id, &user_id).await
}

#[delete("/realm/{realm_id}/user/{user_id}/consent/client/{client_id}")]
pub async fn revoke_user_consent_for_client(
    params: web::Path<(String, String, String)>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id, client_id) = params.into_inner();
    log::info!(
        "Loading user: {} consents for realm: {}",
        &user_id,
        &realm_id,
    );
    UserApi::revoke_user_consent_for_client(&session, &realm_id, &user_id, &client_id).await
}

#[post("/realm/{realm_id}/user/{user_id}/impersonate")]
pub async fn impersonate_user(
    params: web::Path<(String, String)>,
    client_id: web::Query<String>,
    scope: web::Query<String>,
    session: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, user_id) = params.into_inner();
    log::info!(
        "Impersonating user: {} for client_id: {}, scope: {} for realm: {}",
        &user_id,
        &client_id,
        &scope,
        &realm_id,
    );
    UserApi::impersonate_user(&session, &realm_id, &user_id, &client_id, &scope).await
}
