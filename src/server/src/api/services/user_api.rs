use crate::context::DarkShieldContext;
use commons::ApiResult;
use models::entities::{
    authz::{GroupModel, GroupPagingResult, RoleModel},
    credentials::CredentialRepresentation,
    user::UserModel,
};
use services::services::{
    authz_services::{IGroupService, IRoleService},
    client_services::IClientService,
    user_services::IUserService,
};
use shaku::HasComponent;

pub struct UserApi;

impl UserApi {
    pub async fn create_user(
        context: &DarkShieldContext,
        realm: UserModel,
    ) -> ApiResult<UserModel> {
        todo!()
    }

    pub async fn udpate_user(context: &DarkShieldContext, realm: UserModel) -> ApiResult<()> {
        todo!()
    }

    pub async fn delete_user(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    pub async fn load_user(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
    ) -> ApiResult<UserModel> {
        let user_service: &dyn IUserService = context.services().resolve_ref();
        let loaded_user = user_service.load_user(&realm_id, user_id).await;
        match loaded_user {
            Ok(user) => ApiResult::<UserModel>::from_option(user),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_users_by_realm_id(
        context: &DarkShieldContext,
        realm_id: &str,
    ) -> ApiResult<Vec<UserModel>> {
        let user_service: &dyn IUserService = context.services().resolve_ref();

        let loaded_users = user_service.load_users_by_realm_id(&realm_id).await;
        match loaded_users {
            Ok(users) => {
                log::info!("[{}] users loaded for realm: {}", users.len(), realm_id);
                if users.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(users)
                }
            }
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn count_users(context: &DarkShieldContext, realm_id: &str) -> ApiResult<i64> {
        let user_service: &dyn IUserService = context.services().resolve_ref();
        let response = user_service.count_users(&realm_id).await;
        match response {
            Ok(count) => ApiResult::from_data(count),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn add_user_role(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let user_service: &dyn IUserService = context.services().resolve_ref();
        let role_service: &dyn IRoleService = context.services().resolve_ref();

        let user_exists = user_service.user_exists_by_id(&realm_id, &user_id).await;
        if let Ok(response) = user_exists {
            if !response {
                log::error!("user: {} not found in realm: {}", &user_id, &realm_id);
                return ApiResult::from_error(409, "404", "user not found");
            }
        }

        let existing_role = role_service.role_exists_by_id(&realm_id, &role_id).await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = user_service
            .add_user_role(&realm_id, &user_id, &role_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add client role mapping"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn remove_user_role(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let user_service: &dyn IUserService = context.services().resolve_ref();
        let role_service: &dyn IRoleService = context.services().resolve_ref();

        let user_exists = user_service.user_exists_by_id(&realm_id, &user_id).await;
        if let Ok(response) = user_exists {
            if !response {
                log::error!("user: {} not found in realm: {}", &user_id, &realm_id);
                return ApiResult::from_error(409, "404", "user not found");
            }
        }

        let existing_role = role_service.role_exists_by_id(&realm_id, &role_id).await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = user_service
            .remove_user_role(&realm_id, &user_id, &role_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add client role mapping"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn load_user_roles(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
    ) -> ApiResult<Vec<RoleModel>> {
        let role_service: &dyn IRoleService = context.services().resolve_ref();
        let loaded_roles = role_service.load_user_roles(&realm_id, &user_id).await;
        match loaded_roles {
            Ok(roles) => {
                log::info!(
                    "[{}] loaded for roles: {} realm: {}",
                    roles.len(),
                    &user_id,
                    &realm_id
                );
                if roles.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(roles)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load roles for user: {} realm: {}",
                    &user_id,
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn add_user_group(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> ApiResult<()> {
        let user_service: &dyn IUserService = context.services().resolve_ref();
        let group_service: &dyn IGroupService = context.services().resolve_ref();

        let user_exists = user_service.user_exists_by_id(&realm_id, &user_id).await;
        if let Ok(response) = user_exists {
            if !response {
                log::error!("user: {} not found in realm: {}", &user_id, &realm_id);
                return ApiResult::from_error(409, "404", "user not found");
            }
        }

        let existing_group = group_service
            .exists_groups_by_id(&realm_id, &group_id)
            .await;
        if let Ok(res) = existing_group {
            if !res {
                log::error!("group: {} not found in realm: {}", &group_id, &realm_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = user_service
            .add_user_group_mapping(&realm_id, &user_id, &group_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add user group mapping"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn remove_user_group(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> ApiResult<()> {
        let user_service: &dyn IUserService = context.services().resolve_ref();
        let group_service: &dyn IGroupService = context.services().resolve_ref();

        let user_exists = user_service.user_exists_by_id(&realm_id, &user_id).await;
        if let Ok(response) = user_exists {
            if !response {
                log::error!("user: {} not found in realm: {}", &user_id, &realm_id);
                return ApiResult::from_error(409, "404", "user not found");
            }
        }

        let existing_group = group_service
            .exists_groups_by_id(&realm_id, &group_id)
            .await;
        if let Ok(res) = existing_group {
            if !res {
                log::error!("group: {} not found in realm: {}", &group_id, &realm_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = user_service
            .remove_user_group_mapping(&realm_id, &user_id, &group_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add user group mapping"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn load_user_groups(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
    ) -> ApiResult<Vec<GroupModel>> {
        let group_service: &dyn IGroupService = context.services().resolve_ref();

        let loaded_groups = group_service.load_user_groups(&realm_id, &user_id).await;
        match loaded_groups {
            Ok(groups) => {
                log::info!(
                    "[{}] groups: loaded for user {} realm: {}",
                    groups.len(),
                    &user_id,
                    &realm_id
                );
                if groups.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(groups)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load groups for user: {} realm: {}",
                    &user_id,
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn user_count_groups(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
    ) -> ApiResult<i64> {
        let group_service: &dyn IGroupService = context.services().resolve_ref();
        let response = group_service.count_user_groups(&realm_id, &user_id).await;
        match response {
            Ok(count) => ApiResult::from_data(count),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_user_groups_paging(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        page_size: i32,
        page_index: i32,
    ) -> ApiResult<GroupPagingResult> {
        let group_service: &dyn IGroupService = context.services().resolve_ref();

        let loaded_groups = group_service
            .load_user_groups_paging(&realm_id, &user_id, page_index, page_size)
            .await;
        match loaded_groups {
            Ok(groups_paging) => {
                log::info!(
                    "[{}] groups: loaded for user {} realm: {}",
                    groups_paging.groups.len(),
                    &user_id,
                    &realm_id
                );
                if groups_paging.groups.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(groups_paging)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load groups for user: {} realm: {}",
                    &user_id,
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn send_reset_password_email(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    pub async fn send_verify_email(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    pub async fn user_disable_credential_type(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    pub async fn load_user_credentials(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    pub async fn load_user_consents(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    pub async fn revoke_user_consent_for_client(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    pub async fn impersonate_user(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
        scope: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    pub async fn move_credential_to_position(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
        previous_credential_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    pub async fn move_credential_to_first(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    pub async fn reset_user_password(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        password: &CredentialRepresentation,
    ) -> ApiResult<()> {
        todo!()
    }

    pub async fn disable_credential_type(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> ApiResult<()> {
        todo!()
    }
}
