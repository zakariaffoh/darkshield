use crate::context::DarkShieldContext;
use commons::ApiResult;
use models::entities::{
    authz::{GroupModel, GroupPagingResult, RoleModel},
    credentials::CredentialRepresentation,
    user::UserModel,
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
        todo!()
    }
    pub async fn load_users_by_realm_id(
        context: &DarkShieldContext,
        realm_id: &str,
    ) -> ApiResult<Vec<UserModel>> {
        todo!()
    }
    pub async fn count_users(context: &DarkShieldContext, realm_id: &str) -> ApiResult<i64> {
        todo!()
    }
    pub async fn add_user_role(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }
    pub async fn remove_user_role(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }
    pub async fn load_user_roles(
        context: &DarkShieldContext,
        realm_id: &str,
        role_id: &str,
    ) -> ApiResult<Vec<RoleModel>> {
        todo!()
    }

    pub async fn add_user_group(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }
    pub async fn remove_user_group(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    pub async fn load_user_groups(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
    ) -> ApiResult<Vec<GroupModel>> {
        todo!()
    }
    pub async fn user_count_groups(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
    ) -> ApiResult<i64> {
        todo!()
    }
    pub async fn load_user_groups_paging(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        page_size: i32,
        page_index: i32,
    ) -> ApiResult<GroupPagingResult> {
        todo!()
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
