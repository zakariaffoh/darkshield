use async_trait::async_trait;
use commons::ApiResult;
use models::entities::authz::GroupPagingResult;
use models::entities::authz::RolePagingResult;
use models::entities::credentials::CredentialRepresentation;
use models::entities::user::UserModel;
use models::entities::user::UserPagingResult;
use shaku::Component;
use shaku::Interface;
use std::sync::Arc;
use store::providers::interfaces::auth_providers::IRequiredActionProvider;
use store::providers::interfaces::authz_provider::IGroupProvider;
use store::providers::interfaces::realm_provider::IRealmProvider;
use store::providers::interfaces::user_provider::IUserProvider;

use store::providers::interfaces::authz_provider::IRoleProvider;

#[async_trait]
pub trait IUserService: Interface {
    async fn create_user(&self, user: &UserModel) -> Result<(), String>;

    async fn udpate_user(&self, user: &UserModel) -> Result<(), String>;

    async fn delete_user(&self, realm_id: &str, user_id: &str) -> Result<(), String>;

    async fn load_user_by_id(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<UserModel>, String>;

    async fn load_user_by_ids(
        &self,
        realm_id: &str,
        user_ids: &[&str],
    ) -> Result<Vec<UserModel>, String>;

    async fn load_users_paging(
        &self,
        realm_id: &str,
        page: &Option<u64>,
        size: &Option<u64>,
    ) -> Result<UserPagingResult, String>;

    async fn count_users(&self, realm_id: &str) -> Result<u64, String>;

    async fn user_exists_by_id(&self, realm_id: &str, user_id: &str) -> Result<bool, String>;

    async fn add_user_role_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<(), String>;
    async fn remove_user_role_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<(), String>;

    async fn load_user_roles_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        page_index: &Option<u64>,
        page_size: &Option<u64>,
    ) -> Result<RolePagingResult, String>;

    async fn add_user_group_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), String>;

    async fn load_user_groups_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        page_index: &Option<u64>,
        page_size: &Option<u64>,
    ) -> Result<GroupPagingResult, String>;

    async fn remove_user_group_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), String>;

    async fn user_count_groups(&self, realm_id: &str, user_id: &str) -> Result<u64, String>;

    async fn user_exists_by_user_name(
        &self,
        realm_id: &str,
        user_name: &str,
    ) -> Result<bool, String>;

    async fn user_exists_by_email(&self, realm_id: &str, email: &str) -> Result<bool, String>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IUserService)]
pub struct UserService {
    #[shaku(inject)]
    user_provider: Arc<dyn IUserProvider>,

    #[shaku(inject)]
    roles_provider: Arc<dyn IRoleProvider>,

    #[shaku(inject)]
    group_provider: Arc<dyn IGroupProvider>,
}

#[async_trait]
impl IUserService for UserService {
    async fn create_user(&self, user: &UserModel) -> Result<(), String> {
        self.user_provider.create_user(&user).await
    }

    async fn udpate_user(&self, user: &UserModel) -> Result<(), String> {
        self.user_provider.udpate_user(&user).await
    }

    async fn delete_user(&self, realm_id: &str, user_id: &str) -> Result<(), String> {
        self.user_provider.delete_user(&realm_id, &user_id).await
    }

    async fn load_user_by_id(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<UserModel>, String> {
        self.user_provider
            .load_user_by_id(&realm_id, &user_id)
            .await
    }

    async fn load_user_by_ids(
        &self,
        realm_id: &str,
        user_ids: &[&str],
    ) -> Result<Vec<UserModel>, String> {
        self.user_provider
            .load_user_by_ids(&realm_id, &user_ids)
            .await
    }

    async fn load_users_paging(
        &self,
        realm_id: &str,
        page_index: &Option<u64>,
        page_size: &Option<u64>,
    ) -> Result<UserPagingResult, String> {
        self.user_provider
            .load_users_paging(&realm_id, &page_index, &page_size)
            .await
    }

    async fn count_users(&self, realm_id: &str) -> Result<u64, String> {
        self.user_provider.count_users(&realm_id).await
    }

    async fn user_exists_by_id(&self, realm_id: &str, user_id: &str) -> Result<bool, String> {
        self.user_provider
            .user_exists_by_id(&realm_id, &user_id)
            .await
    }

    async fn add_user_role_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        self.user_provider
            .add_user_role_mapping(&realm_id, &user_id, &role_id)
            .await
    }

    async fn remove_user_role_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        self.user_provider
            .remove_user_role_mapping(&realm_id, &user_id, &role_id)
            .await
    }

    async fn load_user_roles_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        page_index: &Option<u64>,
        page_size: &Option<u64>,
    ) -> Result<RolePagingResult, String> {
        self.roles_provider
            .load_user_roles_paging(&realm_id, &user_id, &page_index, &page_size)
            .await
    }

    async fn add_user_group_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), String> {
        self.user_provider
            .add_user_group_mapping(&realm_id, &user_id, &group_id)
            .await
    }

    async fn remove_user_group_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), String> {
        self.user_provider
            .remove_user_group_mapping(&realm_id, &user_id, &group_id)
            .await
    }

    async fn load_user_groups_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        page_index: &Option<u64>,
        page_size: &Option<u64>,
    ) -> Result<GroupPagingResult, String> {
        self.group_provider
            .load_user_groups_paging(&realm_id, &user_id, &page_index, &page_size)
            .await
    }

    async fn user_count_groups(&self, realm_id: &str, user_id: &str) -> Result<u64, String> {
        self.group_provider
            .count_user_groups(&realm_id, &user_id)
            .await
    }

    async fn user_exists_by_user_name(
        &self,
        realm_id: &str,
        user_name: &str,
    ) -> Result<bool, String> {
        self.user_provider
            .user_exists_by_user_name(&realm_id, &user_name)
            .await
    }

    async fn user_exists_by_email(&self, realm_id: &str, email: &str) -> Result<bool, String> {
        self.user_provider
            .user_exists_by_email(&realm_id, &email)
            .await
    }
}

#[async_trait]
pub trait IUserActionService: Interface {
    async fn send_reset_password_email(
        &self,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> ApiResult<()>;

    async fn send_verify_email(
        &self,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> ApiResult<()>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IUserActionService)]
pub struct UserActionService {
    #[shaku(inject)]
    group_provider: Arc<dyn IGroupProvider>,

    #[shaku(inject)]
    role_provider: Arc<dyn IRoleProvider>,

    #[shaku(inject)]
    user_provider: Arc<dyn IUserProvider>,

    #[shaku(inject)]
    realm_provider: Arc<dyn IRealmProvider>,

    #[shaku(inject)]
    required_actions_provider: Arc<dyn IRequiredActionProvider>,
}

#[async_trait]
impl IUserActionService for UserActionService {
    async fn send_reset_password_email(
        &self,
        _realm_id: &str,
        _user_id: &str,
        _client_id: &str,
        _redirect_uri: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn send_verify_email(
        &self,
        _realm_id: &str,
        _user_id: &str,
        _client_id: &str,
        _redirect_uri: &str,
    ) -> ApiResult<()> {
        todo!()
    }
}

#[async_trait]
pub trait IUserConsentService: Interface {
    async fn user_disable_credential_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> ApiResult<()>;

    async fn load_user_credentials(&self, realm_id: &str, user_id: &str) -> ApiResult<()>;

    async fn load_user_consents(&self, realm_id: &str, user_id: &str) -> ApiResult<()>;

    async fn revoke_user_consent_for_client(
        &self,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
    ) -> ApiResult<()>;

    async fn impersonate_user(
        &self,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
        scope: &str,
    ) -> ApiResult<()>;

    async fn move_credential_to_position(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
        previous_credential_id: &str,
    ) -> ApiResult<()>;

    async fn move_credential_to_first(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
    ) -> ApiResult<()>;

    async fn reset_user_password(
        &self,
        realm_id: &str,
        user_id: &str,
        password: &CredentialRepresentation,
    ) -> ApiResult<()>;

    async fn disable_credential_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> ApiResult<()>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IUserConsentService)]
pub struct UserConsentService {
    #[shaku(inject)]
    group_provider: Arc<dyn IGroupProvider>,

    #[shaku(inject)]
    role_provider: Arc<dyn IRoleProvider>,

    #[shaku(inject)]
    user_provider: Arc<dyn IUserProvider>,

    #[shaku(inject)]
    realm_provider: Arc<dyn IRealmProvider>,

    #[shaku(inject)]
    required_actions_provider: Arc<dyn IRequiredActionProvider>,
}

#[async_trait]
impl IUserConsentService for UserConsentService {
    async fn user_disable_credential_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn load_user_credentials(&self, realm_id: &str, user_id: &str) -> ApiResult<()> {
        todo!()
    }

    async fn load_user_consents(&self, realm_id: &str, user_id: &str) -> ApiResult<()> {
        todo!()
    }

    async fn revoke_user_consent_for_client(
        &self,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn impersonate_user(
        &self,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
        scope: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn move_credential_to_position(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
        previous_credential_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn move_credential_to_first(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn reset_user_password(
        &self,
        realm_id: &str,
        user_id: &str,
        password: &CredentialRepresentation,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn disable_credential_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> ApiResult<()> {
        todo!()
    }
}

#[async_trait]
pub trait IUserImpersonationService: Interface {
    async fn impersonate_user(
        &self,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
        scope: &str,
    ) -> ApiResult<()>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IUserImpersonationService)]
pub struct UserImpersonationService {
    #[shaku(inject)]
    group_provider: Arc<dyn IGroupProvider>,

    #[shaku(inject)]
    role_provider: Arc<dyn IRoleProvider>,

    #[shaku(inject)]
    user_provider: Arc<dyn IUserProvider>,

    #[shaku(inject)]
    realm_provider: Arc<dyn IRealmProvider>,

    #[shaku(inject)]
    required_actions_provider: Arc<dyn IRequiredActionProvider>,
}

#[async_trait]
impl IUserImpersonationService for UserImpersonationService {
    async fn impersonate_user(
        &self,
        _realm_id: &str,
        _user_id: &str,
        _client_id: &str,
        _scope: &str,
    ) -> ApiResult<()> {
        todo!()
    }
}
