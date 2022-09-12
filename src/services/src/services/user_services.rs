use async_trait::async_trait;
use commons::ApiResult;
use models::entities::authz::GroupModel;
use models::entities::authz::RoleModel;
use models::entities::credentials::CredentialRepresentation;
use models::entities::user::UserModel;
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
    async fn create_user(&self, realm: UserModel) -> ApiResult<UserModel>;
    async fn udpate_user(&self, realm: UserModel) -> ApiResult<()>;
    async fn delete_user(&self, realm_id: &str, user_id: &str) -> ApiResult<()>;
    async fn load_user(&self, realm_id: &str, user_id: &str) -> ApiResult<UserModel>;
    async fn load_users_by_realm_id(&self, realm_id: &str) -> ApiResult<Vec<UserModel>>;
    async fn count_users(&self, realm_id: &str) -> ApiResult<i64>;
    async fn add_user_role(&self, realm_id: &str, user_id: &str, role_id: &str) -> ApiResult<()>;
    async fn remove_user_role(&self, realm_id: &str, user_id: &str, role_id: &str)
        -> ApiResult<()>;
    async fn load_user_roles(&self, realm_id: &str, role_id: &str) -> ApiResult<Vec<RoleModel>>;

    async fn add_user_group(&self, realm_id: &str, user_id: &str, group_id: &str) -> ApiResult<()>;
    async fn remove_user_group(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> ApiResult<()>;

    async fn load_user_groups(&self, realm_id: &str, user_id: &str) -> ApiResult<Vec<GroupModel>>;
    async fn user_count_groups(&self, realm_id: &str, user_id: &str) -> ApiResult<i64>;
    async fn load_user_groups_paging(
        &self,
        realm_id: &str,
        user_id: &str,
        page_index: i64,
        page_size: i64,
    ) -> ApiResult<Vec<GroupModel>>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IUserService)]
pub struct UserService {
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
impl IUserService for UserService {
    async fn create_user(&self, realm: UserModel) -> ApiResult<UserModel> {
        todo!()
    }
    async fn udpate_user(&self, realm: UserModel) -> ApiResult<()> {
        todo!()
    }
    async fn delete_user(&self, realm_id: &str, user_id: &str) -> ApiResult<()> {
        todo!()
    }
    async fn load_user(&self, realm_id: &str, user_id: &str) -> ApiResult<UserModel> {
        todo!()
    }
    async fn load_users_by_realm_id(&self, realm_id: &str) -> ApiResult<Vec<UserModel>> {
        todo!()
    }
    async fn count_users(&self, realm_id: &str) -> ApiResult<i64> {
        todo!()
    }
    async fn add_user_role(&self, realm_id: &str, user_id: &str, role_id: &str) -> ApiResult<()> {
        todo!()
    }
    async fn remove_user_role(
        &self,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }
    async fn load_user_roles(&self, realm_id: &str, role_id: &str) -> ApiResult<Vec<RoleModel>> {
        todo!()
    }

    async fn add_user_group(&self, realm_id: &str, user_id: &str, group_id: &str) -> ApiResult<()> {
        todo!()
    }
    async fn remove_user_group(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn load_user_groups(&self, realm_id: &str, user_id: &str) -> ApiResult<Vec<GroupModel>> {
        todo!()
    }
    async fn user_count_groups(&self, realm_id: &str, user_id: &str) -> ApiResult<i64> {
        todo!()
    }
    async fn load_user_groups_paging(
        &self,
        realm_id: &str,
        user_id: &str,
        page_index: i64,
        page_size: i64,
    ) -> ApiResult<Vec<GroupModel>> {
        todo!()
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
pub struct UserActionService {}

#[async_trait]
impl IUserActionService for UserActionService {
    async fn send_reset_password_email(
        &self,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn send_verify_email(
        &self,
        realm_id: &str,
        user_id: &str,
        client_id: &str,
        redirect_uri: &str,
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
pub struct UserConsentService {}

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
pub trait IUserCredentialService: Interface {
    async fn user_disable_credential_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> ApiResult<()>;

    async fn load_user_credentials(&self, realm_id: &str, user_id: &str) -> ApiResult<()>;

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
#[shaku(interface = IUserCredentialService)]
pub struct UserCredentialService {}

#[async_trait]
impl IUserCredentialService for UserCredentialService {
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
pub struct UserImpersonationService {}

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
