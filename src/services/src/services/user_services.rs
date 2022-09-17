use async_trait::async_trait;
use commons::ApiResult;
use models::entities::authz::GroupModel;
use models::entities::authz::GroupPagingResult;
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
        page_size: i32,
        page_index: i32,
    ) -> ApiResult<GroupPagingResult>;
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
        page_size: i32,
        page_index: i32,
    ) -> ApiResult<GroupPagingResult> {
        todo!()
    }
}

/*#[async_trait]
impl IUserService for UserService {
    async fn create_user(&self, realm: UserModel) -> ApiResult<UserModel> {
        let realm_model = self.realm_provider.load_realm(&user.realm_id).await;
        match realm_model {
            Ok(realm) => {
                if realm.is_none() {
                    log::error!("Realm: {} not found", &user.realm_id);
                    return ApiResult::from_error(404, "404", "Realm not found");
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load realm: {}. Error: {}",
                    &user.realm_id,
                    err.to_string()
                );
                return ApiResult::from_error(500, "500", "Failed to load realm");
            }
        }
        let realm = realm_model.unwrap().unwrap();
        if realm.registration_allowed.unwrap_or(false) {
            log::error!("User registration not allowed for realm {}", &user.realm_id,);
            return ApiResult::from_error(403, "403", "User registration not allowed");
        }
        let mut user_name = user.user_name.clone();
        if realm.register_email_as_username.unwrap_or(false) {
            user_name = user.email.clone();
        }
        if user_name.is_empty() {
            log::error!("User name is null or empty");
            return ApiResult::from_error(400, "400", "User name is null or empty");
        }
        if self
            .user_provider
            .user_exists_by_user_name(&user.realm_id, &user_name)
            .await
            .unwrap_or(false)
        {
            log::error!("User with user name: {} already exist", &user_name);
            return ApiResult::from_error(409, "409", "User allready exists in the realm");
        }

        if !user.email.is_empty() && realm.duplicated_email_allowed.unwrap_or_default() {
            if self
                .user_provider
                .user_exists_by_email(&user.realm_id, &user_name)
                .await
                .unwrap_or_default()
            {
                log::error!("User with user name: {} already exist", &user_name);
                return ApiResult::from_error(409, "409", "User allready exists in the realm");
            }
        }

        let mut required_actions_list = self
            .required_actions_provider
            .load_required_actions_by_realm(&user.realm_id)
            .await;
        let required_actions;
        match required_actions_list {
            Ok(res) => {
                required_actions = res;
            }
            Err(err) => {
                log::error!("Failed to load required actions");
                return ApiResult::from_error(500, "500", "Failed to load required actions");
            }
        }

        let user_model: UserModel =
            self.user_model_from_representation(&realm, &user, required_actions);

        let created_user = self.user_provider.create_user(&user).await;
        if let Err(err) = created_user {
            log::error!(
                "Failed to create user: {}, realm: {}. Error: {}",
                &user.email,
                &user.realm_id,
                err
            );
            return ApiResult::from_error(500, "500", "Failed to create user");
        }
        let password_policy = realm.password_policy.unwrap_or_default();

        credential_input = UserCredentialModel::new();
        todo!()
    }
    async fn udpate_user(&self, realm: UserModel) -> ApiResult<()> {
        todo!()
    }
    async fn delete_user(&self, realm_id: &str, user_id: &str) -> ApiResult<()> {
        todo!()
    }

    async fn load_user(&self, realm_id: &str, user_id: &str) -> ApiResult<UserModel> {
        let loaded_user = self.user_provider.load_user_by_id(&realm_id, user_id).await;
        match loaded_user {
            Ok(user) => ApiResult::<UserModel>::from_option(user),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn load_users_by_realm_id(&self, realm_id: &str) -> ApiResult<Vec<UserModel>> {
        let loaded_users = self.user_provider.load_users_by_realm_id(&realm_id).await;
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

    async fn add_user_role(&self, realm_id: &str, user_id: &str, role_id: &str) -> ApiResult<()> {
        let user_exists = self
            .user_provider
            .user_exists_by_id(&realm_id, &user_id)
            .await;
        if let Ok(response) = user_exists {
            if !response {
                log::error!("user: {} not found in realm: {}", &user_id, &realm_id);
                return ApiResult::from_error(409, "404", "user not found");
            }
        }

        let existing_role = self
            .role_provider
            .role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = self
            .user_provider
            .add_user_role(&realm_id, &user_id, &role_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to add client role mapping"),
        }
    }

    async fn remove_user_role(
        &self,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let user_exists = self
            .user_provider
            .user_exists_by_id(&realm_id, &user_id)
            .await;
        if let Ok(response) = user_exists {
            if !response {
                log::error!("user: {} not found in realm: {}", &user_id, &realm_id);
                return ApiResult::from_error(409, "404", "user not found");
            }
        }

        let existing_role = self
            .role_provider
            .role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = self
            .user_provider
            .remove_user_role(&realm_id, &user_id, &role_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to add client role mapping"),
        }
    }

    async fn load_user_roles(&self, realm_id: &str, user_id: &str) -> ApiResult<Vec<RoleModel>> {
        let loaded_roles = self
            .role_provider
            .load_user_roles(&realm_id, &user_id)
            .await;
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

    async fn add_user_group(&self, realm_id: &str, user_id: &str, group_id: &str) -> ApiResult<()> {
        let user_exists = self
            .user_provider
            .user_exists_by_id(&realm_id, &user_id)
            .await;
        if let Ok(response) = user_exists {
            if !response {
                log::error!("user: {} not found in realm: {}", &user_id, &realm_id);
                return ApiResult::from_error(409, "404", "user not found");
            }
        }

        let existing_group = self
            .group_provider
            .exists_groups_by_id(&realm_id, &group_id)
            .await;
        if let Ok(res) = existing_group {
            if !res {
                log::error!("group: {} not found in realm: {}", &group_id, &realm_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = self
            .user_provider
            .add_user_group(&realm_id, &user_id, &group_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to add user group mapping"),
        }
    }

    async fn remove_user_group(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> ApiResult<()> {
        let user_exists = self
            .user_provider
            .user_exists_by_id(&realm_id, &user_id)
            .await;
        if let Ok(response) = user_exists {
            if !response {
                log::error!("user: {} not found in realm: {}", &user_id, &realm_id);
                return ApiResult::from_error(409, "404", "user not found");
            }
        }

        let existing_group = self
            .group_provider
            .exists_groups_by_id(&realm_id, &group_id)
            .await;
        if let Ok(res) = existing_group {
            if !res {
                log::error!("group: {} not found in realm: {}", &group_id, &realm_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = self
            .user_provider
            .remove_user_group(&realm_id, &user_id, &group_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to add user group mapping"),
        }
    }

    async fn load_user_groups(&self, realm_id: &str, user_id: &str) -> ApiResult<Vec<GroupModel>> {
        let loaded_groups = self
            .group_provider
            .load_user_groups(&realm_id, &user_id)
            .await;
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

    async fn user_count_groups(&self, realm_id: &str, user_id: &str) -> ApiResult<i64> {
        let response = self
            .user_provider
            .user_count_groups(&realm_id, &user_id)
            .await;
        match response {
            Ok(count) => ApiResult::from_data(count),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn count_users(&self, realm_id: &str) -> ApiResult<i64> {
        let response = self.user_provider.count_users(&realm_id).await;
        match response {
            Ok(count) => ApiResult::from_data(count),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn load_user_groups_paging(
        &self,
        realm_id: &str,
        user_id: &str,
        page_size: i32,
        page_index: i32,
    ) -> ApiResult<GroupPagingResult> {
        let loaded_groups = self
            .group_provider
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
}
*/

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
pub struct UserCredentialService {
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
