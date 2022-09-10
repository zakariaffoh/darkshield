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

use models::entities::realm::RealmModel;
use store::providers::interfaces::authz_provider::IRoleProvider;

#[async_trait]
pub trait IUserService: Interface {
    async fn create_user(&self, realm: UserModel) -> ApiResult<RealmModel>;
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
    async fn create_user(&self, user: UserModel) -> ApiResult<RealmModel> {
        /*let realm_model = self.realm_provider.load_realm(&user.realm_id).await;
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

        credential_input = UserCredentialModel::new();*/
        todo!()
    }

    async fn udpate_user(&self, user: UserModel) -> ApiResult<()> {
        todo!()
    }

    async fn delete_user(&self, _realm_id: &str, user_id: &str) -> ApiResult<()> {
        todo!()
    }

    async fn load_user(&self, _realm_id: &str, user_id: &str) -> ApiResult<UserModel> {
        todo!()
    }

    async fn load_users_by_realm_id(&self, _realm_id: &str) -> ApiResult<Vec<UserModel>> {
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

    async fn count_users(&self, realm_id: &str) -> ApiResult<i64> {
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

    async fn user_disable_credential_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
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
