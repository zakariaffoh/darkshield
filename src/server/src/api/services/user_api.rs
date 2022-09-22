use crate::context::DarkShieldContext;
use ::services::services::credentials_services::IUserCredentialService;
use commons::{validation::EmailValidator, ApiResult};
use models::entities::{
    auth::{RequiredActionEnum, RequiredActionModel},
    authz::{GroupModel, GroupPagingResult, RoleModel},
    credentials::{
        CredentialRepresentation, CredentialTypeEnum, CredentialViewRepresentation,
        PasswordCredentialModel, UserCredentialModel,
    },
    realm::{RealmModel, HASH_ALGORITHM_DEFAULT},
    user::{UserCreateModel, UserModel, UserProfileHelper, UserStorageEnum},
};
use services::services::{
    auth_services::IRequiredActionService,
    authz_services::{IGroupService, IRoleService},
    realm_service::IRealmService,
    user_services::IUserService,
};
use shaku::HasComponent;

pub struct UserApi;

impl UserApi {
    pub async fn create_user(
        context: &DarkShieldContext,
        user: UserCreateModel,
    ) -> ApiResult<UserModel> {
        let realm_service: &dyn IRealmService = context.services().resolve_ref();
        let realm_model = realm_service.load_realm(&user.realm_id).await;
        match &realm_model {
            Ok(realm) => {
                if realm.is_none() {
                    log::error!("Realm: {} not found", &user.realm_id);
                    return ApiResult::from_error(404, "404", "realm not found");
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
        let user_service: &dyn IUserService = context.services().resolve_ref();
        let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();

        if realm.registration_allowed.unwrap() {
            log::error!("User registration not allowed for realm {}", &user.realm_id,);
            return ApiResult::from_error(403, "403", "User registration not allowed");
        }
        let mut user_name = user.user_name.clone();
        if realm.register_email_as_username.unwrap() {
            user_name = user.email.clone();
        }
        if user_name.is_empty() {
            log::error!("User name is null or empty");
            return ApiResult::from_error(400, "400", "User name is null or empty");
        }
        if user_service
            .user_exists_by_user_name(&user.realm_id, &user_name)
            .await
            .unwrap_or_default()
        {
            log::error!("User with user name: {} already exist", &user_name);
            return ApiResult::from_error(409, "409", "User allready exists in the realm");
        }

        if !user.email.is_empty() && realm.duplicated_email_allowed.unwrap_or_default() {
            if user_service
                .user_exists_by_email(&user.realm_id, &user_name)
                .await
                .unwrap_or_default()
            {
                log::error!("User with user name: {} already exist", &user_name);
                return ApiResult::from_error(409, "409", "User allready exists in the realm");
            }
        }

        let mut required_actions_list = required_action_service
            .load_required_action_by_realm_id(&user.realm_id)
            .await;
        match required_actions_list {
            Err(err) => {
                log::error!("Failed to load required actions");
                return ApiResult::from_error(500, "500", "Failed to load required actions");
            }
            _ => {}
        }

        let required_actions = required_actions_list.unwrap();
        let user_model =
            UserApi::user_model_from_representation(&realm, &user, required_actions).await;
        match user_model {
            Err(err) => {
                log::error!("Invalid user. Error: {}", &err);
                return ApiResult::from_error(400, "400", &err);
            }
            _ => {}
        }

        let user_model = user_model.unwrap();
        let credential_input = UserApi::create_user_credential_input(&realm, &user).await;
        match credential_input {
            Err(err) => {
                log::error!("Invalid user credential. Error: {}", &err);
                return ApiResult::from_error(400, "400", &err);
            }
            _ => {}
        }
        let credential_input = credential_input.unwrap();

        let created_user = user_service
            .create_user(&user_model, &credential_input)
            .await;
        if let Err(err) = created_user {
            log::error!(
                "Failed to create user: {}, realm: {}. Error: {}",
                &user.email,
                &user.realm_id,
                err
            );
            return ApiResult::from_error(500, "500", "Failed to create user");
        }

        ApiResult::Data(user_model)
    }

    async fn user_model_from_representation(
        realm: &RealmModel,
        user_create: &UserCreateModel,
        required_actions: Vec<RequiredActionModel>,
    ) -> Result<UserModel, String> {
        let realm_required_action_models = required_actions;
        let mut valid_actions: Vec<String> = Vec::new();

        if !realm_required_action_models.is_empty() {
            let actions = if let Some(required_actions) = &user_create.required_actions {
                required_actions.clone()
            } else {
                Vec::<String>::new()
            };

            let realm_valid_actions: Vec<String> = realm_required_action_models
                .iter()
                .map(|r| r.action.to_string())
                .collect();
            for action in actions.iter() {
                if realm_valid_actions.contains(&action) {
                    valid_actions.push(action.to_owned());
                }
            }
        }

        if user_create.credential.credential_type == CredentialTypeEnum::PASSWORD
            && user_create.credential.is_temporary.unwrap()
        {
            valid_actions.push(RequiredActionEnum::UpdatePassword.to_string());
        }

        if !user_create.email.is_empty() {
            let validate_email = EmailValidator::validate(&user_create.email);
            if let Err(err) = validate_email {
                log::error!(
                    "Email user: {} email{} is invalid",
                    &user_create.user_id,
                    &user_create.email
                );
                return Err("User email is invalid".to_string());
            }
        }

        let user = UserModel {
            user_id: user_create.user_id.clone(),
            realm_id: user_create.realm_id.clone(),
            user_name: user_create.user_name.clone(),
            enabled: user_create.enabled.clone(),
            email: user_create.email.clone(),
            email_verified: Some(false),
            required_actions: Some(valid_actions),
            not_before: user_create.not_before,
            user_storage: Some(UserStorageEnum::Local),
            attributes: user_create.attributes.clone(),
            is_service_account: user_create.is_service_account,
            service_account_client_link: user_create.service_account_client_link.clone(),
            metadata: None,
        };

        if let Err(err) = UserProfileHelper::validate_user_profile_and_attributes(&realm, &user) {
            log::error!("Invalid user: {} profile", &user.user_id,);
            return Err("Invalid user profile".to_string());
        }
        return Ok(user);
    }

    async fn create_user_credential_input(
        realm: &RealmModel,
        user: &UserCreateModel,
    ) -> Result<UserCredentialModel, String> {
        let password_policy = if let Some(policy) = &realm.password_policy {
            policy.hash_algorithm.clone()
        } else {
            Some(HASH_ALGORITHM_DEFAULT.to_owned())
        };

        Ok(UserCredentialModel::new(
            uuid::Uuid::new_v4().to_string(),
            CredentialTypeEnum::PASSWORD.to_string(),
            user.credential.secret.clone(),
            None,
            password_policy,
            None,
        ))
    }

    pub async fn udpate_user(context: &DarkShieldContext, user: UserModel) -> ApiResult<()> {
        let realm_service: &dyn IRealmService = context.services().resolve_ref();
        let realm_model = realm_service.load_realm(&user.realm_id).await;
        match &realm_model {
            Ok(realm) => {
                if realm.is_none() {
                    log::error!("Realm: {} not found", &user.realm_id);
                    return ApiResult::from_error(404, "404", "realm not found");
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
        let user_service: &dyn IUserService = context.services().resolve_ref();

        if !user_service
            .user_exists_by_id(&user.realm_id, &user.user_id)
            .await
            .unwrap_or_default()
        {
            log::error!("User with user id: {} does not exist", &user.user_name);
            return ApiResult::from_error(404, "404", "User does not exists in the realm");
        }
        match user_service.udpate_user(&user).await {
            Err(err) => {
                log::error!("User: {} updated. Error: {}", &user.user_id, &err);
                return ApiResult::from_error(500, "500", "Failed to update user");
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn delete_user(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
    ) -> ApiResult<()> {
        let user_service: &dyn IUserService = context.services().resolve_ref();
        if !user_service
            .user_exists_by_id(&realm_id, &user_id)
            .await
            .unwrap_or_default()
        {
            log::error!("User with user id: {} does not exist", &user_id);
            return ApiResult::from_error(404, "404", "User does not exists in the realm");
        }
        let deleted_user = user_service.delete_user(&realm_id, &user_id).await;
        match deleted_user {
            Err(err) => ApiResult::from_error(500, "500", &err),
            _ => ApiResult::no_content(),
        }
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
                return ApiResult::from_error(404, "404", "user not found");
            }
        }

        let existing_group = group_service
            .exists_groups_by_id(&realm_id, &group_id)
            .await;
        if let Ok(res) = existing_group {
            if !res {
                log::error!("group: {} not found in realm: {}", &group_id, &realm_id,);
                return ApiResult::from_error(404, "404", "client role not found");
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

    pub async fn load_user_credentials(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
    ) -> ApiResult<Vec<CredentialViewRepresentation>> {
        let user_credential_service: &dyn IUserCredentialService = context.services().resolve_ref();
        let user_credentials = user_credential_service
            .load_user_credentials_view(&realm_id, &user_id)
            .await;
        match user_credentials {
            Ok(credentials) => {
                log::info!("[{}] realms loaded", credentials.len());
                if credentials.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(credentials)
                }
            }
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn user_disable_credential_type(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> ApiResult<()> {
        if credential_type.is_empty() {
            log::error!("credential_type is empty");
            return ApiResult::from_error(400, "400", "invalid credential type");
        }
        let user_service: &dyn IUserService = context.services().resolve_ref();

        let user_exists = user_service.user_exists_by_id(&realm_id, &user_id).await;
        if let Ok(response) = user_exists {
            if !response {
                log::error!("user: {} not found in realm: {}", &user_id, &realm_id);
                return ApiResult::from_error(404, "404", "user not found");
            }
        }
        let user_credential_service: &dyn IUserCredentialService = context.services().resolve_ref();
        let disabled_response = user_credential_service
            .disable_credential_type(&realm_id, &user_id, &credential_type)
            .await;
        match disabled_response {
            Err(err) => {
                log::error!(
                    "Failed to disable user: {} credential_type: {}",
                    &user_id,
                    &credential_type
                );
                return ApiResult::from_error(500, "500", "failed to disable credential type");
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn reset_user_password(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        password: &CredentialRepresentation,
    ) -> ApiResult<()> {
        if password.secret.is_empty() {
            log::error!("credential secret is empty");
            return ApiResult::from_error(400, "400", "credential secret is empty");
        }
        let user_service: &dyn IUserService = context.services().resolve_ref();
        let user = user_service.load_user(&realm_id, &user_id).await;
        match &user {
            Ok(data) => {
                if data.is_none() {
                    log::error!("user: {} not found in realm: {}", &user_id, &realm_id);
                    return ApiResult::from_error(404, "404", "user not found");
                }
            }
            Err(err) => {
                log::error!(
                    "failed to load user: {}, realm: {}. Error: {}",
                    &user_id,
                    &realm_id,
                    &err
                );
                return ApiResult::from_error(500, "500", "failed to load user");
            }
        }
        let user_credential_service: &dyn IUserCredentialService = context.services().resolve_ref();
        let mut user = user.unwrap().unwrap();
        if password.is_temporary.unwrap_or_default() {
            if let Some(actions) = user.required_actions {
                let mut update_actions = actions;
                update_actions.push(RequiredActionEnum::UpdatePassword.to_string());
                user.required_actions = Some(update_actions);
            } else {
                user.required_actions = Some(vec![RequiredActionEnum::UpdatePassword.to_string()])
            }
        }
        let password_credential = PasswordCredentialModel::from_password(&password.secret);
        let updated_credential = user_credential_service
            .reset_user_password(&realm_id, &user.user_id, &password_credential)
            .await;

        match updated_credential {
            Err(err) => {
                log::error!("Failed to update user: {} credential", &user_id,);
                return ApiResult::from_error(500, "500", "failed to update user");
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn move_credential_to_position(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
        previous_credential_id: &str,
    ) -> ApiResult<()> {
        let user_service: &dyn IUserService = context.services().resolve_ref();
        let user = user_service.user_exists_by_id(&realm_id, &user_id).await;
        match &user {
            Ok(data) => {
                if !data {
                    log::error!("user: {} not found in realm: {}", &user_id, &realm_id);
                    return ApiResult::from_error(404, "404", "user not found");
                }
            }
            Err(err) => {
                log::error!(
                    "failed to load user: {}, realm: {}. Error: {}",
                    &user_id,
                    &realm_id,
                    &err
                );
                return ApiResult::from_error(500, "500", "failed to load user");
            }
        }
        let user_credential_service: &dyn IUserCredentialService = context.services().resolve_ref();
        let current_credential_exist = user_credential_service
            .user_credential_exists(&realm_id, &user_id, &credential_id)
            .await;

        match &current_credential_exist {
            Ok(data) => {
                if !data {
                    log::error!(
                        "user: {} credential: {},  realm: {} not found",
                        &user_id,
                        &credential_id,
                        &realm_id
                    );
                    return ApiResult::from_error(404, "404", "user credential not found");
                }
            }
            Err(err) => {
                log::error!(
                    "failed to load user: {}, credential: {}, realm: {}. Error: {}",
                    &user_id,
                    &credential_id,
                    &realm_id,
                    &err
                );
                return ApiResult::from_error(500, "500", "failed to load user credential");
            }
        }

        let previous_credential_exist = user_credential_service
            .user_credential_exists(&realm_id, &user_id, &previous_credential_id)
            .await;

        match &previous_credential_exist {
            Ok(data) => {
                if !data {
                    log::error!(
                        "user: {} credential: {},  realm: {} not found",
                        &user_id,
                        &previous_credential_id,
                        &realm_id
                    );
                    return ApiResult::from_error(404, "404", "user credential not found");
                }
            }
            Err(err) => {
                log::error!(
                    "failed to load user: {}, credential: {}, realm: {}. Error: {}",
                    &user_id,
                    &previous_credential_id,
                    &realm_id,
                    &err
                );
                return ApiResult::from_error(500, "500", "failed to load user credential");
            }
        }
        let response = user_credential_service
            .move_credential_to_position(
                &realm_id,
                &user_id,
                &credential_id,
                &previous_credential_id,
            )
            .await;

        match response {
            Err(err) => {
                log::error!(
                    "Failed to move user: {} credential {}, realm: {}. Error: {}",
                    &user_id,
                    &credential_id,
                    &realm_id,
                    &err
                );
                return ApiResult::from_error(500, "500", "failed to move user credential");
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn move_credential_to_first(
        context: &DarkShieldContext,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
    ) -> ApiResult<()> {
        let user_service: &dyn IUserService = context.services().resolve_ref();
        let user = user_service.user_exists_by_id(&realm_id, &user_id).await;
        match &user {
            Ok(data) => {
                if !data {
                    log::error!("user: {} not found in realm: {}", &user_id, &realm_id);
                    return ApiResult::from_error(404, "404", "user not found");
                }
            }
            Err(err) => {
                log::error!(
                    "failed to load user: {}, realm: {}. Error: {}",
                    &user_id,
                    &realm_id,
                    &err
                );
                return ApiResult::from_error(500, "500", "failed to load user");
            }
        }

        let user_credential_service: &dyn IUserCredentialService = context.services().resolve_ref();
        let credential_exist = user_credential_service
            .user_credential_exists(&realm_id, &user_id, &credential_id)
            .await;

        match &credential_exist {
            Ok(data) => {
                if !data {
                    log::error!(
                        "user: {} credential: {},  realm: {} not found",
                        &user_id,
                        &credential_id,
                        &realm_id
                    );
                    return ApiResult::from_error(404, "404", "user credential not found");
                }
            }
            Err(err) => {
                log::error!(
                    "failed to load user: {}, credential: {}, realm: {}. Error: {}",
                    &user_id,
                    &credential_id,
                    &realm_id,
                    &err
                );
                return ApiResult::from_error(500, "500", "failed to load user credential");
            }
        }

        let response = user_credential_service
            .move_credential_to_first(&realm_id, &user_id, &credential_id)
            .await;

        match response {
            Err(err) => {
                log::error!(
                    "Failed to move user: {} credential {}, realm: {}. Error: {}",
                    &user_id,
                    &credential_id,
                    &realm_id,
                    &err
                );
                return ApiResult::from_error(500, "500", "failed to move user credential");
            }
            Ok(_) => ApiResult::no_content(),
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
}
