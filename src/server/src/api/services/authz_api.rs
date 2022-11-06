use std::sync::Arc;

use commons::ApiResult;
use log;
use services::{services::authz_services::IPolicyService, session::session::DarkshieldSession};
use uuid;

use models::{
    auditable::AuditableModel,
    entities::{
        authz::{
            DecisionLogicEnum, DecisionStrategyEnum, GroupModel, GroupPolicyConfig,
            IdentityProviderModel, PolicyModel, PolicyRepresentation, PolicyTypeEnum, RegexConfig,
            ResourceModel, ResourceServerModel, RoleModel, ScopeModel, TimePolicyConfig,
        },
        client::{ClientModel, ClientScopeModel},
        user::UserModel,
    },
};
use services::services::{
    client_services::{IClientScopeService, IClientService},
    user_services::IUserService,
};
use shaku::HasComponent;
pub struct AuthorizationModelApi;

impl AuthorizationModelApi {
    pub async fn create_role(session: &DarkshieldSession, role: RoleModel) -> ApiResult<RoleModel> {
        let existing_role = session
            .services()
            .role_service()
            .load_role_by_name(&role.realm_id, &role.name)
            .await;
        if let Ok(response) = existing_role {
            if response.is_some() {
                log::error!(
                    "role: {} already exists in realm: {}",
                    &role.name,
                    &role.realm_id
                );
                return ApiResult::from_error(409, "500", "role already exists");
            }
        }
        let mut role = role;
        role.role_id = uuid::Uuid::new_v4().to_string();
        role.metadata = AuditableModel::from_creator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let created_role = session.services().role_service().create_role(&role).await;
        match created_role {
            Ok(_) => ApiResult::Data(role),
            Err(err) => {
                log::error!(
                    "Failed to create role: {}, realm: {}. Error: {}",
                    &role.name,
                    &role.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to create role")
            }
        }
    }

    pub async fn update_role(session: &DarkshieldSession, role: RoleModel) -> ApiResult<()> {
        let existing_role = session
            .services()
            .role_service()
            .load_role_by_id(&role.realm_id, &role.role_id)
            .await;
        if let Ok(response) = existing_role {
            if response.is_none() {
                log::error!(
                    "role: {} not found in realm: {}",
                    &role.name,
                    &role.realm_id
                );
                return ApiResult::from_error(404, "404", "role not found");
            }
        }
        let mut role = role;
        role.metadata = AuditableModel::from_updator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let updated_role = session.services().role_service().update_role(&role).await;
        match updated_role {
            Err(err) => {
                log::error!(
                    "Failed to update role: {}, realm: {}. Error: {}",
                    &role.role_id,
                    &role.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update role")
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn delete_role(
        session: &DarkshieldSession,
        realm_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let existing_role = session
            .services()
            .role_service()
            .load_role_by_id(&realm_id, &role_id)
            .await;
        if let Ok(response) = existing_role {
            if response.is_none() {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id);
                return ApiResult::from_error(404, "404", "role not found");
            }
        }
        let deleted_role = session
            .services()
            .role_service()
            .delete_role(&realm_id, &role_id)
            .await;
        match deleted_role {
            Err(err) => {
                log::error!(
                    "Failed to delete role: {}, realm: {}. Error: {}",
                    &role_id,
                    &realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update role")
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn load_role_by_id(
        session: &DarkshieldSession,
        realm_id: &str,
        role_id: &str,
    ) -> ApiResult<RoleModel> {
        let loaded_role = session
            .services()
            .role_service()
            .load_role_by_id(&realm_id, &role_id)
            .await;
        match loaded_role {
            Ok(role) => ApiResult::<RoleModel>::from_option(role),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_roles_by_realm(
        session: &DarkshieldSession,
        realm_id: &str,
    ) -> ApiResult<Vec<RoleModel>> {
        let loaded_roles = session
            .services()
            .role_service()
            .load_roles_by_realm(&realm_id)
            .await;
        match loaded_roles {
            Ok(roles) => {
                log::info!("[{}] roles loaded for realm: {}", roles.len(), &realm_id);
                if roles.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(roles)
                }
            }
            Err(err) => {
                log::error!("Failed to load roles from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn count_roles_by_realm(
        session: &DarkshieldSession,
        realm_id: &str,
    ) -> ApiResult<i64> {
        let response = session
            .services()
            .role_service()
            .count_roles_by_realm(&realm_id)
            .await;
        match response {
            Ok(count) => ApiResult::from_data(count),
            Err(err) => {
                log::error!("Failed to count roles. Error: {}", err);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn create_group(
        session: &DarkshieldSession,
        group: GroupModel,
    ) -> ApiResult<GroupModel> {
        let existing_group = session
            .services()
            .group_service()
            .load_group_by_name(&group.realm_id, &group.name)
            .await;
        if let Ok(response) = existing_group {
            if response.is_some() {
                log::error!(
                    "group: {} already exists in realm: {}",
                    &group.name,
                    &group.realm_id
                );
                return ApiResult::from_error(409, "500", "role already exists");
            }
        }
        let mut group = group;
        group.group_id = uuid::Uuid::new_v4().to_string();
        group.metadata = AuditableModel::from_creator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let created_group = session
            .services()
            .group_service()
            .create_group(&group)
            .await;
        match created_group {
            Ok(_) => ApiResult::Data(group),
            Err(err) => {
                log::error!(
                    "Failed to create group: {}, realm: {}. Error: {}",
                    &group.name,
                    &group.realm_id,
                    err.to_string()
                );
                ApiResult::from_error(500, "500", "failed to create group")
            }
        }
    }

    pub async fn udpate_group(session: &DarkshieldSession, group: GroupModel) -> ApiResult<()> {
        let existing_group = session
            .services()
            .group_service()
            .load_group_by_id(&group.realm_id, &group.group_id)
            .await;
        if let Ok(response) = existing_group {
            if response.is_some() {
                log::error!(
                    "Group: {} already exists in realm: {}",
                    &group.name,
                    &group.realm_id
                );
                return ApiResult::from_error(409, "500", "group already exists");
            }
        }
        let mut group = group;
        group.metadata = AuditableModel::from_updator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let updated_group = session
            .services()
            .group_service()
            .udpate_group(&group)
            .await;
        match updated_group {
            Err(err) => {
                log::error!(
                    "Failed to update group: {}, realm: {}. Error: {}",
                    &group.group_id,
                    &group.realm_id,
                    &err
                );
                ApiResult::from_error(500, "500", "failed to update group")
            }
            _ => {
                log::info!(
                    "Group updated for id: {} and realm: {}",
                    &group.group_id,
                    &group.realm_id
                );
                ApiResult::no_content()
            }
        }
    }

    pub async fn delete_group(
        session: &DarkshieldSession,
        realm_id: &str,
        group_id: &str,
    ) -> ApiResult<()> {
        let existing_group = session
            .services()
            .group_service()
            .load_group_by_id(&realm_id, &group_id)
            .await;
        if let Ok(response) = existing_group {
            if response.is_none() {
                log::error!("group: {} not found in realm: {}", &group_id, &realm_id);
                return ApiResult::from_error(404, "404", "role not found");
            }
        }
        let result = session
            .services()
            .group_service()
            .delete_group(&realm_id, &group_id)
            .await;
        match result {
            Err(_) => ApiResult::from_error(500, "500", "failed to update role"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn load_group_by_id(
        session: &DarkshieldSession,
        realm_id: &str,
        group_id: &str,
    ) -> ApiResult<GroupModel> {
        let loaded_group = session
            .services()
            .group_service()
            .load_group_by_id(&realm_id, &group_id)
            .await;
        match loaded_group {
            Ok(group) => ApiResult::<GroupModel>::from_option(group),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_groups_by_realm(
        session: &DarkshieldSession,
        realm_id: &str,
    ) -> ApiResult<Vec<GroupModel>> {
        let loaded_groups = session
            .services()
            .group_service()
            .load_groups_by_realm(&realm_id)
            .await;
        match loaded_groups {
            Ok(groups) => {
                log::info!("[{}] groups loaded for realm: {}", groups.len(), &realm_id);
                if groups.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(groups)
                }
            }
            Err(err) => {
                log::error!("Failed to load group from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn count_groups(session: &DarkshieldSession, realm_id: &str) -> ApiResult<i64> {
        let response = session
            .services()
            .group_service()
            .count_groups(&realm_id)
            .await;
        match response {
            Ok(count) => ApiResult::from_data(count),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn add_group_role(
        session: &DarkshieldSession,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let existing_group = session
            .services()
            .group_service()
            .exists_groups_by_id(&realm_id, &group_id)
            .await;
        if let Ok(response) = existing_group {
            if !response {
                log::error!("group: {} not found in realm: {}", group_id, realm_id);
                return ApiResult::from_error(409, "404", "group not found");
            }
        }

        let existing_role = session
            .services()
            .role_service()
            .role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "role not found");
            }
        }

        let response = session
            .services()
            .group_service()
            .add_group_role(&realm_id, &group_id, &role_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add role to group"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn remove_group_role(
        session: &DarkshieldSession,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let existing_group = session
            .services()
            .group_service()
            .exists_groups_by_id(&realm_id, &group_id)
            .await;
        if let Ok(response) = existing_group {
            if !response {
                log::error!("group: {} not found in realm: {}", group_id, realm_id);
                return ApiResult::from_error(409, "404", "group not found");
            }
        }

        let existing_role = session
            .services()
            .role_service()
            .role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "role not found");
            }
        }

        let response = session
            .services()
            .group_service()
            .remove_group_role(&realm_id, &group_id, &role_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to remove role from group"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn create_identity_provider(
        session: &DarkshieldSession,
        idp: IdentityProviderModel,
    ) -> ApiResult<IdentityProviderModel> {
        let existing_idp = session
            .services()
            .identity_provider_service()
            .load_identity_provider_by_internal_id(&idp.realm_id, &idp.internal_id)
            .await;
        if let Ok(response) = existing_idp {
            if response.is_some() {
                log::error!(
                    "identity privider: {} already exists in realm: {}",
                    &idp.name,
                    &idp.realm_id
                );
                return ApiResult::from_error(409, "500", "identity privider already exists");
            }
        }
        let mut idp = idp;
        idp.internal_id = uuid::Uuid::new_v4().to_string();
        idp.metadata = AuditableModel::from_creator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let created_idp = session
            .services()
            .identity_provider_service()
            .create_identity_provider(&idp)
            .await;
        match created_idp {
            Ok(_) => ApiResult::Data(idp),
            Err(err) => {
                log::error!(
                    "Failed to create identity provider: {}, realm: {}. Error: {}",
                    &idp.name,
                    &idp.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to create identity privider")
            }
        }
    }

    pub async fn udpate_identity_provider(
        session: &DarkshieldSession,
        idp: IdentityProviderModel,
    ) -> ApiResult<()> {
        let existing_idp = session
            .services()
            .identity_provider_service()
            .load_identity_provider_by_internal_id(&idp.realm_id, &idp.internal_id)
            .await;

        if let Ok(response) = existing_idp {
            if response.is_none() {
                log::error!(
                    "Identity provider: {} already exists in realm: {}",
                    &idp.name,
                    &idp.realm_id
                );
                return ApiResult::from_error(409, "500", "identity provider already exists");
            }
            let existing_idp = response.unwrap();
            if existing_idp.name != idp.name {
                let has_alias = session
                    .services()
                    .identity_provider_service()
                    .exists_by_alias(&idp.realm_id, &idp.internal_id)
                    .await;
                if let Ok(res) = has_alias {
                    if res {
                        log::error!(
                            "identity provider with name: {} already exists in realm: {}",
                            &idp.name,
                            &idp.realm_id
                        );
                        return ApiResult::from_error(
                            409,
                            "500",
                            &format!("identity provider already for alias {0}", &idp.name),
                        );
                    }
                }
            }
        }
        let mut idp = idp;
        idp.metadata = AuditableModel::from_updator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let updated_idp = session
            .services()
            .identity_provider_service()
            .udpate_identity_provider(&idp)
            .await;
        match updated_idp {
            Ok(_) => ApiResult::no_content(),
            Err(err) => {
                log::error!(
                    "Failed to update identity provider: {}, realm: {}. Error: {}",
                    &idp.name,
                    &idp.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update role")
            }
        }
    }

    pub async fn load_identity_provider(
        session: &DarkshieldSession,
        realm_id: &str,
        internal_id: &str,
    ) -> ApiResult<IdentityProviderModel> {
        let loaded_idp = session
            .services()
            .identity_provider_service()
            .load_identity_provider_by_internal_id(&realm_id, &internal_id)
            .await;
        match loaded_idp {
            Ok(idp) => ApiResult::<IdentityProviderModel>::from_option(idp),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_identity_providers_by_realm(
        session: &DarkshieldSession,
        realm_id: &str,
    ) -> ApiResult<Vec<IdentityProviderModel>> {
        let loaded_idps = session
            .services()
            .identity_provider_service()
            .load_identity_providers_by_realm(&realm_id)
            .await;

        match loaded_idps {
            Ok(idps) => {
                log::info!(
                    "[{}] identity providers loaded for realm: {}",
                    idps.len(),
                    &realm_id
                );
                if idps.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(idps)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load identity providers from realm: {}",
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn delete_identity_provider(
        session: &DarkshieldSession,
        realm_id: &str,
        internal_id: &str,
    ) -> ApiResult<()> {
        let existing_idp = session
            .services()
            .identity_provider_service()
            .load_identity_provider_by_internal_id(&realm_id, &internal_id)
            .await;
        if let Ok(response) = existing_idp {
            if response.is_none() {
                log::error!(
                    "identity provider: {} not found in realm: {}",
                    &internal_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "identity provider not found");
            }
        }

        let updated_idp = session
            .services()
            .identity_provider_service()
            .delete_identity_provider(&realm_id, &internal_id)
            .await;
        match updated_idp {
            Err(err) => {
                log::error!(
                    "Failed to update identity provider: {}, realm: {}. Error: {}",
                    &internal_id,
                    &realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update identity provider")
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn exists_by_alias(
        session: &DarkshieldSession,
        realm_id: &str,
        alias: &str,
    ) -> ApiResult<bool> {
        let existing_idp = session
            .services()
            .identity_provider_service()
            .exists_by_alias(&realm_id, &alias)
            .await;
        match existing_idp {
            Ok(res) => ApiResult::Data(res),
            _ => ApiResult::from_error(500, "500", "failed check identity provider"),
        }
    }

    pub async fn create_resource_server(
        session: &DarkshieldSession,
        server: ResourceServerModel,
    ) -> ApiResult<ResourceServerModel> {
        let existing_resource_server = session
            .services()
            .resource_server_service()
            .load_resource_server_by_id(&server.realm_id, &server.server_id)
            .await;

        if let Ok(response) = existing_resource_server {
            if response.is_some() {
                log::error!(
                    "Resource server: {} already exists in realm: {}",
                    &server.name,
                    &server.realm_id
                );
                return ApiResult::from_error(409, "500", "Resource server already exists");
            }
        }
        let mut server = server;
        server.server_id = uuid::Uuid::new_v4().to_string();
        server.metadata = AuditableModel::from_creator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let created_role = session
            .services()
            .resource_server_service()
            .create_resource_server(&server)
            .await;
        match created_role {
            Ok(_) => ApiResult::Data(server),
            Err(err) => {
                log::error!(
                    "Failed to create resource server: {}, realm: {}. Error: {}",
                    &server.server_id,
                    &server.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "Failed to create resource server")
            }
        }
    }

    pub async fn udpate_resource_server(
        session: &DarkshieldSession,
        server: ResourceServerModel,
    ) -> ApiResult<()> {
        let existing_resource_server = session
            .services()
            .resource_server_service()
            .load_resource_server_by_id(&server.realm_id, &server.server_id)
            .await;

        if let Ok(response) = existing_resource_server {
            if response.is_none() {
                log::error!(
                    "Resource server: {} does not exists in realm: {}",
                    &server.server_id,
                    &server.realm_id
                );
                return ApiResult::from_error(404, "404", "Resource server does not exists");
            }
            let existing_server = response.unwrap();
            if existing_server.name != server.name {
                let server_with_name = session
                    .services()
                    .resource_server_service()
                    .resource_server_exists_by_alias(&server.realm_id, &server.name)
                    .await;

                if let Ok(res) = server_with_name {
                    if res {
                        log::error!(
                            "resource server with name: {} already exists in realm: {}",
                            &existing_server.name,
                            &existing_server.realm_id
                        );
                        return ApiResult::from_error(
                            409,
                            "500",
                            &format!(
                                "resource server already for name {0}",
                                &existing_server.name
                            ),
                        );
                    }
                }
            }
        }
        let mut server = server;
        server.metadata = AuditableModel::from_updator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let updated_idp = session
            .services()
            .resource_server_service()
            .udpate_resource_server(&server)
            .await;
        match updated_idp {
            Ok(_) => ApiResult::no_content(),
            Err(err) => {
                log::error!(
                    "Failed to update resource server: {}, realm: {}. Error: {}",
                    &server.name,
                    &server.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update resource server")
            }
        }
    }

    pub async fn load_resource_server_by_id(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<ResourceServerModel> {
        let loaded_resource_server = session
            .services()
            .resource_server_service()
            .load_resource_server_by_id(&realm_id, &server_id)
            .await;

        match loaded_resource_server {
            Ok(idp) => ApiResult::<ResourceServerModel>::from_option(idp),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_resource_servers_by_realm(
        session: &DarkshieldSession,
        realm_id: &str,
    ) -> ApiResult<Vec<ResourceServerModel>> {
        let loaded_servers = session
            .services()
            .resource_server_service()
            .load_resource_servers_by_realm(&realm_id)
            .await;

        match loaded_servers {
            Ok(idps) => {
                log::info!(
                    "[{}] resource servers loaded for realm: {}",
                    idps.len(),
                    &realm_id
                );
                if idps.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(idps)
                }
            }
            Err(err) => {
                log::error!("Failed to load resource servers from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn delete_resource_server_by_id(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<()> {
        let existing_server = session
            .services()
            .resource_server_service()
            .load_resource_server_by_id(&realm_id, &server_id)
            .await;
        if let Ok(response) = existing_server {
            if response.is_none() {
                log::error!(
                    "resource server: {} not found in realm: {}",
                    &server_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "resource server not found");
            }
        }

        let updated_server = session
            .services()
            .resource_server_service()
            .delete_resource_server_by_id(&realm_id, &server_id)
            .await;

        match updated_server {
            Err(err) => {
                log::error!(
                    "Failed to update resource server: {}, realm: {}. Error: {}",
                    &server_id,
                    &realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update resource server")
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn create_resource(
        session: &DarkshieldSession,
        resource: ResourceModel,
    ) -> ApiResult<ResourceModel> {
        let existing_resource = session
            .services()
            .resource_service()
            .resource_exists_by_name(&resource.realm_id, &resource.server_id, &resource.name)
            .await;

        if let Ok(response) = existing_resource {
            if response {
                log::error!(
                    "Resource: {}, server: {} already exists in realm: {}",
                    &resource.name,
                    &resource.server_id,
                    &resource.realm_id
                );
                return ApiResult::from_error(409, "409", "Resource already exists");
            }
        }
        let mut resource = resource;
        resource.resource_id = uuid::Uuid::new_v4().to_string();
        resource.metadata = AuditableModel::from_creator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let created_resource = session
            .services()
            .resource_service()
            .create_resource(&resource)
            .await;
        match created_resource {
            Err(err) => {
                log::error!(
                    "Failed to create resource: {}, server: {}, realm: {}. Error: {}",
                    &resource.resource_id,
                    &resource.server_id,
                    &resource.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "Failed to create resource")
            }
            _ => ApiResult::Data(resource),
        }
    }

    pub async fn udpate_resource(
        session: &DarkshieldSession,
        resource: ResourceModel,
    ) -> ApiResult<()> {
        let existing_resource = session
            .services()
            .resource_service()
            .load_resource_by_id(
                &resource.realm_id,
                &resource.server_id,
                &resource.resource_id,
            )
            .await;

        if let Ok(response) = existing_resource {
            if response.is_none() {
                log::error!(
                    "Resource: {}, server: {} does not exists in realm: {}",
                    &resource.resource_id,
                    &resource.server_id,
                    &resource.realm_id
                );
                return ApiResult::from_error(404, "404", "Resource does not exists");
            }
            let existing_resource = response.unwrap();
            if existing_resource.name != resource.name {
                let resource_with_name = session
                    .services()
                    .resource_service()
                    .resource_exists_by_name(
                        &resource.realm_id,
                        &resource.server_id,
                        &resource.resource_id,
                    )
                    .await;

                if let Ok(res) = resource_with_name {
                    if res {
                        log::error!(
                            "Resource with name: {}, server: {} already exists in realm: {}",
                            &existing_resource.name,
                            &existing_resource.server_id,
                            &existing_resource.realm_id
                        );
                        return ApiResult::from_error(
                            409,
                            "500",
                            &format!("resource already for name {0}", &existing_resource.name),
                        );
                    }
                }
            }
        }
        let mut resource = resource;
        resource.metadata = AuditableModel::from_updator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let updated_resource = session
            .services()
            .resource_service()
            .udpate_resource(&resource)
            .await;
        match updated_resource {
            Err(err) => {
                log::error!(
                    "Failed to update resource: {}, server: {}, realm: {}. Error: {}",
                    &resource.name,
                    &resource.server_id,
                    &resource.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "Failed to update resource")
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn load_resource_by_id(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> ApiResult<ResourceModel> {
        let loaded_resource = session
            .services()
            .resource_service()
            .load_resource_by_id(&realm_id, &server_id, &resource_id)
            .await;

        match loaded_resource {
            Ok(resource) => ApiResult::<ResourceModel>::from_option(resource),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_resources_by_server(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<Vec<ResourceModel>> {
        let loaded_resources = session
            .services()
            .resource_service()
            .load_resources_by_server(&realm_id, &server_id)
            .await;

        match loaded_resources {
            Ok(resources) => {
                log::info!(
                    "[{}] resource loaded for server: {}, realm: {}",
                    resources.len(),
                    &server_id,
                    &realm_id
                );
                if resources.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(resources)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load resources for server: {}, realm: {}",
                    &server_id,
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn load_resources_by_realm(
        session: &DarkshieldSession,
        realm_id: &str,
    ) -> ApiResult<Vec<ResourceModel>> {
        let loaded_resources = session
            .services()
            .resource_service()
            .load_resources_by_realm(&realm_id)
            .await;

        match loaded_resources {
            Ok(resources) => {
                log::info!(
                    "[{}] resources loaded for  realm: {}",
                    resources.len(),
                    &realm_id
                );
                if resources.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(resources)
                }
            }
            Err(err) => {
                log::error!("Failed to load resources for realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn delete_resource_by_id(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> ApiResult<()> {
        let existing_resource = session
            .services()
            .resource_service()
            .load_resource_by_id(&realm_id, &server_id, &resource_id)
            .await;

        if let Ok(response) = existing_resource {
            if response.is_none() {
                log::error!(
                    "resource: {}, server: {},  not found in realm: {}",
                    &resource_id,
                    &server_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "resource not found");
            }
        }
        let deleted_resource = session
            .services()
            .resource_service()
            .delete_resource_by_id(&realm_id, &server_id, &resource_id)
            .await;

        match deleted_resource {
            Err(err) => {
                log::error!(
                    "Failed to update resource: {}, server: {}, realm: {}. Error: {}",
                    &resource_id,
                    &server_id,
                    &realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update resource")
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn add_resource_scope(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> ApiResult<()> {
        let existing_resource = session
            .services()
            .resource_service()
            .resource_exists_by_id(&realm_id, &server_id, &resource_id)
            .await;
        if let Ok(response) = existing_resource {
            if !response {
                log::error!(
                    "Resource: {}, server: {} does not exists in realm: {}",
                    &resource_id,
                    &server_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "Resource does not exists");
            }
        }

        let existing_scope = session
            .services()
            .scope_service()
            .scope_exists_by_id(&realm_id, &server_id, &scope_id)
            .await;
        if let Ok(res) = existing_scope {
            if !res {
                log::error!(
                    "Scope: {}, server: {} does not exists in realm: {}",
                    &scope_id,
                    &server_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "Scope does not exists");
            }
        }

        let response = session
            .services()
            .resource_service()
            .add_resource_scope(&realm_id, &server_id, &resource_id, &scope_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add scope to resource"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn remove_resource_scope(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> ApiResult<()> {
        let existing_resource = session
            .services()
            .resource_service()
            .resource_exists_by_id(&realm_id, &server_id, &resource_id)
            .await;
        if let Ok(response) = existing_resource {
            if !response {
                log::error!(
                    "Resource: {}, server: {} does not exists in realm: {}",
                    &resource_id,
                    &server_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "Resource does not exists");
            }
        }

        let existing_scope = session
            .services()
            .scope_service()
            .scope_exists_by_id(&realm_id, &server_id, &scope_id)
            .await;
        if let Ok(res) = existing_scope {
            if !res {
                log::error!(
                    "Scope: {}, server: {} does not exists in realm: {}",
                    &scope_id,
                    &server_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "Scope does not exists");
            }
        }

        let response = session
            .services()
            .resource_service()
            .remove_resource_scope(&realm_id, &server_id, &resource_id, &scope_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add scope to resource"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn create_scope(
        session: &DarkshieldSession,
        scope: ScopeModel,
    ) -> ApiResult<ScopeModel> {
        let existing_resource_server = session
            .services()
            .resource_server_service()
            .resource_server_exists_by_id(&scope.realm_id, &scope.server_id)
            .await;

        if let Ok(exists_rserver) = existing_resource_server {
            if !exists_rserver {
                log::error!(
                    "Resource server: {}, does not exists in realm: {}",
                    &scope.name,
                    &scope.server_id,
                );
                return ApiResult::from_error(404, "404", "Resource servere not found");
            }
        }

        let existing_scope = session
            .services()
            .scope_service()
            .scope_exists_by_name(&scope.realm_id, &scope.server_id, &scope.name)
            .await;

        if let Ok(res) = existing_scope {
            if res {
                log::error!(
                    "Scope: {}, resource server: {} already exists in realm: {}",
                    &scope.name,
                    &scope.server_id,
                    &scope.realm_id
                );
                return ApiResult::from_error(409, "500", "scope already exists");
            }
        }

        let mut scope = scope;
        scope.scope_id = uuid::Uuid::new_v4().to_string();
        scope.metadata = AuditableModel::from_creator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let created_scope = session
            .services()
            .scope_service()
            .create_scope(&scope)
            .await;
        match created_scope {
            Err(err) => {
                log::error!(
                    "Failed to create scope: {}, resource server: {}, realm: {}. Error: {}",
                    &scope.name,
                    &scope.server_id,
                    &scope.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "Failed to create resource server scope")
            }
            _ => ApiResult::Data(scope),
        }
    }

    pub async fn udpate_scope(session: &DarkshieldSession, scope: ScopeModel) -> ApiResult<()> {
        let existing_resource_server = session
            .services()
            .resource_server_service()
            .resource_server_exists_by_id(&scope.realm_id, &scope.server_id)
            .await;

        if let Ok(exists_rserver) = existing_resource_server {
            if !exists_rserver {
                log::error!(
                    "Resource server: {}, does not exists in realm: {}",
                    &scope.name,
                    &scope.server_id,
                );
                return ApiResult::from_error(404, "500", "Resource servere not found");
            }
        }

        let existing_scope = session
            .services()
            .scope_service()
            .scope_exists_by_id(&scope.realm_id, &scope.server_id, &scope.scope_id)
            .await;

        if let Ok(res) = existing_scope {
            if !res {
                log::error!(
                    "Scope: {}, resource server: {} does not exists in realm: {}",
                    &scope.scope_id,
                    &scope.server_id,
                    &scope.realm_id
                );
                return ApiResult::from_error(404, "404", "scope not found");
            }
        }

        let mut scope = scope;
        scope.metadata = AuditableModel::from_updator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );

        let updated_scope = session
            .services()
            .scope_service()
            .udpate_scope(&scope)
            .await;
        match updated_scope {
            Err(err) => {
                log::error!(
                    "Failed to update scope: {}, resource servr: {}, realm: {}. Error: {}",
                    &scope.scope_id,
                    &scope.server_id,
                    &scope.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update scope")
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn load_scope_by_id(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> ApiResult<ScopeModel> {
        let loaded_scope = session
            .services()
            .scope_service()
            .load_scope_by_id(&realm_id, &server_id, &scope_id)
            .await;

        match loaded_scope {
            Ok(idp) => ApiResult::<ScopeModel>::from_option(idp),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_scopes_by_realm(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<Vec<ScopeModel>> {
        let loaded_scopes = session
            .services()
            .scope_service()
            .load_scopes_by_realm_and_server(&realm_id, &server_id)
            .await;

        match loaded_scopes {
            Ok(scopes) => {
                log::info!(
                    "[{}] scopes for server: {} realm: {}",
                    scopes.len(),
                    &server_id,
                    &realm_id
                );
                if scopes.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(scopes)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load scopes for server: {} realm: {}",
                    &server_id,
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn delete_scope_by_id(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> ApiResult<()> {
        let existing_scope = session
            .services()
            .scope_service()
            .load_scope_by_id(&realm_id, &server_id, &scope_id)
            .await;
        if let Ok(response) = existing_scope {
            if response.is_none() {
                log::error!(
                    "scope: {} resource server: {} not found in realm: {}",
                    &scope_id,
                    &server_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "scope not found");
            }
        }
        let deleted_scope = session
            .services()
            .scope_service()
            .delete_scope_by_id(&realm_id, &server_id, &scope_id)
            .await;

        match deleted_scope {
            Err(err) => {
                log::error!(
                    "Failed to delete scope: {}, server: {}, realm: {}. Error: {}",
                    &scope_id,
                    &server_id,
                    &realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to delete scope")
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn create_policy(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        policy: PolicyRepresentation,
    ) -> ApiResult<PolicyModel> {
        let existing_resource_server = session
            .services()
            .resource_server_service()
            .resource_server_exists_by_id(&realm_id, &server_id)
            .await;
        if let Ok(response) = existing_resource_server {
            if !response {
                log::error!(
                    "Resource server: {} does not  exists in realm: {}",
                    &server_id,
                    &realm_id
                );
                return ApiResult::from_error(409, "500", "Resource server does not exists");
            }
        }

        let existing_policy = session
            .services()
            .policy_service()
            .policy_exists_by_name(&realm_id, &server_id, policy.name())
            .await;
        if let Ok(response) = existing_resource_server {
            if response {
                log::error!(
                    "Policy: {} does already exists in realm: {}, server: {}",
                    policy.name(),
                    &realm_id,
                    &server_id
                );
                return ApiResult::from_error(
                    409,
                    "500",
                    format!("Policy: {0} already exists", policy.name()).as_str(),
                );
            }
        }

        let policy_id = uuid::Uuid::new_v4().to_string();

        let parsed_policy_model = AuthorizationModelApi::policy_model_from_representation(
            session, realm_id, server_id, &policy_id, policy,
        )
        .await;
        match parsed_policy_model {
            Ok(policy_model) => {
                let mut policy_model = policy_model;
                policy_model.metadata = AuditableModel::from_creator(
                    session
                        .context()
                        .authenticated_user()
                        .metadata
                        .tenant
                        .to_owned(),
                    session.context().authenticated_user().user_id.to_owned(),
                );
                let res = session
                    .services()
                    .policy_service()
                    .create_policy(&policy_model)
                    .await;
                match res {
                    Ok(_) => ApiResult::Data(policy_model),
                    Err(err) => {
                        log::error!(
                            "Failed to create policy: {}, realm: {}. Error: {}",
                            &policy_model.name,
                            &realm_id,
                            err
                        );
                        ApiResult::from_error(500, "500", "failed to create role")
                    }
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to create policy model from representation. Error: {}",
                    err
                );
                ApiResult::from_error(400, "500", &err)
            }
        }
    }

    async fn policy_model_from_representation(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
        policy: PolicyRepresentation,
    ) -> Result<PolicyModel, String> {
        let mut policy_type: PolicyTypeEnum;
        let mut name: String;
        let mut description: String;
        let mut decision: DecisionStrategyEnum;
        let mut logic: DecisionLogicEnum;
        let mut policy_owner: String;
        let mut configs: Option<std::collections::BTreeMap<String, String>>;
        let mut script: Option<String> = None;
        let mut resource_type: Option<String> = None;

        let mut associated_policies: Option<Vec<PolicyModel>> = None;
        let mut users: Option<Vec<UserModel>> = None;
        let mut roles: Option<Vec<RoleModel>> = None;
        let mut groups: Option<GroupPolicyConfig> = None;
        let mut clients: Option<Vec<ClientModel>> = None;
        let mut scopes: Option<Vec<ScopeModel>> = None;
        let mut resources: Option<Vec<ResourceModel>> = None;
        let mut client_scopes: Option<Vec<ClientScopeModel>> = None;
        let mut regex_config: Option<RegexConfig> = None;
        let mut time_config: Option<TimePolicyConfig> = None;

        match policy {
            PolicyRepresentation::PyPolicy(py_policy) => {
                if py_policy.script.is_empty() {
                    return Err("field script is empty".to_owned());
                }
                script = Some(py_policy.script);
                if let Some(policies_ids) = &py_policy.policies {
                    match AuthorizationModelApi::resolve_associated_policies(
                        &session.services().policy_service(),
                        &realm_id,
                        &server_id,
                        policies_ids,
                    )
                    .await
                    {
                        Ok(res) => associated_policies = Some(res),
                        Err(err) => return Err(err),
                    }
                }

                policy_type = PolicyTypeEnum::PyPolicy;
                name = py_policy.name;
                description = py_policy.description;
                decision = py_policy.decision;
                logic = py_policy.logic;
                policy_owner = py_policy.policy_owner;
                configs = py_policy.configs;
            }
            PolicyRepresentation::UserPolicy(user_policy) => {
                if let Some(policies_ids) = &user_policy.policies {
                    match AuthorizationModelApi::resolve_associated_policies(
                        &session.services().policy_service(),
                        &realm_id,
                        &server_id,
                        policies_ids,
                    )
                    .await
                    {
                        Ok(res) => associated_policies = Some(res),
                        Err(err) => return Err(err),
                    }
                }
                if !user_policy.users.is_empty() {
                    let user_ids: Vec<_> = user_policy.users.iter().map(|s| s.as_str()).collect();
                    match session
                        .services()
                        .user_service()
                        .load_user_by_ids(&realm_id, &user_ids)
                        .await
                    {
                        Ok(res) => users = Some(res),
                        Err(err) => return Err(err),
                    }
                }
                policy_type = PolicyTypeEnum::UserPolicy;
                name = user_policy.name;
                description = user_policy.description;
                decision = user_policy.decision;
                logic = user_policy.logic;
                policy_owner = user_policy.policy_owner;
                configs = user_policy.configs;
            }
            PolicyRepresentation::RolePolicy(role_policy) => {
                if let Some(policies_ids) = &role_policy.policies {
                    match AuthorizationModelApi::resolve_associated_policies(
                        &session.services().policy_service(),
                        &realm_id,
                        &server_id,
                        policies_ids,
                    )
                    .await
                    {
                        Ok(res) => associated_policies = Some(res),
                        Err(err) => return Err(err),
                    }
                }
                if !role_policy.roles.is_empty() {
                    let roles_ids: Vec<_> = role_policy.roles.iter().map(|s| s.as_str()).collect();
                    match session
                        .services()
                        .role_service()
                        .load_role_by_ids(&realm_id, &roles_ids)
                        .await
                    {
                        Ok(res) => {
                            roles = Some(res);
                        }
                        Err(err) => return Err(err),
                    }
                }
                policy_type = PolicyTypeEnum::RolePolicy;
                name = role_policy.name;
                description = role_policy.description;
                decision = role_policy.decision;
                logic = role_policy.logic;
                policy_owner = role_policy.policy_owner;
                configs = role_policy.configs;
            }
            PolicyRepresentation::GroupPolicy(group_policy) => {
                if let Some(policies_ids) = &group_policy.policies {
                    match AuthorizationModelApi::resolve_associated_policies(
                        &session.services().policy_service(),
                        &realm_id,
                        &server_id,
                        policies_ids,
                    )
                    .await
                    {
                        Ok(res) => associated_policies = Some(res),
                        Err(err) => return Err(err),
                    }
                }

                let group_claim = group_policy.group_claim;
                if group_claim.is_empty() {
                    return Err("field group_claim is empty".to_owned());
                }
                let mut loaded_groups: Vec<GroupModel> = Vec::new();
                if !group_policy.groups.is_empty() {
                    let group_ids: Vec<_> =
                        group_policy.groups.iter().map(|s| s.as_str()).collect();

                    match session
                        .services()
                        .group_service()
                        .load_group_by_ids(&realm_id, &group_ids)
                        .await
                    {
                        Ok(res) => loaded_groups = res,
                        Err(err) => return Err(err),
                    }
                }
                groups = Some(GroupPolicyConfig {
                    group_claim: group_claim,
                    groups: loaded_groups,
                });

                policy_type = PolicyTypeEnum::GroupPolicy;
                name = group_policy.name;
                description = group_policy.description;
                decision = group_policy.decision;
                logic = group_policy.logic;
                policy_owner = group_policy.policy_owner;
                configs = group_policy.configs;
            }
            PolicyRepresentation::ClientPolicy(client_policy) => {
                if let Some(policies_ids) = &client_policy.policies {
                    match AuthorizationModelApi::resolve_associated_policies(
                        &session.services().policy_service(),
                        &realm_id,
                        &server_id,
                        policies_ids,
                    )
                    .await
                    {
                        Ok(res) => associated_policies = Some(res),
                        Err(err) => return Err(err),
                    }
                }

                if !client_policy.clients.is_empty() {
                    let clients_ids: Vec<_> =
                        client_policy.clients.iter().map(|s| s.as_str()).collect();

                    match session
                        .services()
                        .client_service()
                        .load_client_by_ids(&realm_id, &clients_ids)
                        .await
                    {
                        Ok(res) => clients = Some(res),
                        Err(err) => return Err(err),
                    }
                }
                policy_type = PolicyTypeEnum::ClientPolicy;
                name = client_policy.name;
                description = client_policy.description;
                decision = client_policy.decision;
                logic = client_policy.logic;
                policy_owner = client_policy.policy_owner;
                configs = client_policy.configs;
            }
            PolicyRepresentation::ClientScopePolicy(client_scope_policy) => {
                if let Some(policies_ids) = &client_scope_policy.policies {
                    match AuthorizationModelApi::resolve_associated_policies(
                        &session.services().policy_service(),
                        &realm_id,
                        &server_id,
                        policies_ids,
                    )
                    .await
                    {
                        Ok(res) => associated_policies = Some(res),
                        Err(err) => return Err(err),
                    }
                }

                if !client_scope_policy.client_scopes.is_empty() {
                    let client_scope_ids: Vec<_> = client_scope_policy
                        .client_scopes
                        .iter()
                        .map(|s| s.as_str())
                        .collect();
                    match session
                        .services()
                        .client_scope_service()
                        .load_client_scopes_by_ids(&realm_id, &client_scope_ids)
                        .await
                    {
                        Ok(res) => client_scopes = Some(res),
                        Err(err) => return Err(err),
                    }
                }
                policy_type = PolicyTypeEnum::ClientScopePolicy;
                name = client_scope_policy.name;
                description = client_scope_policy.description;
                decision = client_scope_policy.decision;
                logic = client_scope_policy.logic;
                policy_owner = client_scope_policy.policy_owner;
                configs = client_scope_policy.configs;
            }
            PolicyRepresentation::AggregatedPolicy(aggregated_policy) => {
                if let Some(policies_ids) = &aggregated_policy.policies {
                    match AuthorizationModelApi::resolve_associated_policies(
                        &session.services().policy_service(),
                        &realm_id,
                        &server_id,
                        policies_ids,
                    )
                    .await
                    {
                        Ok(res) => associated_policies = Some(res),
                        Err(err) => return Err(err),
                    }
                }
                policy_type = PolicyTypeEnum::AggregatedPolicy;
                name = aggregated_policy.name;
                description = aggregated_policy.description;
                decision = aggregated_policy.decision;
                logic = aggregated_policy.logic;
                policy_owner = aggregated_policy.policy_owner;
                configs = aggregated_policy.configs;
            }
            PolicyRepresentation::RegexPolicy(regex_policy) => {
                if let Some(policies_ids) = &regex_policy.policies {
                    match AuthorizationModelApi::resolve_associated_policies(
                        &session.services().policy_service(),
                        &realm_id,
                        &server_id,
                        policies_ids,
                    )
                    .await
                    {
                        Ok(res) => associated_policies = Some(res),
                        Err(err) => return Err(err),
                    }
                }
                if regex_policy.target_regex.is_empty() {
                    return Err("field target_regex is empty".to_owned());
                }
                if regex_policy.target_claim.is_empty() {
                    return Err("field target_claim is empty".to_owned());
                }

                regex_config = Some(RegexConfig {
                    target_regex: regex_policy.target_regex.clone(),
                    target_claim: regex_policy.target_claim.clone(),
                });
                policy_type = PolicyTypeEnum::RegexPolicy;
                name = regex_policy.name;
                description = regex_policy.description;
                decision = regex_policy.decision;
                logic = regex_policy.logic;
                policy_owner = regex_policy.policy_owner;
                configs = regex_policy.configs;
            }
            PolicyRepresentation::TimePolicy(time_policy) => {
                if let Some(policies_ids) = &time_policy.policies {
                    match AuthorizationModelApi::resolve_associated_policies(
                        &session.services().policy_service(),
                        &realm_id,
                        &server_id,
                        policies_ids,
                    )
                    .await
                    {
                        Ok(res) => associated_policies = Some(res),
                        Err(err) => return Err(err),
                    }
                }

                let check_integer_value = |name: &str,
                                           value: u64,
                                           lower_bound: u64,
                                           higher_bound: u64|
                 -> Result<(), String> {
                    if value < lower_bound || value > higher_bound {
                        return Err(format!(
                            "{} out off bound [{}-{}]",
                            value, lower_bound, higher_bound
                        ));
                    }
                    Ok(())
                };

                if let Some(day_of_month) = time_policy.day_of_month {
                    check_integer_value("day_of_month", day_of_month, 1, 31)?
                }
                if let Some(day_of_month_end) = time_policy.day_of_month_end {
                    check_integer_value("day_of_month_end", day_of_month_end, 1, 31)?
                }
                if let Some(month) = time_policy.month {
                    check_integer_value("month", month, 1, 12)?
                }
                if let Some(month_end) = time_policy.month_end {
                    check_integer_value("month_end", month_end, 1, 12)?
                }
                if let Some(year) = time_policy.year {
                    check_integer_value("year", year, 1, 9999)?
                }
                if let Some(year_end) = time_policy.year_end {
                    check_integer_value("year_end", year_end, 1, 9999)?
                }
                if let Some(hour) = time_policy.hour {
                    check_integer_value("hour", hour, 1, 23)?
                }
                if let Some(hour_end) = time_policy.hour_end {
                    check_integer_value("hour_end", hour_end, 1, 23)?
                }
                if let Some(minute) = time_policy.minute {
                    check_integer_value("minute", minute, 1, 59)?
                }
                if let Some(minute_end) = time_policy.minute_end {
                    check_integer_value("minute_end", minute_end, 1, 59)?
                }
                time_config = Some(TimePolicyConfig {
                    not_before_time: time_policy.not_before_time,
                    not_on_or_after_time: time_policy.not_on_or_after_time,
                    year: time_policy.year,
                    year_end: time_policy.year_end,
                    month: time_policy.month,
                    month_end: time_policy.month_end,
                    day_of_month: time_policy.day_of_month,
                    day_of_month_end: time_policy.day_of_month_end,
                    hour: time_policy.hour,
                    hour_end: time_policy.hour_end,
                    minute: time_policy.minute,
                    minute_end: time_policy.minute_end,
                });
                policy_type = PolicyTypeEnum::TimePolicy;
                name = time_policy.name;
                description = time_policy.description;
                decision = time_policy.decision;
                logic = time_policy.logic;
                policy_owner = time_policy.policy_owner;
                configs = time_policy.configs;
            }
            PolicyRepresentation::ScopePermissionPolicy(scope_policy) => {
                if scope_policy.resource_type.is_empty() {
                    return Err("field resource_type is empty".to_owned());
                }
                resource_type = Some(scope_policy.resource_type.clone());
                if let Some(policies_ids) = &scope_policy.policies {
                    match AuthorizationModelApi::resolve_associated_policies(
                        &session.services().policy_service(),
                        &realm_id,
                        &server_id,
                        policies_ids,
                    )
                    .await
                    {
                        Ok(res) => associated_policies = Some(res),
                        Err(err) => return Err(err),
                    }
                }

                if let Some(scopes_ids) = scope_policy.scopes {
                    let scope_ids: Vec<_> = scopes_ids.iter().map(|s| s.as_str()).collect();
                    match session
                        .services()
                        .scope_service()
                        .load_scopes_by_ids(&realm_id, &scope_ids)
                        .await
                    {
                        Ok(res) => scopes = Some(res),
                        Err(err) => return Err(err),
                    }
                }
                policy_type = PolicyTypeEnum::ScopePermission;
                name = scope_policy.name;
                description = scope_policy.description;
                decision = scope_policy.decision;
                logic = scope_policy.logic;
                policy_owner = scope_policy.policy_owner;
                configs = scope_policy.configs;
            }
            PolicyRepresentation::ResourcePermissionPolicy(resource_policy) => {
                if resource_policy.resource_type.is_empty() {
                    return Err("field resource_type is empty".to_owned());
                }
                resource_type = Some(resource_policy.resource_type.clone());

                if let Some(policies_ids) = &resource_policy.policies {
                    match AuthorizationModelApi::resolve_associated_policies(
                        &session.services().policy_service(),
                        &realm_id,
                        &server_id,
                        policies_ids,
                    )
                    .await
                    {
                        Ok(res) => associated_policies = Some(res),
                        Err(err) => return Err(err),
                    }
                }

                if let Some(resources_ids) = resource_policy.resources {
                    let resources_ids: Vec<_> = resources_ids.iter().map(|s| s.as_str()).collect();

                    match session
                        .services()
                        .resource_service()
                        .load_resources_by_ids(&realm_id, &resources_ids)
                        .await
                    {
                        Ok(res) => resources = Some(res),
                        Err(err) => return Err(err),
                    }
                }
                policy_type = PolicyTypeEnum::ResourcePermission;
                name = resource_policy.name;
                description = resource_policy.description;
                decision = resource_policy.decision;
                logic = resource_policy.logic;
                policy_owner = resource_policy.policy_owner;
                configs = resource_policy.configs;
            }
            _ => return Err("Unsupported policy type".to_owned()),
        }

        let policy = PolicyModel {
            policy_id: policy_id.to_owned(),
            server_id: server_id.to_owned(),
            realm_id: realm_id.to_owned(),
            policy_type: policy_type,
            name: name,
            description: description,
            decision: decision,
            logic: logic,
            policy_owner: policy_owner,
            configs: configs,
            policies: associated_policies,
            resources: resources,
            scopes: scopes,
            roles: roles,
            groups: groups,
            regex: regex_config,
            time: time_config,
            users: users,
            script: script,
            client_scopes: client_scopes,
            clients: clients,
            resource_type: None,
            metadata: AuditableModel::default(),
        };
        Ok(policy)
    }

    async fn resolve_associated_policies(
        policy_service: &Arc<dyn IPolicyService>,
        realm_id: &str,
        server_id: &str,
        policies_ids: &Vec<String>,
    ) -> Result<Vec<PolicyModel>, String> {
        let params: Vec<_> = policies_ids.iter().map(|s| s.as_str()).collect();
        let loaded_policies = policy_service
            .load_policy_by_ids(realm_id, server_id, &params)
            .await;
        match loaded_policies {
            Ok(plcs) => {
                if plcs.len() != policies_ids.len() {
                    return Err("missing policies".to_owned());
                }
                return Ok(plcs);
            }
            Err(err) => return Err(err),
        }
    }

    pub async fn update_policy(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
        policy: PolicyRepresentation,
    ) -> ApiResult<PolicyModel> {
        let existing_resource_server = session
            .services()
            .resource_server_service()
            .resource_server_exists_by_id(&realm_id, &server_id)
            .await;
        if let Ok(response) = existing_resource_server {
            if !response {
                log::error!(
                    "Resource server: {} does not  exists in realm: {}",
                    &policy.name(),
                    &realm_id
                );
                return ApiResult::from_error(409, "500", "Resource server does not exists");
            }
        }

        let existing_policy = session
            .services()
            .policy_service()
            .policy_exists_by_id(&realm_id, &server_id, &policy_id)
            .await;
        if let Ok(response) = existing_resource_server {
            if !response {
                log::error!(
                    "Policy: {} does not exists in realm: {}, server: {}",
                    &policy_id,
                    &realm_id,
                    &server_id
                );
                return ApiResult::from_error(
                    409,
                    "500",
                    format!("Policy: {0} does not exists", policy.name()).as_str(),
                );
            }
        }

        let parsed_policy_model = AuthorizationModelApi::policy_model_from_representation(
            session, realm_id, server_id, &policy_id, policy,
        )
        .await;
        match parsed_policy_model {
            Ok(policy_model) => {
                let mut policy_model = policy_model;
                policy_model.metadata = AuditableModel::from_updator(
                    session
                        .context()
                        .authenticated_user()
                        .metadata
                        .tenant
                        .to_owned(),
                    session.context().authenticated_user().user_id.to_owned(),
                );
                let res = session
                    .services()
                    .policy_service()
                    .udpate_policy(&policy_model)
                    .await;
                match res {
                    Ok(_) => ApiResult::no_content(),
                    Err(err) => {
                        log::error!(
                            "Failed to update policy: {} realm: {}. Error: {}",
                            &policy_model.name,
                            &realm_id,
                            err
                        );
                        ApiResult::from_error(500, "500", "failed to update role")
                    }
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to update policy model from representation. Error: {}",
                    err
                );
                ApiResult::from_error(400, "500", &err)
            }
        }
    }

    pub async fn load_policy_by_id(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> ApiResult<PolicyModel> {
        let loaded_policy = session
            .services()
            .policy_service()
            .load_policy_by_id(&realm_id, &server_id, &policy_id)
            .await;

        match loaded_policy {
            Ok(policy) => ApiResult::<PolicyModel>::from_option(policy),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_policy_scopes_by_policy_id(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> ApiResult<Vec<ScopeModel>> {
        let loaded_policy_scopes = session
            .services()
            .policy_service()
            .load_policy_scopes_by_id(&realm_id, &server_id, &policy_id)
            .await;

        match loaded_policy_scopes {
            Ok(scopes) => {
                log::info!(
                    "[{}] scopes loaded for policy: {} ,server: {} realm: {}",
                    scopes.len(),
                    &policy_id,
                    &server_id,
                    &realm_id
                );
                if scopes.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(scopes)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load scopes for policy: {} ,server: {} realm: {}",
                    &policy_id,
                    &server_id,
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn load_policy_resources_by_policy_id(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> ApiResult<Vec<ResourceModel>> {
        let loaded_resources = session
            .services()
            .policy_service()
            .load_policy_resources_by_id(&realm_id, &server_id, &policy_id)
            .await;

        match loaded_resources {
            Ok(resources) => {
                log::info!(
                    "[{}] resources loaded for policy: {} server: {} realm: {}",
                    resources.len(),
                    &policy_id,
                    &server_id,
                    &realm_id
                );
                if resources.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(resources)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load resources for policy: {} server: {} realm: {}",
                    &policy_id,
                    &server_id,
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn load_associates_policies_by_policy_id(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> ApiResult<Vec<PolicyModel>> {
        let loaded_associated_policies = session
            .services()
            .policy_service()
            .load_associated_policies_by_policy_id(&realm_id, &server_id, &policy_id)
            .await;

        match loaded_associated_policies {
            Ok(resources) => {
                log::info!(
                    "[{}] associated policies loaded for policy: {} server: {} realm: {}",
                    resources.len(),
                    &policy_id,
                    &server_id,
                    &realm_id
                );
                if resources.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(resources)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load associated policies for policy: {} server: {} realm: {}",
                    &policy_id,
                    &server_id,
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn load_policies_by_server_id(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<Vec<PolicyModel>> {
        let loaded_policies = session
            .services()
            .policy_service()
            .load_policies_by_server_id(&realm_id, &server_id)
            .await;

        match loaded_policies {
            Ok(resources) => {
                log::info!(
                    "[{}] policies loaded for  server: {} realm: {}",
                    resources.len(),
                    &server_id,
                    &realm_id
                );
                if resources.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(resources)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load policies for server: {} realm: {}",
                    &server_id,
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn count_policies_by_query(
        session: &DarkshieldSession,
        realm_id: &str,
        count_query: &str,
    ) -> ApiResult<u64> {
        let count_policies_result = session
            .services()
            .policy_service()
            .count_policies(&realm_id, &count_query)
            .await;

        match count_policies_result {
            Ok(res) => ApiResult::<u64>::from_data(res),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn search_policies_by_query(
        session: &DarkshieldSession,
        realm_id: &str,
        search_query: &str,
    ) -> ApiResult<Vec<PolicyModel>> {
        let loaded_policies = session
            .services()
            .policy_service()
            .search_policies(&realm_id, &search_query)
            .await;

        match loaded_policies {
            Ok(resources) => {
                log::info!(
                    "[{}] policies loaded for realm: {}",
                    resources.len(),
                    &realm_id
                );
                if resources.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(resources)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load policies for realm: {} and query: {}",
                    &realm_id,
                    &search_query,
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn delete_policy_by_id(
        session: &DarkshieldSession,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> ApiResult {
        let existing_resource_server = session
            .services()
            .resource_server_service()
            .resource_server_exists_by_id(&realm_id, &server_id)
            .await;
        if let Ok(response) = existing_resource_server {
            if !response {
                log::error!(
                    "Resource server: {} does not  exists in realm: {}",
                    &policy_id,
                    &realm_id
                );
                return ApiResult::from_error(409, "500", "Resource server does not exists");
            }
        }

        let existing_policy = session
            .services()
            .policy_service()
            .policy_exists_by_id(&realm_id, &server_id, &policy_id)
            .await;
        if let Ok(response) = existing_policy {
            if !response {
                log::error!(
                    "Policy: {} does not exists in realm: {}, server: {}",
                    &policy_id,
                    &realm_id,
                    &server_id
                );
                return ApiResult::from_error(
                    404,
                    "500",
                    format!("Policy: {0} does not exists", policy_id).as_str(),
                );
            }
        }

        let deleted_policy = session
            .services()
            .policy_service()
            .delete_policy_by_id(&realm_id, &server_id, &policy_id)
            .await;
        match deleted_policy {
            Ok(_) => ApiResult::no_content(),
            Err(err) => ApiResult::from_error(404, "500", &err),
        }
    }
}
