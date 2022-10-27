use crate::context::DarkShieldContext;
use commons::ApiResult;
use log;
use uuid;

use models::{
    auditable::AuditableModel,
    entities::authz::{
        GroupModel, IdentityProviderModel, PolicyModel, PolicyRepresentation, ResourceModel,
        ResourceServerModel, RoleModel, ScopeModel,
    },
};
use services::services::authz_services::{
    IGroupService, IIdentityProviderService, IResourceServerService, IResourceService,
    IRoleService, IScopeService,
};
use shaku::HasComponent;
pub struct AuthorizationModelApi;

impl AuthorizationModelApi {
    pub async fn create_role(context: &DarkShieldContext, role: RoleModel) -> ApiResult<RoleModel> {
        let role_service: &dyn IRoleService = context.services().resolve_ref();
        let existing_role = role_service
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
        role.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_role = role_service.create_role(&role).await;
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

    pub async fn update_role(context: &DarkShieldContext, role: RoleModel) -> ApiResult<()> {
        let role_service: &dyn IRoleService = context.services().resolve_ref();

        let existing_role = role_service
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
        role.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_role = role_service.update_role(&role).await;
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
        context: &DarkShieldContext,
        realm_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let role_service: &dyn IRoleService = context.services().resolve_ref();

        let existing_role = role_service.load_role_by_id(&realm_id, &role_id).await;
        if let Ok(response) = existing_role {
            if response.is_none() {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id);
                return ApiResult::from_error(404, "404", "role not found");
            }
        }
        let deleted_role = role_service.delete_role(&realm_id, &role_id).await;
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
        context: &DarkShieldContext,
        realm_id: &str,
        role_id: &str,
    ) -> ApiResult<RoleModel> {
        let role_service: &dyn IRoleService = context.services().resolve_ref();
        let loaded_role = role_service.load_role_by_id(&realm_id, &role_id).await;
        match loaded_role {
            Ok(role) => ApiResult::<RoleModel>::from_option(role),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_roles_by_realm(
        context: &DarkShieldContext,
        realm_id: &str,
    ) -> ApiResult<Vec<RoleModel>> {
        let role_service: &dyn IRoleService = context.services().resolve_ref();

        let loaded_roles = role_service.load_roles_by_realm(&realm_id).await;
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
        context: &DarkShieldContext,
        realm_id: &str,
    ) -> ApiResult<i64> {
        let role_service: &dyn IRoleService = context.services().resolve_ref();
        let response = role_service.count_roles_by_realm(&realm_id).await;
        match response {
            Ok(count) => ApiResult::from_data(count),
            Err(err) => {
                log::error!("Failed to count roles. Error: {}", err);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn create_group(
        context: &DarkShieldContext,
        group: GroupModel,
    ) -> ApiResult<GroupModel> {
        let group_service: &dyn IGroupService = context.services().resolve_ref();
        let existing_group = group_service
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
        group.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_group = group_service.create_group(&group).await;
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

    pub async fn udpate_group(context: &DarkShieldContext, group: GroupModel) -> ApiResult<()> {
        let group_service: &dyn IGroupService = context.services().resolve_ref();

        let existing_group = group_service
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
        group.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_group = group_service.udpate_group(&group).await;
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
        context: &DarkShieldContext,
        realm_id: &str,
        group_id: &str,
    ) -> ApiResult<()> {
        let group_service: &dyn IGroupService = context.services().resolve_ref();

        let existing_group = group_service.load_group_by_id(&realm_id, &group_id).await;
        if let Ok(response) = existing_group {
            if response.is_none() {
                log::error!("group: {} not found in realm: {}", &group_id, &realm_id);
                return ApiResult::from_error(404, "404", "role not found");
            }
        }
        let result = group_service.delete_group(&realm_id, &group_id).await;
        match result {
            Err(_) => ApiResult::from_error(500, "500", "failed to update role"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn load_group_by_id(
        context: &DarkShieldContext,
        realm_id: &str,
        group_id: &str,
    ) -> ApiResult<GroupModel> {
        let group_service: &dyn IGroupService = context.services().resolve_ref();

        let loaded_group = group_service.load_group_by_id(&realm_id, &group_id).await;
        match loaded_group {
            Ok(group) => ApiResult::<GroupModel>::from_option(group),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_groups_by_realm(
        context: &DarkShieldContext,
        realm_id: &str,
    ) -> ApiResult<Vec<GroupModel>> {
        let group_service: &dyn IGroupService = context.services().resolve_ref();
        let loaded_groups = group_service.load_groups_by_realm(&realm_id).await;
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

    pub async fn count_groups(context: &DarkShieldContext, realm_id: &str) -> ApiResult<i64> {
        let group_service: &dyn IGroupService = context.services().resolve_ref();

        let response = group_service.count_groups(&realm_id).await;
        match response {
            Ok(count) => ApiResult::from_data(count),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn add_group_role(
        context: &DarkShieldContext,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let role_service: &dyn IRoleService = context.services().resolve_ref();
        let group_service: &dyn IGroupService = context.services().resolve_ref();

        let existing_group = group_service
            .exists_groups_by_id(&realm_id, &group_id)
            .await;
        if let Ok(response) = existing_group {
            if !response {
                log::error!("group: {} not found in realm: {}", group_id, realm_id);
                return ApiResult::from_error(409, "404", "group not found");
            }
        }

        let existing_role = role_service.role_exists_by_id(&realm_id, &role_id).await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "role not found");
            }
        }

        let response = group_service
            .add_group_role(&realm_id, &group_id, &role_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add role to group"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn remove_group_role(
        context: &DarkShieldContext,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let role_service: &dyn IRoleService = context.services().resolve_ref();
        let group_service: &dyn IGroupService = context.services().resolve_ref();

        let existing_group = group_service
            .exists_groups_by_id(&realm_id, &group_id)
            .await;
        if let Ok(response) = existing_group {
            if !response {
                log::error!("group: {} not found in realm: {}", group_id, realm_id);
                return ApiResult::from_error(409, "404", "group not found");
            }
        }

        let existing_role = role_service.role_exists_by_id(&realm_id, &role_id).await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "role not found");
            }
        }

        let response = group_service
            .remove_group_role(&realm_id, &group_id, &role_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to remove role from group"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn create_identity_provider(
        context: &DarkShieldContext,
        idp: IdentityProviderModel,
    ) -> ApiResult<IdentityProviderModel> {
        let identity_provider_service: &dyn IIdentityProviderService =
            context.services().resolve_ref();

        let existing_idp = identity_provider_service
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
        idp.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_idp = identity_provider_service
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
        context: &DarkShieldContext,
        idp: IdentityProviderModel,
    ) -> ApiResult<()> {
        let identity_provider_service: &dyn IIdentityProviderService =
            context.services().resolve_ref();

        let existing_idp = identity_provider_service
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
                let has_alias = identity_provider_service
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
        idp.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_idp = identity_provider_service
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
        context: &DarkShieldContext,
        realm_id: &str,
        internal_id: &str,
    ) -> ApiResult<IdentityProviderModel> {
        let identity_provider_service: &dyn IIdentityProviderService =
            context.services().resolve_ref();

        let loaded_idp = identity_provider_service
            .load_identity_provider_by_internal_id(&realm_id, &internal_id)
            .await;
        match loaded_idp {
            Ok(idp) => ApiResult::<IdentityProviderModel>::from_option(idp),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_identity_providers_by_realm(
        context: &DarkShieldContext,
        realm_id: &str,
    ) -> ApiResult<Vec<IdentityProviderModel>> {
        let identity_provider_service: &dyn IIdentityProviderService =
            context.services().resolve_ref();

        let loaded_idps = identity_provider_service
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
        context: &DarkShieldContext,
        realm_id: &str,
        internal_id: &str,
    ) -> ApiResult<()> {
        let identity_provider_service: &dyn IIdentityProviderService =
            context.services().resolve_ref();

        let existing_idp = identity_provider_service
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

        let updated_idp = identity_provider_service
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
        context: &DarkShieldContext,
        realm_id: &str,
        alias: &str,
    ) -> ApiResult<bool> {
        let identity_provider_service: &dyn IIdentityProviderService =
            context.services().resolve_ref();
        let existing_idp = identity_provider_service
            .exists_by_alias(&realm_id, &alias)
            .await;
        match existing_idp {
            Ok(res) => ApiResult::Data(res),
            _ => ApiResult::from_error(500, "500", "failed check identity provider"),
        }
    }

    pub async fn create_resource_server(
        context: &DarkShieldContext,
        server: ResourceServerModel,
    ) -> ApiResult<ResourceServerModel> {
        let resource_server_server: &dyn IResourceServerService = context.services().resolve_ref();

        let existing_resource_server = resource_server_server
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
        server.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_role = resource_server_server.create_resource_server(&server).await;
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
        context: &DarkShieldContext,
        server: ResourceServerModel,
    ) -> ApiResult<()> {
        let resource_server_server: &dyn IResourceServerService = context.services().resolve_ref();

        let existing_resource_server = resource_server_server
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
                let server_with_name = resource_server_server
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
        server.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_idp = resource_server_server.udpate_resource_server(&server).await;
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
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<ResourceServerModel> {
        let resource_server_server: &dyn IResourceServerService = context.services().resolve_ref();
        let loaded_resource_server = resource_server_server
            .load_resource_server_by_id(&realm_id, &server_id)
            .await;

        match loaded_resource_server {
            Ok(idp) => ApiResult::<ResourceServerModel>::from_option(idp),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_resource_servers_by_realm(
        context: &DarkShieldContext,
        realm_id: &str,
    ) -> ApiResult<Vec<ResourceServerModel>> {
        let resource_server_server: &dyn IResourceServerService = context.services().resolve_ref();

        let loaded_servers = resource_server_server
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
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<()> {
        let resource_server_server: &dyn IResourceServerService = context.services().resolve_ref();

        let existing_server = resource_server_server
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

        let updated_server = resource_server_server
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
        context: &DarkShieldContext,
        resource: ResourceModel,
    ) -> ApiResult<ResourceModel> {
        let resource_service: &dyn IResourceService = context.services().resolve_ref();
        let existing_resource = resource_service
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
        resource.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_resource = resource_service.create_resource(&resource).await;
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
        context: &DarkShieldContext,
        resource: ResourceModel,
    ) -> ApiResult<()> {
        let resource_service: &dyn IResourceService = context.services().resolve_ref();
        let existing_resource = resource_service
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
                let resource_with_name = resource_service
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
        resource.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_resource = resource_service.udpate_resource(&resource).await;
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
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> ApiResult<ResourceModel> {
        let resource_service: &dyn IResourceService = context.services().resolve_ref();

        let loaded_resource = resource_service
            .load_resource_by_id(&realm_id, &server_id, &resource_id)
            .await;

        match loaded_resource {
            Ok(resource) => ApiResult::<ResourceModel>::from_option(resource),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_resources_by_server(
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<Vec<ResourceModel>> {
        let resource_service: &dyn IResourceService = context.services().resolve_ref();
        let loaded_resources = resource_service
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
        context: &DarkShieldContext,
        realm_id: &str,
    ) -> ApiResult<Vec<ResourceModel>> {
        let resource_service: &dyn IResourceService = context.services().resolve_ref();
        let loaded_resources = resource_service.load_resources_by_realm(&realm_id).await;

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
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> ApiResult<()> {
        let resource_service: &dyn IResourceService = context.services().resolve_ref();

        let existing_resource = resource_service
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
        let updated_resource = resource_service
            .delete_resource_by_id(&realm_id, &server_id, &resource_id)
            .await;

        match updated_resource {
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
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> ApiResult<()> {
        let resource_service: &dyn IResourceService = context.services().resolve_ref();
        let scope_service: &dyn IScopeService = context.services().resolve_ref();

        let existing_resource = resource_service
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

        let existing_scope = scope_service
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

        let response = resource_service
            .add_resource_scope(&realm_id, &server_id, &resource_id, &scope_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add scope to resource"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn remove_resource_scope(
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> ApiResult<()> {
        let resource_service: &dyn IResourceService = context.services().resolve_ref();
        let scope_service: &dyn IScopeService = context.services().resolve_ref();

        let existing_resource = resource_service
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

        let existing_scope = scope_service
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

        let response = resource_service
            .remove_resource_scope(&realm_id, &server_id, &resource_id, &scope_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add scope to resource"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn create_scope(
        context: &DarkShieldContext,
        scope: ScopeModel,
    ) -> ApiResult<ScopeModel> {
        let resource_server_service: &dyn IResourceServerService = context.services().resolve_ref();
        let scope_service: &dyn IScopeService = context.services().resolve_ref();

        let existing_resource_server = resource_server_service
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

        let existing_scope = scope_service
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
        scope.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_scope = scope_service.create_scope(&scope).await;
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

    pub async fn udpate_scope(context: &DarkShieldContext, scope: ScopeModel) -> ApiResult<()> {
        let resource_server_service: &dyn IResourceServerService = context.services().resolve_ref();
        let scope_service: &dyn IScopeService = context.services().resolve_ref();

        let existing_resource_server = resource_server_service
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

        let existing_scope = scope_service
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
        scope.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());

        let updated_scope = scope_service.udpate_scope(&scope).await;
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
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> ApiResult<ScopeModel> {
        let scope_service: &dyn IScopeService = context.services().resolve_ref();
        let loaded_scope = scope_service
            .load_scope_by_id(&realm_id, &server_id, &scope_id)
            .await;

        match loaded_scope {
            Ok(idp) => ApiResult::<ScopeModel>::from_option(idp),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_scopes_by_realm(
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<Vec<ScopeModel>> {
        let scope_service: &dyn IScopeService = context.services().resolve_ref();
        let loaded_scopes = scope_service
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
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> ApiResult<()> {
        let scope_service: &dyn IScopeService = context.services().resolve_ref();
        let existing_scope = scope_service
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
        let deleted_scope = scope_service
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
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        policy: &PolicyRepresentation,
    ) -> ApiResult<PolicyModel> {
        todo!()
    }

    pub async fn update_policy(
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
        policy: &PolicyRepresentation,
    ) -> ApiResult<PolicyModel> {
        todo!()
    }

    pub async fn load_policy_by_id(
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> ApiResult<PolicyModel> {
        todo!()
    }

    pub async fn load_policy_scopes_by_policy_id(
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> ApiResult<Vec<PolicyModel>> {
        todo!()
    }

    pub async fn load_policy_resources_by_policy_id(
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> ApiResult<Vec<PolicyModel>> {
        todo!()
    }

    pub async fn load_associates_policies_by_policy_id(
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> ApiResult<Vec<PolicyModel>> {
        todo!()
    }

    pub async fn load_policies_by_server_id(
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<Vec<PolicyModel>> {
        todo!()
    }

    pub async fn count_policies_by_query(
        context: &DarkShieldContext,
        realm_id: &str,
        count_query: &str,
    ) -> ApiResult<u64> {
        todo!()
    }

    pub async fn search_policies_by_query(
        context: &DarkShieldContext,
        realm_id: &str,
        search_query: &str,
    ) -> ApiResult<Vec<PolicyModel>> {
        todo!()
    }

    pub async fn delete_policy_by_id(
        context: &DarkShieldContext,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> ApiResult<Vec<PolicyModel>> {
        todo!()
    }
}
