use async_trait::async_trait;
use commons::ApiResult;
use log;
use models::auditable::AuditableModel;
use models::entities::authz::*;
use shaku::Component;
use shaku::Interface;
use std::sync::Arc;
use store::providers::interfaces::authz_provider::IGroupProvider;
use store::providers::interfaces::authz_provider::IIdentityProvider;
use store::providers::interfaces::authz_provider::IResourceProvider;
use store::providers::interfaces::authz_provider::IResourceServerProvider;
use store::providers::interfaces::authz_provider::IRoleProvider;
use store::providers::interfaces::authz_provider::IScopeProvider;
use uuid;

#[async_trait]
pub trait IRoleService: Interface {
    async fn create_role(&self, realm: RoleModel) -> ApiResult<RoleModel>;
    async fn update_role(&self, realm: RoleModel) -> ApiResult<()>;
    async fn delete_role(&self, realm_id: &str, role_id: &str) -> ApiResult<()>;
    async fn load_role_by_id(&self, realm_id: &str, role_id: &str) -> ApiResult<RoleModel>;
    async fn load_roles_by_realm(&self, realm_id: &str) -> ApiResult<Vec<RoleModel>>;
    async fn count_roles_by_realm(&self, realm_id: &str) -> ApiResult<i64>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRoleService)]
pub struct RoleService {
    #[shaku(inject)]
    role_provider: Arc<dyn IRoleProvider>,
}

#[async_trait]
impl IRoleService for RoleService {
    async fn create_role(&self, role: RoleModel) -> ApiResult<RoleModel> {
        let existing_role = self
            .role_provider
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
        let created_role = self.role_provider.create_role(&role).await;
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

    async fn update_role(&self, role: RoleModel) -> ApiResult<()> {
        let existing_role = self
            .role_provider
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
        let updated_role = self.role_provider.update_role(&role).await;
        match updated_role {
            Ok(_) => ApiResult::no_content(),
            Err(err) => {
                log::error!(
                    "Failed to update role: {}, realm: {}. Error: {}",
                    &role.role_id,
                    &role.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update role")
            }
        }
    }

    async fn delete_role(&self, realm_id: &str, role_id: &str) -> ApiResult<()> {
        let existing_role = self
            .role_provider
            .load_role_by_id(&realm_id, &role_id)
            .await;
        if let Ok(response) = existing_role {
            if response.is_none() {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id);
                return ApiResult::from_error(404, "404", "role not found");
            }
        }
        let deleted_role = self.role_provider.delete_role(&realm_id, &role_id).await;
        match deleted_role {
            Ok(_) => ApiResult::no_content(),
            Err(err) => {
                log::error!(
                    "Failed to delete role: {}, realm: {}. Error: {}",
                    &role_id,
                    &realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update role")
            }
        }
    }

    async fn load_role_by_id(&self, realm_id: &str, role_id: &str) -> ApiResult<RoleModel> {
        let loaded_role = self
            .role_provider
            .load_role_by_id(&realm_id, &role_id)
            .await;
        match loaded_role {
            Ok(role) => ApiResult::<RoleModel>::from_option(role),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn load_roles_by_realm(&self, realm_id: &str) -> ApiResult<Vec<RoleModel>> {
        let loaded_roles = self.role_provider.load_roles_by_realm(&realm_id).await;
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

    async fn count_roles_by_realm(&self, realm_id: &str) -> ApiResult<i64> {
        let response = self.role_provider.count_roles(&realm_id).await;
        match response {
            Ok(count) => ApiResult::from_data(count),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }
}

#[async_trait]
pub trait IGroupService: Interface {
    async fn create_group(&self, group: GroupModel) -> ApiResult<GroupModel>;
    async fn udpate_group(&self, group: GroupModel) -> ApiResult<()>;
    async fn delete_group(&self, realm_id: &str, group_id: &str) -> ApiResult<()>;
    async fn load_group_by_id(&self, realm_id: &str, group_id: &str) -> ApiResult<GroupModel>;
    async fn load_groups_by_realm(&self, realm_id: &str) -> ApiResult<Vec<GroupModel>>;
    async fn count_groups(&self, realm_id: &str) -> ApiResult<i64>;
    async fn add_group_role(&self, realm_id: &str, group_id: &str, role_id: &str) -> ApiResult<()>;
    async fn remove_group_role(
        &self,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> ApiResult<()>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IGroupService)]
pub struct GroupService {
    #[shaku(inject)]
    group_provider: Arc<dyn IGroupProvider>,
    #[shaku(inject)]
    role_provider: Arc<dyn IRoleProvider>,
}

#[async_trait]
impl IGroupService for GroupService {
    async fn create_group(&self, group: GroupModel) -> ApiResult<GroupModel> {
        let existing_group = self
            .group_provider
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
        let created_group = self.group_provider.create_group(&group).await;
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

    async fn udpate_group(&self, group: GroupModel) -> ApiResult<()> {
        let existing_group = self
            .group_provider
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
        let updated_group = self.group_provider.update_group(&group).await;
        match updated_group {
            Ok(_) => {
                log::info!(
                    "Group updated for id: {} and realm: {}",
                    &group.group_id,
                    &group.realm_id
                );
                ApiResult::no_content()
            }
            Err(err) => {
                log::error!(
                    "Failed to update group: {}, realm: {}. Error: {}",
                    &group.group_id,
                    &group.realm_id,
                    &err
                );
                ApiResult::from_error(500, "500", "failed to update group")
            }
        }
    }

    async fn delete_group(&self, realm_id: &str, group_id: &str) -> ApiResult<()> {
        let existing_group = self
            .group_provider
            .load_group_by_id(&realm_id, &group_id)
            .await;
        if let Ok(response) = existing_group {
            if response.is_none() {
                log::error!("group: {} not found in realm: {}", &group_id, &realm_id);
                return ApiResult::from_error(404, "404", "role not found");
            }
        }
        let result = self.group_provider.delete_group(&realm_id, &group_id).await;
        match result {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to update role"),
        }
    }

    async fn load_group_by_id(&self, realm_id: &str, group_id: &str) -> ApiResult<GroupModel> {
        let loaded_group = self
            .group_provider
            .load_group_by_id(&realm_id, &group_id)
            .await;
        match loaded_group {
            Ok(group) => ApiResult::<GroupModel>::from_option(group),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn load_groups_by_realm(&self, realm_id: &str) -> ApiResult<Vec<GroupModel>> {
        let loaded_groups = self.group_provider.load_groups_by_realm(&realm_id).await;
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

    async fn count_groups(&self, realm_id: &str) -> ApiResult<i64> {
        let response = self.group_provider.count_groups(&realm_id).await;
        match response {
            Ok(count) => ApiResult::from_data(count),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn add_group_role(&self, realm_id: &str, group_id: &str, role_id: &str) -> ApiResult<()> {
        let existing_group = self
            .group_provider
            .exists_groups_by_id(&realm_id, &group_id)
            .await;
        if let Ok(response) = existing_group {
            if !response {
                log::error!("group: {} not found in realm: {}", group_id, realm_id);
                return ApiResult::from_error(409, "404", "group not found");
            }
        }

        let existing_role = self
            .role_provider
            .role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "role not found");
            }
        }

        let response = self
            .group_provider
            .add_group_role_mapping(&realm_id, &group_id, &role_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to add role to group"),
        }
    }

    async fn remove_group_role(
        &self,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let existing_group = self
            .group_provider
            .exists_groups_by_id(&realm_id, &group_id)
            .await;
        if let Ok(response) = existing_group {
            if !response {
                log::error!("group: {} not found in realm: {}", group_id, realm_id);
                return ApiResult::from_error(409, "404", "group not found");
            }
        }

        let existing_role = self
            .role_provider
            .role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "role not found");
            }
        }

        let response = self
            .group_provider
            .remove_group_role_mapping(&realm_id, &group_id, &role_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to remove role from group"),
        }
    }
}

#[async_trait]
pub trait IIdentityProviderService: Interface {
    async fn create_identity_provider(
        &self,
        idp: IdentityProviderModel,
    ) -> ApiResult<IdentityProviderModel>;
    async fn udpate_identity_provider(&self, idp: IdentityProviderModel) -> ApiResult<()>;
    async fn load_identity_provider(
        &self,
        realm_id: &str,
        internal_id: &str,
    ) -> ApiResult<IdentityProviderModel>;
    async fn load_identity_providers_by_realm(
        &self,
        realm_id: &str,
    ) -> ApiResult<Vec<IdentityProviderModel>>;
    async fn delete_identity_provider(&self, realm_id: &str, internal_id: &str) -> ApiResult<()>;
    async fn exists_by_alias(&self, realm_id: &str, alias: &str) -> ApiResult<bool>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IIdentityProviderService)]
pub struct IdentityProviderService {
    #[shaku(inject)]
    identity_provider: Arc<dyn IIdentityProvider>,
}

#[async_trait]
impl IIdentityProviderService for IdentityProviderService {
    async fn create_identity_provider(
        &self,
        idp: IdentityProviderModel,
    ) -> ApiResult<IdentityProviderModel> {
        let existing_idp = self
            .identity_provider
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
        let created_idp = self.identity_provider.create_identity_provider(&idp).await;
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

    async fn udpate_identity_provider(&self, idp: IdentityProviderModel) -> ApiResult<()> {
        let existing_idp = self
            .identity_provider
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
                let has_alias = self
                    .identity_provider
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
        let updated_idp = self.identity_provider.udpate_identity_provider(&idp).await;
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

    async fn load_identity_provider(
        &self,
        realm_id: &str,
        internal_id: &str,
    ) -> ApiResult<IdentityProviderModel> {
        let loaded_idp = self
            .identity_provider
            .load_identity_provider_by_internal_id(&realm_id, &internal_id)
            .await;
        match loaded_idp {
            Ok(idp) => ApiResult::<IdentityProviderModel>::from_option(idp),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn load_identity_providers_by_realm(
        &self,
        realm_id: &str,
    ) -> ApiResult<Vec<IdentityProviderModel>> {
        let loaded_idps = self
            .identity_provider
            .load_identity_provider_by_realm(&realm_id)
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

    async fn delete_identity_provider(&self, realm_id: &str, internal_id: &str) -> ApiResult<()> {
        let existing_idp = self
            .identity_provider
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
        let updated_idp = self
            .identity_provider
            .remove_identity_provider(&realm_id, &internal_id)
            .await;
        match updated_idp {
            Ok(_) => ApiResult::no_content(),
            Err(err) => {
                log::error!(
                    "Failed to update identity provider: {}, realm: {}. Error: {}",
                    &internal_id,
                    &realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update identity provider")
            }
        }
    }

    async fn exists_by_alias(&self, realm_id: &str, alias: &str) -> ApiResult<bool> {
        let existing_idp = self
            .identity_provider
            .exists_by_alias(&realm_id, &alias)
            .await;
        match existing_idp {
            Ok(res) => ApiResult::Data(res),
            Err(_) => ApiResult::from_error(500, "500", "failed check identity provider"),
        }
    }
}

#[async_trait]
pub trait IResourceServerService: Interface {
    async fn create_resource_server(
        &self,
        server: ResourceServerModel,
    ) -> ApiResult<ResourceServerModel>;

    async fn udpate_resource_server(&self, server: ResourceServerModel) -> ApiResult<()>;

    async fn load_resource_server_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<ResourceServerModel>;

    async fn load_resource_servers_by_realm(
        &self,
        realm_id: &str,
    ) -> ApiResult<Vec<ResourceServerModel>>;

    async fn delete_resource_server_by_id(&self, realm_id: &str, server_id: &str) -> ApiResult<()>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IResourceServerService)]
pub struct ResourceServerService {
    #[shaku(inject)]
    resource_server_provider: Arc<dyn IResourceServerProvider>,
}

#[async_trait]
impl IResourceServerService for ResourceServerService {
    async fn create_resource_server(
        &self,
        server: ResourceServerModel,
    ) -> ApiResult<ResourceServerModel> {
        let existing_resource_server = self
            .resource_server_provider
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
        let created_role = self
            .resource_server_provider
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

    async fn udpate_resource_server(&self, server: ResourceServerModel) -> ApiResult<()> {
        let existing_resource_server = self
            .resource_server_provider
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
                let server_with_name = self
                    .resource_server_provider
                    .resource_server_exists_by_alias(&server.realm_id, &server.server_id)
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
        let updated_idp = self
            .resource_server_provider
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

    async fn load_resource_server_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<ResourceServerModel> {
        let loaded_resource_server = self
            .resource_server_provider
            .load_resource_server_by_id(&realm_id, &server_id)
            .await;

        match loaded_resource_server {
            Ok(idp) => ApiResult::<ResourceServerModel>::from_option(idp),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn load_resource_servers_by_realm(
        &self,
        realm_id: &str,
    ) -> ApiResult<Vec<ResourceServerModel>> {
        let loaded_servers = self
            .resource_server_provider
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

    async fn delete_resource_server_by_id(&self, realm_id: &str, server_id: &str) -> ApiResult<()> {
        let existing_server = self
            .resource_server_provider
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
        let updated_server = self
            .resource_server_provider
            .delete_resource_server(&realm_id, &server_id)
            .await;

        match updated_server {
            Ok(_) => ApiResult::no_content(),
            Err(err) => {
                log::error!(
                    "Failed to update resource server: {}, realm: {}. Error: {}",
                    &server_id,
                    &realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update resource server")
            }
        }
    }
}

#[async_trait]
pub trait IResourceService: Interface {
    async fn create_resource(&self, resource: ResourceModel) -> ApiResult<ResourceModel>;

    async fn udpate_resource(&self, resource: ResourceModel) -> ApiResult<()>;

    async fn load_resource_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> ApiResult<ResourceModel>;

    async fn load_resources_by_server(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<Vec<ResourceModel>>;

    async fn load_resources_by_realm(&self, realm_id: &str) -> ApiResult<Vec<ResourceModel>>;

    async fn delete_resource_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> ApiResult<()>;

    async fn add_resource_scope(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> ApiResult<()>;

    async fn remove_resource_scope(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> ApiResult<()>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IResourceService)]
pub struct ResourceService {
    #[shaku(inject)]
    resource_provider: Arc<dyn IResourceProvider>,

    #[shaku(inject)]
    scope_provider: Arc<dyn IScopeProvider>,
}

#[async_trait]
impl IResourceService for ResourceService {
    async fn create_resource(&self, resource: ResourceModel) -> ApiResult<ResourceModel> {
        let existing_resource = self
            .resource_provider
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
        let created_resource = self.resource_provider.create_resource(&resource).await;
        match created_resource {
            Ok(_) => ApiResult::Data(resource),
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
        }
    }

    async fn udpate_resource(&self, resource: ResourceModel) -> ApiResult<()> {
        let existing_resource = self
            .resource_provider
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
                let resource_with_name = self
                    .resource_provider
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
        let updated_resource = self.resource_provider.udpate_resource(&resource).await;
        match updated_resource {
            Ok(_) => ApiResult::no_content(),
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
        }
    }

    async fn load_resource_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> ApiResult<ResourceModel> {
        let loaded_resource = self
            .resource_provider
            .load_resource_by_id(&realm_id, &server_id, &resource_id)
            .await;

        match loaded_resource {
            Ok(resource) => ApiResult::<ResourceModel>::from_option(resource),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn load_resources_by_server(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<Vec<ResourceModel>> {
        let loaded_resources = self
            .resource_provider
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

    async fn load_resources_by_realm(&self, realm_id: &str) -> ApiResult<Vec<ResourceModel>> {
        let loaded_resources = self
            .resource_provider
            .load_resource_by_realm(&realm_id)
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

    async fn delete_resource_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> ApiResult<()> {
        let existing_resource = self
            .resource_provider
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
        let updated_resource = self
            .resource_provider
            .delete_resource_by_id(&realm_id, &server_id, &resource_id)
            .await;

        match updated_resource {
            Ok(_) => ApiResult::no_content(),
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
        }
    }

    async fn add_resource_scope(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> ApiResult<()> {
        let existing_resource = self
            .resource_provider
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

        let existing_scope = self
            .scope_provider
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

        let response = self
            .resource_provider
            .add_resource_scope_mapping(&realm_id, &server_id, &resource_id, &scope_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to add scope to resource"),
        }
    }

    async fn remove_resource_scope(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> ApiResult<()> {
        let existing_resource = self
            .resource_provider
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

        let existing_scope = self
            .scope_provider
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

        let response = self
            .resource_provider
            .remove_resource_scope_mapping(&realm_id, &server_id, &resource_id, &scope_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to add scope to resource"),
        }
    }
}

#[async_trait]
pub trait IScopeService: Interface {
    async fn create_scope(&self, server: ScopeModel) -> ApiResult<ScopeModel>;

    async fn udpate_scope(&self, server: ScopeModel) -> ApiResult<()>;

    async fn load_scope_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> ApiResult<ScopeModel>;

    async fn load_scopes_by_realm(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<Vec<ScopeModel>>;

    async fn delete_scope_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> ApiResult<()>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IScopeService)]
pub struct ScopeService {
    #[shaku(inject)]
    resource_server_provider: Arc<dyn IResourceServerProvider>,

    #[shaku(inject)]
    scope_provider: Arc<dyn IScopeProvider>,
}

#[async_trait]
impl IScopeService for ScopeService {
    async fn create_scope(&self, scope: ScopeModel) -> ApiResult<ScopeModel> {
        let existing_resource_server = self
            .resource_server_provider
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

        let existing_scope = self
            .scope_provider
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
        let created_scope = self.scope_provider.create_scope(&scope).await;
        match created_scope {
            Ok(_) => ApiResult::Data(scope),
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
        }
    }

    async fn udpate_scope(&self, scope: ScopeModel) -> ApiResult<()> {
        let existing_resource_server = self
            .resource_server_provider
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

        let existing_scope = self
            .scope_provider
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

        let updated_scope = self.scope_provider.udpate_scope(&scope).await;
        match updated_scope {
            Ok(_) => ApiResult::no_content(),
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
        }
    }

    async fn load_scope_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> ApiResult<ScopeModel> {
        let loaded_scope = self
            .scope_provider
            .load_scope_by_id(&realm_id, &server_id, &scope_id)
            .await;

        match loaded_scope {
            Ok(idp) => ApiResult::<ScopeModel>::from_option(idp),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn load_scopes_by_realm(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> ApiResult<Vec<ScopeModel>> {
        let loaded_scopes = self
            .scope_provider
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

    async fn delete_scope_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> ApiResult<()> {
        let existing_scope = self
            .scope_provider
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
        let deleted_scope = self
            .scope_provider
            .delete_scope_by_id(&realm_id, &server_id, &scope_id)
            .await;

        match deleted_scope {
            Ok(_) => ApiResult::no_content(),
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
        }
    }
}
