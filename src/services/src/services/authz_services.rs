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
    async fn create_role(&self, realm: &RoleModel) -> Result<(), String>;
    async fn update_role(&self, realm: &RoleModel) -> Result<(), String>;
    async fn delete_role(&self, realm_id: &str, role_id: &str) -> Result<(), String>;
    async fn load_role_by_id(
        &self,
        realm_id: &str,
        role_id: &str,
    ) -> Result<Option<RoleModel>, String>;
    async fn load_roles_by_realm(&self, realm_id: &str) -> Result<Vec<RoleModel>, String>;
    async fn count_roles_by_realm(&self, realm_id: &str) -> Result<i64, String>;
    async fn load_role_by_name(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<Option<RoleModel>, String>;
    async fn role_exists_by_id(&self, realm_id: &str, role_id: &str) -> Result<bool, String>;
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
    async fn create_role(&self, role: &RoleModel) -> Result<(), String> {
        self.role_provider.create_role(&role).await
    }

    async fn update_role(&self, role: &RoleModel) -> Result<(), String> {
        self.role_provider.update_role(&role).await
    }

    async fn delete_role(&self, realm_id: &str, role_id: &str) -> Result<(), String> {
        self.role_provider.delete_role(&realm_id, &role_id).await
    }

    async fn load_role_by_id(
        &self,
        realm_id: &str,
        role_id: &str,
    ) -> Result<Option<RoleModel>, String> {
        self.role_provider
            .load_role_by_id(&realm_id, &role_id)
            .await
    }

    async fn load_roles_by_realm(&self, realm_id: &str) -> Result<Vec<RoleModel>, String> {
        self.role_provider.load_roles_by_realm(&realm_id).await
    }

    async fn count_roles_by_realm(&self, realm_id: &str) -> Result<i64, String> {
        self.role_provider.count_roles(&realm_id).await
    }

    async fn load_role_by_name(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<Option<RoleModel>, String> {
        self.role_provider.load_role_by_name(&realm_id, &name).await
    }

    async fn role_exists_by_id(&self, realm_id: &str, role_id: &str) -> Result<bool, String> {
        self.role_provider
            .role_exists_by_id(&realm_id, &role_id)
            .await
    }
}

#[async_trait]
pub trait IGroupService: Interface {
    async fn create_group(&self, group: &GroupModel) -> Result<(), String>;

    async fn udpate_group(&self, group: &GroupModel) -> Result<(), String>;

    async fn delete_group(&self, realm_id: &str, group_id: &str) -> Result<(), String>;

    async fn load_group_by_id(
        &self,
        realm_id: &str,
        group_id: &str,
    ) -> Result<Option<GroupModel>, String>;

    async fn load_groups_by_realm(&self, realm_id: &str) -> Result<Vec<GroupModel>, String>;

    async fn count_groups(&self, realm_id: &str) -> Result<i64, String>;

    async fn add_group_role(
        &self,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> Result<(), String>;

    async fn remove_group_role(
        &self,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> Result<(), String>;

    async fn exists_groups_by_id(&self, realm_id: &str, group_id: &str) -> Result<bool, String>;

    async fn load_group_by_name(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<Option<GroupModel>, String>;
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
    async fn create_group(&self, group: &GroupModel) -> Result<(), String> {
        self.group_provider.create_group(&group).await
    }

    async fn udpate_group(&self, group: &GroupModel) -> Result<(), String> {
        self.group_provider.update_group(&group).await
    }

    async fn delete_group(&self, realm_id: &str, group_id: &str) -> Result<(), String> {
        self.group_provider.delete_group(&realm_id, &group_id).await
    }

    async fn load_group_by_id(
        &self,
        realm_id: &str,
        group_id: &str,
    ) -> Result<Option<GroupModel>, String> {
        self.group_provider
            .load_group_by_id(&realm_id, &group_id)
            .await
    }

    async fn load_groups_by_realm(&self, realm_id: &str) -> Result<Vec<GroupModel>, String> {
        self.group_provider.load_groups_by_realm(&realm_id).await
    }

    async fn count_groups(&self, realm_id: &str) -> Result<i64, String> {
        self.group_provider.count_groups(&realm_id).await
    }

    async fn add_group_role(
        &self,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        self.group_provider
            .add_group_role_mapping(&realm_id, &group_id, &role_id)
            .await
    }

    async fn remove_group_role(
        &self,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        self.group_provider
            .remove_group_role_mapping(&realm_id, &group_id, &role_id)
            .await
    }
    async fn exists_groups_by_id(&self, realm_id: &str, group_id: &str) -> Result<bool, String> {
        self.group_provider
            .exists_groups_by_id(&realm_id, &group_id)
            .await
    }

    async fn load_group_by_name(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<Option<GroupModel>, String> {
        self.group_provider
            .load_group_by_name(&realm_id, &name)
            .await
    }
}

#[async_trait]
pub trait IIdentityProviderService: Interface {
    async fn create_identity_provider(&self, idp: &IdentityProviderModel) -> Result<(), String>;

    async fn udpate_identity_provider(&self, idp: &IdentityProviderModel) -> Result<(), String>;

    async fn load_identity_provider(
        &self,
        realm_id: &str,
        internal_id: &str,
    ) -> Result<Option<IdentityProviderModel>, String>;

    async fn load_identity_providers_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<IdentityProviderModel>, String>;

    async fn delete_identity_provider(
        &self,
        realm_id: &str,
        internal_id: &str,
    ) -> Result<(), String>;

    async fn exists_by_alias(&self, realm_id: &str, alias: &str) -> Result<bool, String>;

    async fn load_identity_provider_by_internal_id(
        &self,
        realm_id: &str,
        internal_id: &str,
    ) -> Result<Option<IdentityProviderModel>, String>;
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
    async fn create_identity_provider(&self, idp: &IdentityProviderModel) -> Result<(), String> {
        self.identity_provider.create_identity_provider(&idp).await
    }

    async fn udpate_identity_provider(&self, idp: &IdentityProviderModel) -> Result<(), String> {
        self.identity_provider.udpate_identity_provider(&idp).await
    }

    async fn load_identity_provider(
        &self,
        realm_id: &str,
        internal_id: &str,
    ) -> Result<Option<IdentityProviderModel>, String> {
        self.identity_provider
            .load_identity_provider_by_internal_id(&realm_id, &internal_id)
            .await
    }

    async fn load_identity_providers_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<IdentityProviderModel>, String> {
        self.identity_provider
            .load_identity_provider_by_realm(&realm_id)
            .await
    }

    async fn delete_identity_provider(
        &self,
        realm_id: &str,
        internal_id: &str,
    ) -> Result<(), String> {
        self.identity_provider
            .remove_identity_provider(&realm_id, &internal_id)
            .await
    }

    async fn exists_by_alias(&self, realm_id: &str, alias: &str) -> Result<bool, String> {
        self.identity_provider
            .exists_by_alias(&realm_id, &alias)
            .await
    }

    async fn load_identity_provider_by_internal_id(
        &self,
        realm_id: &str,
        internal_id: &str,
    ) -> Result<Option<IdentityProviderModel>, String> {
        self.identity_provider
            .load_identity_provider_by_internal_id(&realm_id, &internal_id)
            .await
    }
}

#[async_trait]
pub trait IResourceServerService: Interface {
    async fn create_resource_server(&self, server: &ResourceServerModel) -> Result<(), String>;

    async fn udpate_resource_server(&self, server: &ResourceServerModel) -> Result<(), String>;

    async fn load_resource_server_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Option<ResourceServerModel>, String>;

    async fn load_resource_servers_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<ResourceServerModel>, String>;

    async fn delete_resource_server_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<(), String>;

    async fn resource_server_exists_by_alias(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<bool, String>;

    async fn resource_server_exists_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<bool, String>;
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
    async fn create_resource_server(&self, server: &ResourceServerModel) -> Result<(), String> {
        self.resource_server_provider
            .create_resource_server(&server)
            .await
    }

    async fn udpate_resource_server(&self, server: &ResourceServerModel) -> Result<(), String> {
        self.resource_server_provider
            .udpate_resource_server(&server)
            .await
    }

    async fn load_resource_server_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Option<ResourceServerModel>, String> {
        self.resource_server_provider
            .load_resource_server_by_id(&realm_id, &server_id)
            .await
    }

    async fn load_resource_servers_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<ResourceServerModel>, String> {
        self.resource_server_provider
            .load_resource_servers_by_realm(&realm_id)
            .await
    }

    async fn delete_resource_server_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<(), String> {
        self.resource_server_provider
            .delete_resource_server(&realm_id, &server_id)
            .await
    }

    async fn resource_server_exists_by_alias(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<bool, String> {
        self.resource_server_provider
            .resource_server_exists_by_alias(&realm_id, &name)
            .await
    }
    async fn resource_server_exists_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<bool, String> {
        self.resource_server_provider
            .resource_server_exists_by_id(&realm_id, &server_id)
            .await
    }
}

#[async_trait]
pub trait IResourceService: Interface {
    async fn create_resource(&self, resource: &ResourceModel) -> Result<(), String>;

    async fn udpate_resource(&self, resource: &ResourceModel) -> Result<(), String>;

    async fn load_resource_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> Result<Option<ResourceModel>, String>;

    async fn load_resources_by_server(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Vec<ResourceModel>, String>;

    async fn load_resources_by_realm(&self, realm_id: &str) -> Result<Vec<ResourceModel>, String>;

    async fn delete_resource_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> Result<(), String>;

    async fn add_resource_scope(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> Result<(), String>;

    async fn remove_resource_scope(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> Result<(), String>;

    async fn resource_exists_by_name(
        &self,
        realm_id: &str,
        server_id: &str,
        name: &str,
    ) -> Result<bool, String>;

    async fn resource_exists_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> Result<bool, String>;
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
    async fn create_resource(&self, resource: &ResourceModel) -> Result<(), String> {
        self.resource_provider.create_resource(&resource).await
    }

    async fn udpate_resource(&self, resource: &ResourceModel) -> Result<(), String> {
        self.resource_provider.udpate_resource(&resource).await
    }

    async fn load_resource_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> Result<Option<ResourceModel>, String> {
        self.resource_provider
            .load_resource_by_id(&realm_id, &server_id, &resource_id)
            .await
    }

    async fn load_resources_by_server(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Vec<ResourceModel>, String> {
        self.resource_provider
            .load_resources_by_server(&realm_id, &server_id)
            .await
    }

    async fn load_resources_by_realm(&self, realm_id: &str) -> Result<Vec<ResourceModel>, String> {
        self.resource_provider
            .load_resource_by_realm(&realm_id)
            .await
    }

    async fn delete_resource_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> Result<(), String> {
        self.resource_provider
            .delete_resource_by_id(&realm_id, &server_id, &resource_id)
            .await
    }

    async fn add_resource_scope(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> Result<(), String> {
        self.resource_provider
            .add_resource_scope_mapping(&realm_id, &server_id, &resource_id, &scope_id)
            .await
    }

    async fn remove_resource_scope(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> Result<(), String> {
        self.resource_provider
            .remove_resource_scope_mapping(&realm_id, &server_id, &resource_id, &scope_id)
            .await
    }

    async fn resource_exists_by_name(
        &self,
        realm_id: &str,
        server_id: &str,
        name: &str,
    ) -> Result<bool, String> {
        self.resource_provider
            .resource_exists_by_name(&realm_id, &server_id, &name)
            .await
    }

    async fn resource_exists_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> Result<bool, String> {
        self.resource_provider
            .resource_exists_by_id(&realm_id, &server_id, &resource_id)
            .await
    }
}

#[async_trait]
pub trait IScopeService: Interface {
    async fn create_scope(&self, server: &ScopeModel) -> Result<(), String>;

    async fn udpate_scope(&self, server: &ScopeModel) -> Result<(), String>;

    async fn load_scope_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> Result<Option<ScopeModel>, String>;

    async fn load_scopes_by_realm(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Vec<ScopeModel>, String>;

    async fn delete_scope_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> Result<(), String>;

    async fn scope_exists_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> Result<bool, String>;

    async fn scope_exists_by_name(
        &self,
        realm_id: &str,
        server_id: &str,
        name: &str,
    ) -> Result<bool, String>;

    async fn load_scopes_by_realm_and_server(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Vec<ScopeModel>, String>;
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
    async fn create_scope(&self, scope: &ScopeModel) -> Result<(), String> {
        self.scope_provider.create_scope(&scope).await
    }

    async fn udpate_scope(&self, scope: &ScopeModel) -> Result<(), String> {
        self.scope_provider.udpate_scope(&scope).await
    }

    async fn load_scope_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> Result<Option<ScopeModel>, String> {
        self.scope_provider
            .load_scope_by_id(&realm_id, &server_id, &scope_id)
            .await
    }

    async fn load_scopes_by_realm(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Vec<ScopeModel>, String> {
        self.scope_provider
            .load_scopes_by_realm_and_server(&realm_id, &server_id)
            .await
    }

    async fn delete_scope_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> Result<(), String> {
        self.scope_provider
            .delete_scope_by_id(&realm_id, &server_id, &scope_id)
            .await
    }
    async fn scope_exists_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> Result<bool, String> {
        self.scope_provider
            .scope_exists_by_id(&realm_id, &server_id, &scope_id)
            .await
    }

    async fn scope_exists_by_name(
        &self,
        realm_id: &str,
        server_id: &str,
        name: &str,
    ) -> Result<bool, String> {
        self.scope_provider
            .scope_exists_by_name(&realm_id, &server_id, &name)
            .await
    }

    async fn load_scopes_by_realm_and_server(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Vec<ScopeModel>, String> {
        self.scope_provider
            .load_scopes_by_realm_and_server(&realm_id, &server_id)
            .await
    }
}
