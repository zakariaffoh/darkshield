use async_trait::async_trait;
use models::entities::authz::{
    GroupModel, IdentityProviderModel, ResourceServerModel, RoleModel, ScopeModel,
};
use shaku::Interface;

#[async_trait]
pub trait IRoleProvider: Interface {
    async fn create_role(&self, role_model: &RoleModel) -> Result<(), String>;
    async fn update_role(&self, role_model: &RoleModel) -> Result<(), String>;
    async fn load_roles_by_ids(
        &self,
        realm_id: &str,
        roles_ids: &Vec<String>,
    ) -> Result<Vec<RoleModel>, String>;
    async fn load_roles_by_realm(&self, realm_id: &str) -> Result<Vec<RoleModel>, String>;
    async fn load_role_by_name(
        &self,
        realm_id: &str,
        role_name: &str,
    ) -> Result<Option<RoleModel>, String>;
    async fn delete_role(&self, realm_id: &str, role_id: &str) -> Result<(), String>;
    async fn load_realm_role(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<Option<RoleModel>, String>;
    async fn load_role_by_id(
        &self,
        realm_id: &str,
        role_id: &str,
    ) -> Result<Option<RoleModel>, String>;

    async fn exists_by_name(&self, realm_id: &str, name: &str) -> Result<bool, String>;

    async fn client_role_exists_by_id(&self, realm_id: &str, role_id: &str)
        -> Result<bool, String>;

    async fn role_exists_by_id(&self, realm_id: &str, role_id: &str) -> Result<bool, String>;

    async fn count_roles(&self, realm_id: &str) -> Result<i64, String>;

    async fn load_client_roles(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<RoleModel>, String>;
}

#[async_trait]
pub trait IGroupProvider: Interface {
    async fn create_group(&self, group_model: &GroupModel) -> Result<(), String>;
    async fn update_group(&self, group_model: &GroupModel) -> Result<(), String>;
    async fn delete_group(&self, realm_id: &str, group_id: &str) -> Result<(), String>;
    async fn load_group_by_name(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<Option<GroupModel>, String>;
    async fn load_group_by_id(
        &self,
        realm_id: &str,
        group_id: &str,
    ) -> Result<Option<GroupModel>, String>;

    async fn load_groups_by_realm(&self, realm_id: &str) -> Result<Vec<GroupModel>, String>;
    async fn count_groups(&self, realm_id: &str) -> Result<i64, String>;
    async fn exists_groups_by_id(&self, realm_id: &str, realm_id: &str) -> Result<bool, String>;
    async fn add_group_role_mapping(
        &self,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> Result<(), String>;

    async fn remove_group_role_mapping(
        &self,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> Result<(), String>;
}

#[async_trait]
pub trait IIdentityProvider: Interface {
    async fn create_identity_provider(&self, idp: &IdentityProviderModel) -> Result<(), String>;

    async fn udpate_identity_provider(&self, idp: &IdentityProviderModel) -> Result<(), String>;

    async fn load_identity_provider_by_internal_id(
        &self,
        realm_id: &str,
        internal_id: &str,
    ) -> Result<Option<IdentityProviderModel>, String>;

    async fn load_identity_provider_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<IdentityProviderModel>, String>;

    async fn remove_identity_provider(
        &self,
        realm_id: &str,
        provider_id: &str,
    ) -> Result<bool, String>;

    async fn exists_by_alias(&self, realm_id: &str, provider_id: &str) -> Result<bool, String>;
}

#[async_trait]
pub trait IResourceServerProvider: Interface {
    async fn create_resource_server(&self, server: &ResourceServerModel) -> Result<(), String>;

    async fn udpate_resource_server(&self, server: &ResourceServerModel) -> Result<(), String>;

    async fn load_resource_server_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Option<ResourceServerModel>, String>;

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

    async fn load_resource_servers_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<ResourceServerModel>, String>;

    async fn delete_resource_server(&self, realm_id: &str, server_id: &str) -> Result<(), String>;
}

#[async_trait]
pub trait IScopeProvider: Interface {
    async fn create_scope(&self, scope: &ScopeModel) -> Result<(), String>;

    async fn udpate_scope(&self, scope: &ScopeModel) -> Result<(), String>;

    async fn load_scope_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> Result<Option<ScopeModel>, String>;

    async fn load_scopes_by_realm(&self, realm_id: &str) -> Result<Vec<ScopeModel>, String>;

    async fn load_scopes_by_realm_and_server(
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

    async fn scope_exists_by_name(
        &self,
        realm_id: &str,
        server_id: &str,
        name: &str,
    ) -> Result<bool, String>;
}
