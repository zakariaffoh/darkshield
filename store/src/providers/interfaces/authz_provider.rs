use async_trait::async_trait;
use models::entities::authz_models::{GroupModel, RoleModel};
use shaku::Interface;

#[async_trait]
pub trait IRoleProvider: Interface {
    async fn create_role(&self, role_model: &RoleModel);
    async fn update_role(&self, role_model: &RoleModel);
    async fn load_roles_by_ids(&self, realm_id: &str, roles_ids: Vec<String>) -> Vec<RoleModel>;
    async fn load_roles_by_realm(&self, realm_id: &str) -> Vec<RoleModel>;
    async fn load_role_by_name(&self, realm_id: &str, role_name: &str) -> Option<RoleModel>;
    async fn delete_role(&self, realm_id: &str, role_id: &str) -> Result<(), String>;
    async fn load_realm_role(&self, realm_id: &str, name: &str) -> Option<RoleModel>;
    async fn load_role_by_id(&self, realm_id: &str, role_id: &str) -> Option<RoleModel>;
    async fn exists_by_name(&self, realm_id: &str, name: &str) -> Result<bool, String>;
}

#[async_trait]
pub trait IGroupProvider: Interface {
    async fn create_group(&self, group_model: &GroupModel);
}

#[async_trait]
pub trait IScopeProvider: Interface {}