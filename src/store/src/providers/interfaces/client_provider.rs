use async_trait::async_trait;
use models::entities::{
    authz::RoleModel,
    client::{ClientModel, ClientScopeModel, ProtocolEnum, ProtocolMapperModel},
};
use shaku::Interface;

#[async_trait]
pub trait IClientProvider: Interface {
    async fn create_client(&self, client: &ClientModel) -> Result<(), String>;

    async fn update_client(&self, client: &ClientModel) -> Result<(), String>;

    async fn load_client_by_name(
        &self,
        realm_id: &str,
        client_name: &str,
    ) -> Result<Option<ClientModel>, String>;

    async fn delete_clients_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<(), String>;

    async fn load_client_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Option<ClientModel>, String>;

    async fn load_client_by_client_ids(
        &self,
        realm_id: &str,
        client_id: &Vec<String>,
    ) -> Result<Vec<ClientModel>, String>;

    async fn load_clients_by_realm_id(&self, realm_id: &str) -> Result<Vec<ClientModel>, String>;

    async fn client_exists_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<bool, String>;

    async fn add_client_role(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> Result<(), String>;

    async fn remove_client_role(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> Result<(), String>;

    async fn add_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> Result<(), String>;

    async fn remove_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> Result<(), String>;

    async fn add_client_protocol_mapper_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> Result<(), String>;

    async fn remove_client_protocol_mapper_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> Result<(), String>;

    async fn load_client_protocol_mappers_ids(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<String>, String>;

    async fn load_client_scopes_ids(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<String>, String>;

    async fn load_client_roles(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<RoleModel>, String>;

    async fn count_clients(&self, realm_id: &str) -> Result<i64, String>;

    async fn load_client_by_role_id(
        &self,
        realm_id: &str,
        role_id: &str,
    ) -> Result<Option<ClientModel>, String>;

    /*async fn load_client_scopes_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<ClientScopeModel>, String>;*/
}

#[async_trait]
pub trait IClientScopeProvider: Interface {
    async fn create_client_scope(&self, client_scope: &ClientScopeModel) -> Result<(), String>;

    async fn update_client_scope(&self, client_scope: &ClientScopeModel) -> Result<(), String>;

    async fn load_client_scope_by_client_scope_id(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<Option<ClientScopeModel>, String>;

    async fn load_client_scopes_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<ClientScopeModel>, String>;

    async fn client_scope_exists_by_name(&self, realm_id: &str, name: &str)
        -> Result<bool, String>;

    async fn client_scope_exists_by_scope_id(
        &self,
        realm_id: &str,
        scope_id: &str,
    ) -> Result<bool, String>;

    async fn delete_client_scope(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<(), String>;

    async fn add_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        client_scope_id: &str,
        mapper_id: &str,
    ) -> Result<(), String>;

    async fn remove_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        client_scope_id: &str,
        mapper_id: &str,
    ) -> Result<(), String>;

    async fn add_client_scope_role_mapping(
        &self,
        realm_id: &str,
        client_scope_id: &str,
        role_id: &str,
    ) -> Result<(), String>;

    async fn remove_client_scope_role_mapping(
        &self,
        realm_id: &str,
        client_scope_id: &str,
        role_id: &str,
    ) -> Result<(), String>;
}

#[async_trait]
pub trait IProtocolMapperProvider: Interface {
    async fn create_protocol_mapper(&self, mapper: &ProtocolMapperModel) -> Result<(), String>;

    async fn update_protocol_mapper(&self, mapper: &ProtocolMapperModel) -> Result<(), String>;

    async fn load_protocol_mapper_by_mapper_id(
        &self,
        realm_id: &str,
        mapper_id: &str,
    ) -> Result<Option<ProtocolMapperModel>, String>;

    async fn load_protocol_mappers_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<ProtocolMapperModel>, String>;

    async fn exists_protocol_mapper_by_id(
        &self,
        realm_id: &str,
        mapper_id: &str,
    ) -> Result<bool, String>;

    async fn exists_protocol_mapper_by_name(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<bool, String>;

    async fn load_protocol_mappers_by_client_scope_id(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<Vec<ProtocolMapperModel>, String>;

    async fn load_protocol_mappers_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<ProtocolMapperModel>, String>;

    async fn load_protocol_mappers_by_protocol(
        &self,
        realm_id: &str,
        protocol: ProtocolEnum,
    ) -> Result<Vec<ProtocolMapperModel>, String>;

    async fn delete_protocol_mapper(&self, realm_id: &str, mapper_id: &str) -> Result<(), String>;
}
