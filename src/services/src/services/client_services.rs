use async_trait::async_trait;
use models::entities::authz::RoleModel;
use models::entities::client::ClientModel;
use models::entities::client::ClientScopeModel;
use models::entities::client::ProtocolEnum;
use models::entities::client::ProtocolMapperModel;
use models::entities::user::UserModel;
use shaku::Component;
use shaku::Interface;
use std::sync::Arc;
use store::providers::interfaces::authz_provider::IRoleProvider;
use store::providers::interfaces::client_provider::IClientProvider;
use store::providers::interfaces::client_provider::IClientScopeProvider;
use store::providers::interfaces::client_provider::IProtocolMapperProvider;

#[async_trait]
pub trait IClientService: Interface {
    async fn create_client(&self, client: &ClientModel) -> Result<(), String>;

    async fn update_client(&self, client: &ClientModel) -> Result<(), String>;

    async fn delete_client(&self, realm_id: &str, client_id: &str) -> Result<(), String>;

    async fn load_client_by_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Option<ClientModel>, String>;

    async fn load_client_by_ids(
        &self,
        realm_id: &str,
        client_ids: &Vec<String>,
    ) -> Result<Vec<ClientModel>, String>;

    async fn load_clients_by_realm(&self, realm_id: &str) -> Result<Vec<ClientModel>, String>;

    async fn count_clients_by_realm(&self, realm_id: &str) -> Result<i64, String>;

    async fn client_exists_by_id(&self, realm_id: &str, client_id: &str) -> Result<bool, String>;

    async fn load_client_roles_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<RoleModel>, String>;

    async fn add_client_role_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> Result<(), String>;

    async fn remove_client_role_mapping(
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

    async fn load_client_scopes_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<ClientScopeModel>, String>;

    async fn add_client_protocol_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> Result<(), String>;

    async fn remove_client_protocol_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> Result<(), String>;

    async fn load_protocols_mappers_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<ProtocolMapperModel>, String>;

    async fn load_associated_service_acount_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Option<UserModel>, String>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IClientService)]
pub struct ClientService {
    #[shaku(inject)]
    client_provider: Arc<dyn IClientProvider>,

    #[shaku(inject)]
    client_scope_provider: Arc<dyn IClientScopeProvider>,

    #[shaku(inject)]
    protocol_mapper_provider: Arc<dyn IProtocolMapperProvider>,

    #[shaku(inject)]
    role_provider: Arc<dyn IRoleProvider>,
}

#[async_trait]
impl IClientService for ClientService {
    async fn create_client(&self, client: &ClientModel) -> Result<(), String> {
        self.client_provider.create_client(&client).await
    }

    async fn update_client(&self, client: &ClientModel) -> Result<(), String> {
        self.client_provider.update_client(&client).await
    }

    async fn delete_client(&self, realm_id: &str, client_id: &str) -> Result<(), String> {
        self.client_provider
            .delete_clients_by_client_id(&realm_id, &client_id)
            .await
    }

    async fn load_client_by_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Option<ClientModel>, String> {
        self.client_provider
            .load_client_by_client_id(&realm_id, &client_id)
            .await
    }

    async fn load_client_by_ids(
        &self,
        realm_id: &str,
        client_ids: &Vec<String>,
    ) -> Result<Vec<ClientModel>, String> {
        self.client_provider
            .load_client_by_client_ids(&realm_id, &client_ids)
            .await
    }

    async fn load_clients_by_realm(&self, realm_id: &str) -> Result<Vec<ClientModel>, String> {
        self.client_provider
            .load_clients_by_realm_id(&realm_id)
            .await
    }

    async fn count_clients_by_realm(&self, realm_id: &str) -> Result<i64, String> {
        self.client_provider.count_clients(&realm_id).await
    }

    async fn client_exists_by_id(&self, realm_id: &str, client_id: &str) -> Result<bool, String> {
        self.client_provider
            .client_exists_by_client_id(&realm_id, &client_id)
            .await
    }

    async fn load_client_roles_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<RoleModel>, String> {
        self.role_provider
            .load_client_roles(&realm_id, &client_id)
            .await
    }

    async fn add_client_role_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        self.client_provider
            .add_client_role(&realm_id, &client_id, &role_id)
            .await
    }

    async fn remove_client_role_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        self.client_provider
            .remove_client_role(&realm_id, &client_id, &role_id)
            .await
    }

    async fn add_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> Result<(), String> {
        self.client_provider
            .add_client_scope_mapping(&realm_id, &client_id, &client_scope_id)
            .await
    }

    async fn remove_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> Result<(), String> {
        self.client_provider
            .remove_client_scope_mapping(&realm_id, &client_id, &client_scope_id)
            .await
    }

    async fn load_client_scopes_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<ClientScopeModel>, String> {
        self.client_scope_provider
            .load_client_scopes_by_client_id(&realm_id, &client_id)
            .await
    }

    async fn add_client_protocol_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> Result<(), String> {
        self.client_provider
            .add_client_protocol_mapper_mapping(&realm_id, &client_id, &mapper_id)
            .await
    }

    async fn remove_client_protocol_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> Result<(), String> {
        self.client_provider
            .remove_client_protocol_mapper_mapping(&realm_id, &client_id, &mapper_id)
            .await
    }

    async fn load_protocols_mappers_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<ProtocolMapperModel>, String> {
        self.protocol_mapper_provider
            .load_protocol_mappers_by_client_id(&realm_id, &client_id)
            .await
    }

    async fn load_associated_service_acount_by_client_id(
        &self,
        _realm_id: &str,
        _client_id: &str,
    ) -> Result<Option<UserModel>, String> {
        todo!()
    }
}

#[async_trait]
pub trait IProtocolMapperService: Interface {
    async fn create_protocol_mapper(&self, mapper: &ProtocolMapperModel) -> Result<(), String>;

    async fn update_protocol_mapper(&self, mapper: &ProtocolMapperModel) -> Result<(), String>;

    async fn delete_protocol_mapper(&self, realm_id: &str, mapper_id: &str) -> Result<(), String>;

    async fn load_protocol_mapper_by_mapper_id(
        &self,
        realm_id: &str,
        mapper_id: &str,
    ) -> Result<Option<ProtocolMapperModel>, String>;

    async fn load_protocol_mappers_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<ProtocolMapperModel>, String>;

    async fn load_protocol_mapper_by_protocol(
        &self,
        realm_id: &str,
        protocol: ProtocolEnum,
    ) -> Result<Vec<ProtocolMapperModel>, String>;

    async fn load_protocol_mappers_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<ProtocolMapperModel>, String>;

    async fn protocol_mapper_exists_by_mapper_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<bool, String>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IProtocolMapperService)]
pub struct ProtocolMapperService {
    #[shaku(inject)]
    protocol_mapper_provider: Arc<dyn IProtocolMapperProvider>,
}

#[async_trait]
impl IProtocolMapperService for ProtocolMapperService {
    async fn create_protocol_mapper(&self, mapper: &ProtocolMapperModel) -> Result<(), String> {
        self.protocol_mapper_provider
            .create_protocol_mapper(&mapper)
            .await
    }

    async fn update_protocol_mapper(&self, mapper: &ProtocolMapperModel) -> Result<(), String> {
        self.protocol_mapper_provider
            .update_protocol_mapper(&mapper)
            .await
    }

    async fn delete_protocol_mapper(&self, realm_id: &str, mapper_id: &str) -> Result<(), String> {
        self.protocol_mapper_provider
            .delete_protocol_mapper(&realm_id, &mapper_id)
            .await
    }

    async fn load_protocol_mapper_by_mapper_id(
        &self,
        realm_id: &str,
        mapper_id: &str,
    ) -> Result<Option<ProtocolMapperModel>, String> {
        self.protocol_mapper_provider
            .load_protocol_mapper_by_mapper_id(&realm_id, &mapper_id)
            .await
    }

    async fn load_protocol_mappers_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<ProtocolMapperModel>, String> {
        self.protocol_mapper_provider
            .load_protocol_mappers_by_realm(&realm_id)
            .await
    }

    async fn load_protocol_mapper_by_protocol(
        &self,
        realm_id: &str,
        protocol: ProtocolEnum,
    ) -> Result<Vec<ProtocolMapperModel>, String> {
        self.protocol_mapper_provider
            .load_protocol_mappers_by_protocol(&realm_id, protocol)
            .await
    }

    async fn load_protocol_mappers_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<ProtocolMapperModel>, String> {
        self.protocol_mapper_provider
            .load_protocol_mappers_by_client_id(&realm_id, client_id)
            .await
    }

    async fn protocol_mapper_exists_by_mapper_id(
        &self,
        realm_id: &str,
        mapper_id: &str,
    ) -> Result<bool, String> {
        self.protocol_mapper_provider
            .exists_protocol_mapper_by_id(&realm_id, &mapper_id)
            .await
    }
}

#[async_trait]
pub trait IClientScopeService: Interface {
    async fn create_client_scope(&self, scope: &ClientScopeModel) -> Result<(), String>;

    async fn update_client_scope(&self, scope: &ClientScopeModel) -> Result<(), String>;

    async fn delete_client_scope(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<(), String>;

    async fn load_client_scope_by_scope_id(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<Option<ClientScopeModel>, String>;

    async fn load_client_scope_by_scope_ids(
        &self,
        realm_id: &str,
        client_scope_id: &[&str],
    ) -> Result<Vec<ClientScopeModel>, String>;


    async fn add_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        scope_id: &str,
        mapper_id: &str,
    ) -> Result<(), String>;

    async fn remove_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        scope_id: &str,
        mapper_id: &str,
    ) -> Result<(), String>;

    async fn add_client_scope_role_mapping(
        &self,
        realm_id: &str,
        scope_id: &str,
        role_id: &str,
    ) -> Result<(), String>;

    async fn remove_client_scope_role_mapping(
        &self,
        realm_id: &str,
        scope_id: &str,
        role_id: &str,
    ) -> Result<(), String>;

    async fn client_scope_exists_by_scope_id(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<bool, String>;

    async fn client_scope_exists_by_name(&self, realm_id: &str, name: &str)
        -> Result<bool, String>;

    async fn load_client_scope_names_by_protocol(
        &self,
        realm_id: &str,
        protocol: &str,
    ) -> Result<Vec<String>, String>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IClientScopeService)]
pub struct ClientScopeService {
    #[shaku(inject)]
    client_scope_provider: Arc<dyn IClientScopeProvider>,

    #[shaku(inject)]
    protocol_mapper_provider: Arc<dyn IProtocolMapperProvider>,

    #[shaku(inject)]
    role_provider: Arc<dyn IRoleProvider>,
}

#[async_trait]
impl IClientScopeService for ClientScopeService {
    async fn create_client_scope(&self, client_scope: &ClientScopeModel) -> Result<(), String> {
        self.client_scope_provider
            .create_client_scope(&client_scope)
            .await
    }

    async fn update_client_scope(&self, client_scope: &ClientScopeModel) -> Result<(), String> {
        self.client_scope_provider
            .update_client_scope(&client_scope)
            .await
    }

    async fn delete_client_scope(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<(), String> {
        self.client_scope_provider
            .delete_client_scope(&realm_id, &client_scope_id)
            .await
    }

    async fn load_client_scope_by_scope_id(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<Option<ClientScopeModel>, String> {
        self.client_scope_provider
            .load_client_scope_by_client_scope_id(&realm_id, &client_scope_id)
            .await
    }

    async fn add_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        scope_id: &str,
        mapper_id: &str,
    ) -> Result<(), String> {
        self.client_scope_provider
            .add_client_scope_protocol_mapper(&realm_id, &scope_id, &mapper_id)
            .await
    }

    async fn remove_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        scope_id: &str,
        mapper_id: &str,
    ) -> Result<(), String> {
        self.client_scope_provider
            .remove_client_scope_protocol_mapper(&realm_id, &scope_id, &mapper_id)
            .await
    }

    async fn add_client_scope_role_mapping(
        &self,
        realm_id: &str,
        scope_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        self.client_scope_provider
            .add_client_scope_role_mapping(&realm_id, &scope_id, &role_id)
            .await
    }

    async fn remove_client_scope_role_mapping(
        &self,
        realm_id: &str,
        scope_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        self.client_scope_provider
            .remove_client_scope_role_mapping(&realm_id, &scope_id, &role_id)
            .await
    }

    async fn client_scope_exists_by_scope_id(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<bool, String> {
        self.client_scope_provider
            .client_scope_exists_by_scope_id(&realm_id, &client_scope_id)
            .await
    }

    async fn client_scope_exists_by_name(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<bool, String> {
        self.client_scope_provider
            .client_scope_exists_by_name(&realm_id, &name)
            .await
    }

    async fn load_client_scope_names_by_protocol(
        &self,
        realm_id: &str,
        protocol: &str,
    ) -> Result<Vec<String>, String> {
        self.client_scope_provider
            .load_client_scope_names_by_protocol(&realm_id, &protocol)
            .await
    }
}
