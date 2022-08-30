use async_trait::async_trait;
use commons::api_result::ApiResult;
use models::entities::client::ClientModel;
use models::entities::client::ClientScopeModel;
use models::entities::client::ProtocolMapperModel;
use models::entities::user::UserModel;
use shaku::Component;
use shaku::Interface;
use std::sync::Arc;
use store::providers::interfaces::client_provider::IClientProvider;
use store::providers::interfaces::client_provider::IProtocolMapperProvider;

#[async_trait]
pub trait IClientService: Interface {
    async fn create_client(&self, client: ClientModel) -> ApiResult<ClientModel>;
    async fn update_client(&self, realm: ClientModel) -> ApiResult<()>;
    async fn delete_client(&self, realm_id: &str, client_id: &str) -> ApiResult<bool>;
    async fn load_client_by_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Option<ClientModel>>;
    async fn load_clients_by_realm(&self, realm_id: &str) -> ApiResult<Vec<ClientModel>>;
    async fn count_clients_by_realm(&self, realm_id: &str) -> ApiResult<u32>;
    async fn load_client_roles_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ClientModel>>;

    async fn add_client_roles_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        roles_ids: Vec<String>,
    ) -> ApiResult<Vec<ClientModel>>;

    async fn remove_client_roles_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        roles_ids: Vec<String>,
    ) -> ApiResult<Vec<ClientModel>>;

    async fn add_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> ApiResult<()>;

    async fn remove_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> ApiResult<()>;

    async fn load_client_scopes_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ClientScopeModel>>;

    async fn add_client_protocol_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()>;

    async fn remove_client_protocol_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()>;

    async fn load_client_protocols_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>>;

    async fn load_associated_service_acount_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Option<UserModel>>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IClientService)]
pub struct ClientService {
    #[shaku(inject)]
    client_provider: Arc<dyn IClientProvider>,
}

#[async_trait]
impl IClientService for ClientService {
    async fn create_client(&self, client: ClientModel) -> ApiResult<ClientModel> {
        todo!()
    }
    async fn update_client(&self, client: ClientModel) -> ApiResult<()> {
        todo!()
    }
    async fn delete_client(&self, realm_id: &str, client_id: &str) -> ApiResult<bool> {
        todo!()
    }
    async fn load_client_by_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Option<ClientModel>> {
        todo!()
    }
    async fn load_clients_by_realm(&self, realm_id: &str) -> ApiResult<Vec<ClientModel>> {
        todo!()
    }
    async fn count_clients_by_realm(&self, realm_id: &str) -> ApiResult<u32> {
        todo!()
    }

    async fn load_client_roles_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ClientModel>> {
        todo!()
    }

    async fn add_client_roles_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        roles_ids: Vec<String>,
    ) -> ApiResult<Vec<ClientModel>> {
        todo!()
    }

    async fn remove_client_roles_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        roles_ids: Vec<String>,
    ) -> ApiResult<Vec<ClientModel>> {
        todo!()
    }

    async fn add_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn remove_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn load_client_scopes_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ClientScopeModel>> {
        todo!()
    }

    async fn add_client_protocol_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn remove_client_protocol_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        todo!()
    }

    async fn load_client_protocols_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>> {
        todo!()
    }

    async fn load_associated_service_acount_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Option<UserModel>> {
        todo!()
    }
}

#[async_trait]
pub trait IProtocolMapperService: Interface {
    async fn create_protocol_mapper(
        &self,
        mapper: ProtocolMapperModel,
    ) -> ApiResult<ProtocolMapperModel>;
    async fn update_protocol_mapper(&self, mapper: ProtocolMapperModel) -> ApiResult<()>;
    async fn delete_protocol_mapper(&self, realm_id: &str, mapper_id: &str) -> ApiResult<bool>;
    async fn load_protocol_mapper_by_mapper_id(
        &self,
        realm_id: &str,
        mapper_id: &str,
    ) -> ApiResult<Option<ClientModel>>;
    async fn load_protocol_mappers_by_realm(
        &self,
        realm_id: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>>;

    async fn load_protocol_mapper_by_protocol(
        &self,
        realm_id: &str,
        protocol: &str,
    ) -> ApiResult<Vec<ClientModel>>;

    async fn load_protocol_mappers_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ClientModel>>;
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
    async fn create_protocol_mapper(
        &self,
        mapper: ProtocolMapperModel,
    ) -> ApiResult<ProtocolMapperModel> {
        todo!();
    }
    async fn update_protocol_mapper(&self, mapper: ProtocolMapperModel) -> ApiResult<()> {
        todo!();
    }
    async fn delete_protocol_mapper(&self, realm_id: &str, mapper_id: &str) -> ApiResult<bool> {
        todo!();
    }
    async fn load_protocol_mapper_by_mapper_id(
        &self,
        realm_id: &str,
        mapper_id: &str,
    ) -> ApiResult<Option<ClientModel>> {
        todo!();
    }
    async fn load_protocol_mappers_by_realm(
        &self,
        realm_id: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>> {
        todo!();
    }

    async fn load_protocol_mapper_by_protocol(
        &self,
        realm_id: &str,
        protocol: &str,
    ) -> ApiResult<Vec<ClientModel>> {
        todo!();
    }

    async fn load_protocol_mappers_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ClientModel>> {
        todo!();
    }
}

#[async_trait]
pub trait IClientScopeService: Interface {
    async fn create_client_scope(&self, scope: ClientScopeModel) -> ApiResult<ClientScopeModel>;

    async fn update_client_scope(&self, scope: ClientScopeModel) -> ApiResult<()>;

    async fn delete_client_scope(&self, realm_id: &str, scope_id: &str) -> ApiResult<bool>;

    async fn load_client_scope_by_scope_id(
        &self,
        realm_id: &str,
        scope_id: &str,
    ) -> ApiResult<Option<ClientScopeModel>>;

    async fn load_client_scope_by_realm(&self, realm_id: &str) -> ApiResult<Vec<ClientScopeModel>>;

    async fn add_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        scope_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()>;

    async fn remove_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        scope_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()>;

    async fn add_client_scope_role_mapping(
        &self,
        realm_id: &str,
        scope_id: &str,
        role_id: &str,
    ) -> ApiResult<()>;

    async fn remove_client_scope_role_mapping(
        &self,
        realm_id: &str,
        scope_id: &str,
        role_id: &str,
    ) -> ApiResult<()>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IClientScopeService)]
pub struct ClientScopeService {
    #[shaku(inject)]
    client_scope_provider: Arc<dyn IProtocolMapperProvider>,
}

#[async_trait]
impl IClientScopeService for ClientScopeService {
    async fn create_client_scope(&self, scope: ClientScopeModel) -> ApiResult<ClientScopeModel> {
        todo!();
    }

    async fn update_client_scope(&self, scope: ClientScopeModel) -> ApiResult<()> {
        todo!();
    }

    async fn delete_client_scope(&self, realm_id: &str, scope_id: &str) -> ApiResult<bool> {
        todo!();
    }

    async fn load_client_scope_by_scope_id(
        &self,
        realm_id: &str,
        scope_id: &str,
    ) -> ApiResult<Option<ClientScopeModel>> {
        todo!();
    }

    async fn load_client_scope_by_realm(&self, realm_id: &str) -> ApiResult<Vec<ClientScopeModel>> {
        todo!();
    }

    async fn add_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        scope_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        todo!();
    }

    async fn remove_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        scope_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        todo!();
    }

    async fn add_client_scope_role_mapping(
        &self,
        realm_id: &str,
        scope_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        todo!();
    }

    async fn remove_client_scope_role_mapping(
        &self,
        realm_id: &str,
        scope_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        todo!();
    }
}
