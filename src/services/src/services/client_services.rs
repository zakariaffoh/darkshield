use async_trait::async_trait;
use commons::ApiResult;
use models::auditable::AuditableModel;
use models::entities::authz::RoleModel;
use models::entities::client::ClientModel;
use models::entities::client::ClientScopeModel;
use models::entities::client::ProtocolEnum;
use models::entities::client::ProtocolMapperModel;
use models::entities::user::UserModel;
use shaku::Component;
use shaku::Interface;
use std::str::FromStr;
use std::sync::Arc;
use store::providers::interfaces::authz_provider::IRoleProvider;
use store::providers::interfaces::client_provider::IClientProvider;
use store::providers::interfaces::client_provider::IClientScopeProvider;
use store::providers::interfaces::client_provider::IProtocolMapperProvider;

#[async_trait]
pub trait IClientService: Interface {
    async fn create_client(&self, client: ClientModel) -> ApiResult<ClientModel>;
    async fn update_client(&self, realm: ClientModel) -> ApiResult<()>;
    async fn delete_client(&self, realm_id: &str, client_id: &str) -> ApiResult<()>;
    async fn load_client_by_id(&self, realm_id: &str, client_id: &str) -> ApiResult<ClientModel>;
    async fn load_clients_by_realm(&self, realm_id: &str) -> ApiResult<Vec<ClientModel>>;
    async fn count_clients_by_realm(&self, realm_id: &str) -> ApiResult<i64>;
    async fn load_client_roles_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<RoleModel>>;

    async fn add_client_role_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> ApiResult<()>;

    async fn remove_client_role_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> ApiResult<()>;

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

    async fn load_protocols_mappers_by_client_id(
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

    #[shaku(inject)]
    client_scope_provider: Arc<dyn IClientScopeProvider>,

    #[shaku(inject)]
    protocol_mapper_provider: Arc<dyn IProtocolMapperProvider>,

    #[shaku(inject)]
    role_provider: Arc<dyn IRoleProvider>,
}

#[async_trait]
impl IClientService for ClientService {
    async fn create_client(&self, client: ClientModel) -> ApiResult<ClientModel> {
        let existing_client = self
            .client_provider
            .client_exists_by_client_id(&client.realm_id, &client.client_id)
            .await;
        if let Ok(response) = existing_client {
            if response {
                log::error!(
                    "client: {} already exists in realm: {}",
                    &client.client_id,
                    &client.realm_id
                );
                return ApiResult::from_error(409, "500", "client already exists");
            }
        }
        let mut client = client;
        client.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_client = self.client_provider.create_client(&client).await;
        match created_client {
            Ok(_) => ApiResult::Data(client),
            Err(_) => ApiResult::from_error(500, "500", "failed to create client"),
        }
    }
    async fn update_client(&self, client: ClientModel) -> ApiResult<()> {
        let existing_client = self
            .client_provider
            .client_exists_by_client_id(&client.realm_id, &client.client_id)
            .await;
        if let Ok(res) = existing_client {
            if !res {
                log::error!(
                    "client: {} not found in realm: {}",
                    &client.client_id,
                    &client.realm_id
                );
                return ApiResult::from_error(404, "404", "client not found");
            }
        }
        let mut client = client;
        client.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_client = self.client_provider.update_client(&client).await;
        match updated_client {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to update client"),
        }
    }

    async fn delete_client(&self, realm_id: &str, client_id: &str) -> ApiResult<()> {
        let existing_client = self
            .client_provider
            .client_exists_by_client_id(&realm_id, &client_id)
            .await;
        if let Ok(res) = existing_client {
            if !res {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(404, "404", "client not found");
            }
        }
        let response = self
            .client_provider
            .delete_clients_by_client_id(&realm_id, &client_id)
            .await;
        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to delete client"),
        }
    }

    async fn load_client_by_id(&self, realm_id: &str, client_id: &str) -> ApiResult<ClientModel> {
        let loaded_client = self
            .client_provider
            .load_client_by_client_id(&realm_id, &client_id)
            .await;
        match loaded_client {
            Ok(client_record) => ApiResult::<ClientModel>::from_option(client_record),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn load_clients_by_realm(&self, realm_id: &str) -> ApiResult<Vec<ClientModel>> {
        let loaded_clients = self
            .client_provider
            .load_clients_by_realm_id(&realm_id)
            .await;
        match loaded_clients {
            Ok(clients) => {
                log::info!(
                    "[{}] clients loaded for realm: {}",
                    clients.len(),
                    &realm_id
                );
                if clients.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(clients)
                }
            }
            Err(err) => {
                log::error!("Failed to load clients from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    async fn count_clients_by_realm(&self, realm_id: &str) -> ApiResult<i64> {
        let count_clients = self.client_provider.count_clients(&realm_id).await;
        match count_clients {
            Ok(res) => ApiResult::from_data(res),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn load_client_roles_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<RoleModel>> {
        let loaded_client_roles = self
            .role_provider
            .load_client_roles(&realm_id, &client_id)
            .await;
        match loaded_client_roles {
            Ok(roles) => {
                log::info!(
                    "[{}] client roles loaded for realm: {}",
                    roles.len(),
                    &realm_id
                );
                if roles.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(roles)
                }
            }
            Err(err) => {
                log::error!("Failed to load clients from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    async fn add_client_role_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let existing_client = self
            .client_provider
            .client_exists_by_client_id(&realm_id, &client_id)
            .await;
        if let Ok(response) = existing_client {
            if !response {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(409, "404", "client not found");
            }
        }

        let existing_role = self
            .role_provider
            .client_role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = self
            .client_provider
            .add_client_role(&realm_id, &client_id, &role_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to add client role mapping"),
        }
    }

    async fn remove_client_role_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let existing_client = self
            .client_provider
            .client_exists_by_client_id(&realm_id, &client_id)
            .await;
        if let Ok(response) = existing_client {
            if !response {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(409, "404", "client not found");
            }
        }

        let existing_role = self
            .role_provider
            .client_role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = self
            .client_provider
            .remove_client_role(&realm_id, &client_id, &role_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to remove client role mapping"),
        }
    }

    async fn add_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> ApiResult<()> {
        let existing_client = self
            .client_provider
            .client_exists_by_client_id(&realm_id, &client_id)
            .await;
        if let Ok(response) = existing_client {
            if !response {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(409, "404", "client not found");
            }
        }

        let existing_client_scope = self
            .client_scope_provider
            .client_scope_exists_by_scope_id(&realm_id, &client_scope_id)
            .await;
        if let Ok(res) = existing_client_scope {
            if !res {
                log::error!(
                    "client scope: {} not found in realm: {}",
                    &client_scope_id,
                    &realm_id,
                );
                return ApiResult::from_error(409, "404", "client scope not found");
            }
        }

        let response = self
            .client_provider
            .add_client_scope_mapping(&realm_id, &client_id, &client_scope_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to add client scope mapping"),
        }
    }

    async fn remove_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> ApiResult<()> {
        let existing_client = self
            .client_provider
            .client_exists_by_client_id(&realm_id, &client_id)
            .await;
        if let Ok(response) = existing_client {
            if !response {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(409, "404", "client not found");
            }
        }

        let existing_client_scope = self
            .client_scope_provider
            .client_scope_exists_by_scope_id(&realm_id, &client_scope_id)
            .await;
        if let Ok(res) = existing_client_scope {
            if !res {
                log::error!(
                    "client scope: {} not found in realm: {}",
                    &client_scope_id,
                    &realm_id,
                );
                return ApiResult::from_error(409, "404", "client scope not found");
            }
        }

        let response = self
            .client_provider
            .remove_client_scope_mapping(&realm_id, &client_id, &client_scope_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to remove client scope mapping"),
        }
    }

    async fn load_client_scopes_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ClientScopeModel>> {
        let loaded_client_scopes = self
            .client_scope_provider
            .load_client_scopes_by_client_id(&realm_id, &client_id)
            .await;
        match loaded_client_scopes {
            Ok(scopes) => {
                log::info!(
                    "[{}] client scopes loaded for client: {} realm: {}",
                    scopes.len(),
                    &client_id,
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
                    "Failed to load clients scopes for client: {} realm: {}",
                    &client_id,
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    async fn add_client_protocol_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        let existing_client = self
            .client_provider
            .client_exists_by_client_id(&realm_id, &client_id)
            .await;
        if let Ok(response) = existing_client {
            if !response {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(409, "404", "client not found");
            }
        }

        let existing_protocol_mapper = self
            .protocol_mapper_provider
            .exists_protocol_mapper_by_id(&realm_id, &mapper_id)
            .await;
        if let Ok(res) = existing_protocol_mapper {
            if !res {
                log::error!(
                    "protocol mapper: {} not found in realm: {}",
                    &mapper_id,
                    &realm_id,
                );
                return ApiResult::from_error(409, "404", "protocol mapper not found");
            }
        }

        let response = self
            .client_provider
            .add_client_protocol_mapper_mapping(&realm_id, &client_id, &mapper_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to add protocol mapper to client"),
        }
    }

    async fn remove_client_protocol_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        let existing_client = self
            .client_provider
            .client_exists_by_client_id(&realm_id, &client_id)
            .await;
        if let Ok(response) = existing_client {
            if !response {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(409, "404", "client not found");
            }
        }

        let existing_protocol_mapper = self
            .protocol_mapper_provider
            .exists_protocol_mapper_by_id(&realm_id, &mapper_id)
            .await;
        if let Ok(res) = existing_protocol_mapper {
            if !res {
                log::error!(
                    "protocol mapper: {} not found in realm: {}",
                    &mapper_id,
                    &realm_id,
                );
                return ApiResult::from_error(409, "404", "protocol mapper not found");
            }
        }

        let response = self
            .client_provider
            .remove_client_protocol_mapper_mapping(&realm_id, &client_id, &mapper_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => {
                ApiResult::from_error(500, "500", "failed to remove protocol mapper to client")
            }
        }
    }

    async fn load_protocols_mappers_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>> {
        let loaded_protocols_mappers = self
            .protocol_mapper_provider
            .load_protocol_mappers_by_client_id(&realm_id, &client_id)
            .await;
        match loaded_protocols_mappers {
            Ok(mappers) => {
                log::info!(
                    "[{}] protocols mappers loaded for realm: {}",
                    mappers.len(),
                    &realm_id
                );
                if mappers.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(mappers)
                }
            }
            Err(err) => {
                log::error!("Failed to load clients from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    async fn load_associated_service_acount_by_client_id(
        &self,
        _realm_id: &str,
        _client_id: &str,
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

    async fn delete_protocol_mapper(&self, realm_id: &str, mapper_id: &str) -> ApiResult<()>;

    async fn load_protocol_mapper_by_mapper_id(
        &self,
        realm_id: &str,
        mapper_id: &str,
    ) -> ApiResult<ProtocolMapperModel>;

    async fn load_protocol_mappers_by_realm(
        &self,
        realm_id: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>>;

    async fn load_protocol_mapper_by_protocol(
        &self,
        realm_id: &str,
        protocol: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>>;

    async fn load_protocol_mappers_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>>;
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
        let existing_protocol_mapper = self
            .protocol_mapper_provider
            .exists_protocol_mapper_by_name(&mapper.realm_id, &mapper.name)
            .await;
        if let Ok(response) = existing_protocol_mapper {
            if response {
                log::error!(
                    "protocol mapper: {} already exists in realm: {}",
                    &mapper.name,
                    &mapper.realm_id
                );
                return ApiResult::from_error(409, "500", "protocol mapper already exists");
            }
        }
        let mut mapper = mapper;
        mapper.mapper_id = uuid::Uuid::new_v4().to_string();
        mapper.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_mapper = self
            .protocol_mapper_provider
            .create_protocol_mapper(&mapper)
            .await;
        match created_mapper {
            Ok(_) => ApiResult::Data(mapper),
            Err(_) => ApiResult::from_error(500, "500", "failed to create protocol mapper"),
        }
    }

    async fn update_protocol_mapper(&self, mapper: ProtocolMapperModel) -> ApiResult<()> {
        let existing_protocol_mapper = self
            .protocol_mapper_provider
            .exists_protocol_mapper_by_id(&mapper.realm_id, &mapper.mapper_id)
            .await;
        if let Ok(res) = existing_protocol_mapper {
            if !res {
                log::error!(
                    "protocol mapper: {} not found in realm: {}",
                    &mapper.name,
                    &mapper.realm_id
                );
                return ApiResult::from_error(404, "404", "protocol mapper not found");
            }
        }
        let mut mapper = mapper;
        mapper.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_protocol_mapper = self
            .protocol_mapper_provider
            .update_protocol_mapper(&mapper)
            .await;
        match updated_protocol_mapper {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to update protocol mapper"),
        }
    }

    async fn delete_protocol_mapper(&self, realm_id: &str, mapper_id: &str) -> ApiResult<()> {
        let existing_protocol_mapper = self
            .protocol_mapper_provider
            .exists_protocol_mapper_by_id(&realm_id, &mapper_id)
            .await;
        if let Ok(res) = existing_protocol_mapper {
            if !res {
                log::error!(
                    "protocol mapper: {} not found in realm: {}",
                    &mapper_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "protocol mapper not found");
            }
        }
        let response = self
            .protocol_mapper_provider
            .delete_protocol_mapper(&realm_id, &mapper_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(err) => {
                log::error!(
                    "Failed to delete protocol mapper: {}, realm: {}. Error: {}",
                    &mapper_id,
                    &realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to delete protocol mapper")
            }
        }
    }

    async fn load_protocol_mapper_by_mapper_id(
        &self,
        realm_id: &str,
        mapper_id: &str,
    ) -> ApiResult<ProtocolMapperModel> {
        let loaded_protocol_mapper = self
            .protocol_mapper_provider
            .load_protocol_mapper_by_mapper_id(&realm_id, &mapper_id)
            .await;
        match loaded_protocol_mapper {
            Ok(mapper) => ApiResult::<ProtocolMapperModel>::from_option(mapper),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn load_protocol_mappers_by_realm(
        &self,
        realm_id: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>> {
        let loaded_protocol_mapper = self
            .protocol_mapper_provider
            .load_protocol_mappers_by_realm(&realm_id)
            .await;
        match loaded_protocol_mapper {
            Ok(mapper) => ApiResult::from_data(mapper),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn load_protocol_mapper_by_protocol(
        &self,
        realm_id: &str,
        protocol: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>> {
        let protocol_enum = ProtocolEnum::from_str(protocol);
        if let Err(err) = protocol_enum {
            return ApiResult::<Vec<ProtocolMapperModel>>::from_error(400, "400", &err);
        }

        let loaded_protocol_mappers = self
            .protocol_mapper_provider
            .load_protocol_mappers_by_protocol(&realm_id, protocol_enum.unwrap())
            .await;

        match loaded_protocol_mappers {
            Ok(mappers) => {
                log::info!(
                    "[{}] protocol mappers loaded for protocol: {} realm: {}",
                    mappers.len(),
                    &protocol,
                    &realm_id
                );
                if mappers.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(mappers)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load clients scopes for client_id: {} realm: {}",
                    &protocol,
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    async fn load_protocol_mappers_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>> {
        let loaded_protocol_mappers = self
            .protocol_mapper_provider
            .load_protocol_mappers_by_client_id(&realm_id, client_id)
            .await;
        match loaded_protocol_mappers {
            Ok(mappers) => {
                log::info!(
                    "[{}] protocol mappers loaded for client_id: {} realm: {}",
                    mappers.len(),
                    &client_id,
                    &realm_id
                );
                if mappers.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(mappers)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load clients scopes for client: {} realm: {}",
                    &client_id,
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }
}

#[async_trait]
pub trait IClientScopeService: Interface {
    async fn create_client_scope(&self, scope: ClientScopeModel) -> ApiResult<ClientScopeModel>;

    async fn update_client_scope(&self, scope: ClientScopeModel) -> ApiResult<()>;

    async fn delete_client_scope(&self, realm_id: &str, client_scope_id: &str) -> ApiResult<()>;

    async fn load_client_scope_by_scope_id(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> ApiResult<ClientScopeModel>;

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
    client_scope_provider: Arc<dyn IClientScopeProvider>,

    #[shaku(inject)]
    protocol_mapper_provider: Arc<dyn IProtocolMapperProvider>,

    #[shaku(inject)]
    role_provider: Arc<dyn IRoleProvider>,
}

#[async_trait]
impl IClientScopeService for ClientScopeService {
    async fn create_client_scope(
        &self,
        client_scope: ClientScopeModel,
    ) -> ApiResult<ClientScopeModel> {
        let existing_client_scope = self
            .client_scope_provider
            .client_scope_exists_by_name(&client_scope.realm_id, &client_scope.name)
            .await;
        if let Ok(response) = existing_client_scope {
            if response {
                log::error!(
                    "client scope: {} already exists in realm: {}",
                    &client_scope.name,
                    &client_scope.realm_id
                );
                return ApiResult::from_error(409, "500", "client scope already exists");
            }
        }
        let mut client_scope = client_scope;
        client_scope.client_scope_id = uuid::Uuid::new_v4().to_string();
        client_scope.metadata =
            AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_client_scope = self
            .client_scope_provider
            .create_client_scope(&client_scope)
            .await;
        match created_client_scope {
            Ok(_) => ApiResult::Data(client_scope),
            Err(_) => ApiResult::from_error(500, "500", "failed to create client scope"),
        }
    }

    async fn update_client_scope(&self, client_scope: ClientScopeModel) -> ApiResult<()> {
        let existing_client_scope = self
            .client_scope_provider
            .client_scope_exists_by_scope_id(&client_scope.realm_id, &client_scope.client_scope_id)
            .await;
        if let Ok(response) = existing_client_scope {
            if !response {
                log::error!(
                    "client scope: {} not found in realm: {}",
                    &client_scope.name,
                    &client_scope.realm_id
                );
                return ApiResult::from_error(404, "404", "client scope not found");
            }
        }
        let mut client_scope = client_scope;
        client_scope.metadata =
            AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_client_scope = self
            .client_scope_provider
            .update_client_scope(&client_scope)
            .await;
        match updated_client_scope {
            Ok(_) => ApiResult::no_content(),
            Err(err) => {
                log::error!(
                    "Failed to update client scope: {}, realm: {}. Error: {}",
                    &client_scope.client_scope_id,
                    &client_scope.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update client scope")
            }
        }
    }

    async fn delete_client_scope(&self, realm_id: &str, client_scope_id: &str) -> ApiResult<()> {
        let existing_client_scope = self
            .client_scope_provider
            .load_client_scope_by_client_scope_id(&realm_id, &client_scope_id)
            .await;
        if let Ok(response) = existing_client_scope {
            if response.is_none() {
                log::error!(
                    "client scope: {} not found in realm: {}",
                    &client_scope_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "client scope not found");
            }
        }
        let deleted_client_scope = self
            .client_scope_provider
            .delete_client_scope(&realm_id, &client_scope_id)
            .await;
        match deleted_client_scope {
            Ok(_) => ApiResult::no_content(),
            Err(err) => {
                log::error!(
                    "Failed to delete client scope: {}, realm: {}. Error: {}",
                    &client_scope_id,
                    &realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to delete client scope")
            }
        }
    }

    async fn load_client_scope_by_scope_id(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> ApiResult<ClientScopeModel> {
        let loaded_client_scope = self
            .client_scope_provider
            .load_client_scope_by_client_scope_id(&realm_id, &client_scope_id)
            .await;
        match loaded_client_scope {
            Ok(scope) => ApiResult::<ClientScopeModel>::from_option(scope),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    async fn add_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        scope_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        let existing_client_scope = self
            .client_scope_provider
            .client_scope_exists_by_scope_id(&realm_id, &scope_id)
            .await;
        if let Ok(response) = existing_client_scope {
            if !response {
                log::error!(
                    "client scope: {} not found in realm: {}",
                    &scope_id,
                    &realm_id
                );
                return ApiResult::from_error(409, "404", "client scope not found");
            }
        }

        let existing_protocol_mapper = self
            .protocol_mapper_provider
            .exists_protocol_mapper_by_id(&realm_id, &mapper_id)
            .await;
        if let Ok(res) = existing_protocol_mapper {
            if !res {
                log::error!(
                    "protocol mapper: {} not found in realm: {}",
                    &scope_id,
                    &mapper_id,
                );
                return ApiResult::from_error(409, "404", "client scope not found");
            }
        }

        let response = self
            .client_scope_provider
            .add_client_scope_protocol_mapper(&realm_id, &scope_id, &mapper_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => {
                ApiResult::from_error(500, "500", "failed to add client scope protocol mapper")
            }
        }
    }

    async fn remove_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        scope_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        let existing_client_scope = self
            .client_scope_provider
            .client_scope_exists_by_scope_id(&realm_id, &scope_id)
            .await;
        if let Ok(response) = existing_client_scope {
            if !response {
                log::error!(
                    "client scope: {} not found in realm: {}",
                    &scope_id,
                    &realm_id
                );
                return ApiResult::from_error(409, "404", "client scope not found");
            }
        }

        let existing_protocol_mapper = self
            .protocol_mapper_provider
            .exists_protocol_mapper_by_id(&realm_id, &mapper_id)
            .await;
        if let Ok(res) = existing_protocol_mapper {
            if !res {
                log::error!(
                    "protocol mapper: {} not found in realm: {}",
                    &scope_id,
                    &mapper_id,
                );
                return ApiResult::from_error(409, "404", "client scope not found");
            }
        }

        let response = self
            .client_scope_provider
            .remove_client_scope_protocol_mapper(&realm_id, &scope_id, &mapper_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => {
                ApiResult::from_error(500, "500", "failed to remove client scope protocol mapper")
            }
        }
    }

    async fn add_client_scope_role_mapping(
        &self,
        realm_id: &str,
        scope_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let existing_client_scope = self
            .client_scope_provider
            .client_scope_exists_by_scope_id(&realm_id, &scope_id)
            .await;
        if let Ok(response) = existing_client_scope {
            if !response {
                log::error!(
                    "client scope: {} not found in realm: {}",
                    &scope_id,
                    &realm_id
                );
                return ApiResult::from_error(409, "404", "client scope not found");
            }
        }

        let existing_protocol_mapper = self
            .role_provider
            .client_role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_protocol_mapper {
            if !res {
                log::error!("client role: {} not found in realm: {}", &role_id, &role_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = self
            .client_scope_provider
            .add_client_scope_role_mapping(&realm_id, &scope_id, &role_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => {
                ApiResult::from_error(500, "500", "failed to add client role client scope mapping")
            }
        }
    }

    async fn remove_client_scope_role_mapping(
        &self,
        realm_id: &str,
        scope_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let existing_client_scope = self
            .client_scope_provider
            .client_scope_exists_by_scope_id(&realm_id, &scope_id)
            .await;
        if let Ok(response) = existing_client_scope {
            if !response {
                log::error!(
                    "client scope: {} not found in realm: {}",
                    &scope_id,
                    &realm_id
                );
                return ApiResult::from_error(409, "404", "client scope not found");
            }
        }

        let existing_protocol_mapper = self
            .role_provider
            .client_role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_protocol_mapper {
            if !res {
                log::error!("client role: {} not found in realm: {}", &role_id, &role_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = self
            .client_scope_provider
            .remove_client_scope_role_mapping(&realm_id, &scope_id, &role_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(
                500,
                "500",
                "failed to remove client role client scope mapping",
            ),
        }
    }
}
