use std::str::FromStr;

use commons::ApiResult;
use log;
use services::session::session::DarkshieldSession;
use uuid;

use models::{
    auditable::AuditableModel,
    entities::{
        authz::RoleModel,
        client::{ClientModel, ClientScopeModel, ProtocolEnum, ProtocolMapperModel},
        user::UserModel,
    },
};
use services::services::{
    authz_services::IRoleService,
    client_services::{IClientScopeService, IClientService, IProtocolMapperService},
};
pub struct ClientApi;

impl ClientApi {
    pub async fn create_client(
        session: &DarkshieldSession,
        client: ClientModel,
    ) -> ApiResult<ClientModel> {
        let existing_client = session
            .services()
            .client_service()
            .client_exists_by_id(&client.realm_id, &client.client_id)
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
        client.metadata = AuditableModel::from_creator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let created_client = session
            .services()
            .client_service()
            .create_client(&client)
            .await;
        match created_client {
            Err(_) => ApiResult::from_error(500, "500", "failed to create client"),
            _ => ApiResult::Data(client),
        }
    }

    pub async fn update_client(session: &DarkshieldSession, client: ClientModel) -> ApiResult<()> {
        let existing_client = session
            .services()
            .client_service()
            .client_exists_by_id(&client.realm_id, &client.client_id)
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
        client.metadata = AuditableModel::from_updator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let updated_client = session
            .services()
            .client_service()
            .update_client(&client)
            .await;
        match updated_client {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to update client"),
        }
    }

    pub async fn delete_client(
        session: &DarkshieldSession,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<()> {
        let existing_client = session
            .services()
            .client_service()
            .client_exists_by_id(&realm_id, &client_id)
            .await;

        if let Ok(res) = existing_client {
            if !res {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(404, "404", "client not found");
            }
        }

        let response = session
            .services()
            .client_service()
            .delete_client(&realm_id, &client_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to delete client"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn load_client_by_id(
        session: &DarkshieldSession,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<ClientModel> {
        let loaded_client = session
            .services()
            .client_service()
            .load_client_by_id(&realm_id, &client_id)
            .await;

        match loaded_client {
            Ok(client_record) => ApiResult::<ClientModel>::from_option(client_record),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_client_by_ids(
        session: &DarkshieldSession,
        realm_id: &str,
        client_ids: &[&str],
    ) -> ApiResult<Vec<ClientModel>> {
        let loaded_clients = session
            .services()
            .client_service()
            .load_client_by_ids(&realm_id, &client_ids)
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

    pub async fn load_clients_by_realm(
        session: &DarkshieldSession,
        realm_id: &str,
    ) -> ApiResult<Vec<ClientModel>> {
        let loaded_clients = session
            .services()
            .client_service()
            .load_clients_by_realm(&realm_id)
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

    pub async fn count_clients_by_realm(
        session: &DarkshieldSession,
        realm_id: &str,
    ) -> ApiResult<i64> {
        let count_clients = session
            .services()
            .client_service()
            .count_clients_by_realm(&realm_id)
            .await;
        match count_clients {
            Ok(res) => ApiResult::from_data(res),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_client_roles_mapping(
        session: &DarkshieldSession,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<RoleModel>> {
        let loaded_client_roles = session
            .services()
            .client_service()
            .load_client_roles_mapping(&realm_id, &client_id)
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

    pub async fn add_client_role_mapping(
        session: &DarkshieldSession,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let existing_client = session
            .services()
            .client_service()
            .client_exists_by_id(&realm_id, &client_id)
            .await;

        if let Ok(response) = existing_client {
            if !response {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(409, "404", "client not found");
            }
        }

        let existing_role = session
            .services()
            .role_service()
            .client_role_exists_by_id(&realm_id, &role_id)
            .await;

        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = session
            .services()
            .client_service()
            .add_client_role_mapping(&realm_id, &client_id, &role_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add client role mapping"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn remove_client_role_mapping(
        session: &DarkshieldSession,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let existing_client = session
            .services()
            .client_service()
            .client_exists_by_id(&realm_id, &client_id)
            .await;

        if let Ok(response) = existing_client {
            if !response {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(409, "404", "client not found");
            }
        }

        let existing_role = session
            .services()
            .role_service()
            .client_role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = session
            .services()
            .client_service()
            .remove_client_role_mapping(&realm_id, &client_id, &role_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to remove client role mapping"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn add_client_scope_mapping(
        session: &DarkshieldSession,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> ApiResult<()> {
        let existing_client = session
            .services()
            .client_service()
            .client_exists_by_id(&realm_id, &client_id)
            .await;
        if let Ok(response) = existing_client {
            if !response {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(409, "404", "client not found");
            }
        }

        let existing_client_scope = session
            .services()
            .client_scope_service()
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

        let response = session
            .services()
            .client_service()
            .add_client_scope_mapping(&realm_id, &client_id, &client_scope_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add client scope mapping"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn remove_client_scope_mapping(
        session: &DarkshieldSession,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> ApiResult<()> {
        let existing_client = session
            .services()
            .client_service()
            .client_exists_by_id(&realm_id, &client_id)
            .await;

        if let Ok(response) = existing_client {
            if !response {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(409, "404", "client not found");
            }
        }

        let existing_client_scope = session
            .services()
            .client_scope_service()
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

        let response = session
            .services()
            .client_service()
            .remove_client_scope_mapping(&realm_id, &client_id, &client_scope_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to remove client scope mapping"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn load_client_scopes_by_client_id(
        session: &DarkshieldSession,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ClientScopeModel>> {
        let loaded_client_scopes = session
            .services()
            .client_service()
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

    pub async fn add_client_protocol_mapping(
        session: &DarkshieldSession,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        let existing_client = session
            .services()
            .client_service()
            .client_exists_by_id(&realm_id, &client_id)
            .await;
        if let Ok(response) = existing_client {
            if !response {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(409, "404", "client not found");
            }
        }

        let existing_protocol_mapper = session
            .services()
            .protocol_mapper_service()
            .protocol_mapper_exists_by_mapper_id(&realm_id, &mapper_id)
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

        let response = session
            .services()
            .client_service()
            .add_client_protocol_mapping(&realm_id, &client_id, &mapper_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(500, "500", "failed to add protocol mapper to client"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn remove_client_protocol_mapping(
        session: &DarkshieldSession,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        let existing_client = session
            .services()
            .client_service()
            .client_exists_by_id(&realm_id, &client_id)
            .await;

        if let Ok(response) = existing_client {
            if !response {
                log::error!("client: {} not found in realm: {}", &client_id, &realm_id);
                return ApiResult::from_error(409, "404", "client not found");
            }
        }

        let existing_protocol_mapper = session
            .services()
            .protocol_mapper_service()
            .protocol_mapper_exists_by_mapper_id(&realm_id, &mapper_id)
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

        let response = session
            .services()
            .client_service()
            .remove_client_protocol_mapping(&realm_id, &client_id, &mapper_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => {
                ApiResult::from_error(500, "500", "failed to remove protocol mapper to client")
            }
        }
    }

    pub async fn load_associated_service_acount_by_client_id(
        session: &DarkshieldSession,
        _realm_id: &str,
        _client_id: &str,
    ) -> ApiResult<Option<UserModel>> {
        todo!()
    }

    pub async fn create_protocol_mapper(
        session: &DarkshieldSession,
        mapper: ProtocolMapperModel,
    ) -> ApiResult<ProtocolMapperModel> {
        let existing_protocol_mapper = session
            .services()
            .protocol_mapper_service()
            .protocol_mapper_exists_by_mapper_id(&mapper.realm_id, &mapper.name)
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
        mapper.metadata = AuditableModel::from_creator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let created_mapper = session
            .services()
            .protocol_mapper_service()
            .create_protocol_mapper(&mapper)
            .await;

        match created_mapper {
            Err(_) => ApiResult::from_error(500, "500", "failed to create protocol mapper"),
            _ => ApiResult::Data(mapper),
        }
    }

    pub async fn update_protocol_mapper(
        session: &DarkshieldSession,
        mapper: ProtocolMapperModel,
    ) -> ApiResult<()> {
        let existing_protocol_mapper = session
            .services()
            .protocol_mapper_service()
            .protocol_mapper_exists_by_mapper_id(&mapper.realm_id, &mapper.mapper_id)
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
        mapper.metadata = AuditableModel::from_updator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let updated_protocol_mapper = session
            .services()
            .protocol_mapper_service()
            .update_protocol_mapper(&mapper)
            .await;
        match updated_protocol_mapper {
            Err(_) => ApiResult::from_error(500, "500", "failed to update protocol mapper"),
            _ => ApiResult::no_content(),
        }
    }

    pub async fn delete_protocol_mapper(
        session: &DarkshieldSession,
        realm_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        let existing_protocol_mapper = session
            .services()
            .protocol_mapper_service()
            .protocol_mapper_exists_by_mapper_id(&realm_id, &mapper_id)
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

        let response = session
            .services()
            .protocol_mapper_service()
            .delete_protocol_mapper(&realm_id, &mapper_id)
            .await;

        match response {
            Err(err) => {
                log::error!(
                    "Failed to delete protocol mapper: {}, realm: {}. Error: {}",
                    &mapper_id,
                    &realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to delete protocol mapper")
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn load_protocol_mapper_by_mapper_id(
        session: &DarkshieldSession,
        realm_id: &str,
        mapper_id: &str,
    ) -> ApiResult<ProtocolMapperModel> {
        let loaded_protocol_mapper = session
            .services()
            .protocol_mapper_service()
            .load_protocol_mapper_by_mapper_id(&realm_id, &mapper_id)
            .await;

        match loaded_protocol_mapper {
            Ok(mapper) => ApiResult::<ProtocolMapperModel>::from_option(mapper),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_protocol_mappers_by_realm(
        session: &DarkshieldSession,
        realm_id: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>> {
        let loaded_protocol_mapper = session
            .services()
            .protocol_mapper_service()
            .load_protocol_mappers_by_realm(&realm_id)
            .await;
        match loaded_protocol_mapper {
            Ok(mapper) => ApiResult::from_data(mapper),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_protocol_mapper_by_protocol(
        session: &DarkshieldSession,
        realm_id: &str,
        protocol: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>> {
        let protocol_enum = ProtocolEnum::from_str(protocol);
        if let Err(err) = protocol_enum {
            return ApiResult::<Vec<ProtocolMapperModel>>::from_error(400, "400", &err);
        }

        let loaded_protocol_mappers = session
            .services()
            .protocol_mapper_service()
            .load_protocol_mapper_by_protocol(&realm_id, protocol_enum.unwrap())
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

    pub async fn load_protocol_mappers_by_client_id(
        session: &DarkshieldSession,
        realm_id: &str,
        client_id: &str,
    ) -> ApiResult<Vec<ProtocolMapperModel>> {
        let loaded_protocol_mappers = session
            .services()
            .protocol_mapper_service()
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

    pub async fn create_client_scope(
        session: &DarkshieldSession,
        client_scope: ClientScopeModel,
    ) -> ApiResult<ClientScopeModel> {
        let existing_client_scope = session
            .services()
            .client_scope_service()
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
        client_scope.metadata = AuditableModel::from_creator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let created_client_scope = session
            .services()
            .client_scope_service()
            .create_client_scope(&client_scope)
            .await;
        match created_client_scope {
            Ok(_) => ApiResult::Data(client_scope),
            Err(_) => ApiResult::from_error(500, "500", "failed to create client scope"),
        }
    }

    pub async fn update_client_scope(
        session: &DarkshieldSession,
        client_scope: ClientScopeModel,
    ) -> ApiResult<()> {
        let existing_client_scope = session
            .services()
            .client_scope_service()
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
        client_scope.metadata = AuditableModel::from_updator(
            session
                .context()
                .authenticated_user()
                .metadata
                .tenant
                .to_owned(),
            session.context().authenticated_user().user_id.to_owned(),
        );
        let updated_client_scope = session
            .services()
            .client_scope_service()
            .update_client_scope(&client_scope)
            .await;
        match updated_client_scope {
            Err(err) => {
                log::error!(
                    "Failed to update client scope: {}, realm: {}. Error: {}",
                    &client_scope.client_scope_id,
                    &client_scope.realm_id,
                    err
                );
                ApiResult::from_error(500, "500", "failed to update client scope")
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn delete_client_scope(
        session: &DarkshieldSession,
        realm_id: &str,
        client_scope_id: &str,
    ) -> ApiResult<()> {
        let existing_client_scope = session
            .services()
            .client_scope_service()
            .load_client_scope_by_scope_id(&realm_id, &client_scope_id)
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
        let deleted_client_scope = session
            .services()
            .client_scope_service()
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

    pub async fn load_client_scope_by_scope_id(
        session: &DarkshieldSession,
        realm_id: &str,
        client_scope_id: &str,
    ) -> ApiResult<ClientScopeModel> {
        let loaded_client_scope = session
            .services()
            .client_scope_service()
            .load_client_scope_by_scope_id(&realm_id, &client_scope_id)
            .await;
        match loaded_client_scope {
            Ok(scope) => ApiResult::<ClientScopeModel>::from_option(scope),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn add_client_scope_protocol_mapper(
        session: &DarkshieldSession,
        realm_id: &str,
        scope_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        let existing_client_scope = session
            .services()
            .client_scope_service()
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

        let existing_protocol_mapper = session
            .services()
            .protocol_mapper_service()
            .protocol_mapper_exists_by_mapper_id(&realm_id, &mapper_id)
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

        let response = session
            .services()
            .client_scope_service()
            .add_client_scope_protocol_mapper(&realm_id, &scope_id, &mapper_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => {
                ApiResult::from_error(500, "500", "failed to add client scope protocol mapper")
            }
        }
    }

    pub async fn remove_client_scope_protocol_mapper(
        session: &DarkshieldSession,
        realm_id: &str,
        scope_id: &str,
        mapper_id: &str,
    ) -> ApiResult<()> {
        let existing_client_scope = session
            .services()
            .client_scope_service()
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

        let existing_protocol_mapper = session
            .services()
            .protocol_mapper_service()
            .protocol_mapper_exists_by_mapper_id(&realm_id, &mapper_id)
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

        let response = session
            .services()
            .client_scope_service()
            .remove_client_scope_protocol_mapper(&realm_id, &scope_id, &mapper_id)
            .await;

        match response {
            Ok(_) => ApiResult::no_content(),
            Err(_) => {
                ApiResult::from_error(500, "500", "failed to remove client scope protocol mapper")
            }
        }
    }

    pub async fn add_client_scope_role_mapping(
        session: &DarkshieldSession,
        realm_id: &str,
        scope_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let existing_client_scope = session
            .services()
            .client_scope_service()
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

        let existing_role = session
            .services()
            .role_service()
            .role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!("client role: {} not found in realm: {}", &role_id, &role_id,);
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = session
            .services()
            .client_scope_service()
            .add_client_scope_role_mapping(&realm_id, &scope_id, &role_id)
            .await;

        match response {
            Err(_) => {
                ApiResult::from_error(500, "500", "failed to add client role client scope mapping")
            }
            _ => ApiResult::no_content(),
        }
    }

    pub async fn remove_client_scope_role_mapping(
        session: &DarkshieldSession,
        realm_id: &str,
        scope_id: &str,
        role_id: &str,
    ) -> ApiResult<()> {
        let existing_client_scope = session
            .services()
            .client_scope_service()
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

        let existing_role = session
            .services()
            .role_service()
            .role_exists_by_id(&realm_id, &role_id)
            .await;
        if let Ok(res) = existing_role {
            if !res {
                log::error!(
                    "client role: {} not found in realm: {}",
                    &role_id,
                    &realm_id,
                );
                return ApiResult::from_error(409, "404", "client role not found");
            }
        }

        let response = session
            .services()
            .client_scope_service()
            .remove_client_scope_role_mapping(&realm_id, &scope_id, &role_id)
            .await;

        match response {
            Err(_) => ApiResult::from_error(
                500,
                "500",
                "failed to remove client role client scope mapping",
            ),
            _ => ApiResult::no_content(),
        }
    }
}
