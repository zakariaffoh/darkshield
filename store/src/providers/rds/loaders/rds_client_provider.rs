use std::sync::Arc;

use async_trait::async_trait;
use models::{
    auditable::AuditableModel,
    entities::{
        authz::RoleModel,
        client::{ClientModel, ClientScopeModel, ProtocolEnum, ProtocolMapperModel},
    },
};
use shaku::Component;
use tokio_postgres::Row;

use crate::providers::{
    core::builder::*,
    interfaces::client_provider::{IClientProvider, IClientScopeProvider, IProtocolMapperProvider},
    rds::{client::postgres_client::IDataBaseManager, tables::client_tables},
};

use super::rds_authz_providers::RdsRoleProvider;

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IProtocolMapperProvider)]
pub struct RdsProtocolMapperProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsProtocolMapperProvider {
    pub fn read_protocol_mapper_record(&self, row: Row) -> ProtocolMapperModel {
        ProtocolMapperModel {
            mapper_id: row.get("mapper_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            mapper_type: row.get("mapper_type"),
            protocol: row.get("protocol"),
            configs: row.get("configs"),
            metadata: Some(AuditableModel {
                tenant: row.get("tenant"),
                created_by: row.get("created_by"),
                updated_by: row.get("updated_by"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                version: row.get("version"),
            }),
        }
    }
}

#[allow(dead_code)]
#[async_trait]
impl IProtocolMapperProvider for RdsProtocolMapperProvider {
    async fn create_protocol_mapper(&self, mapper: &ProtocolMapperModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_protocol_mapper_sql = InsertRequestBuilder::new()
            .table_name(client_tables::PROTOCOL_MAPPER_TABLE.table_name.clone())
            .columns(client_tables::PROTOCOL_MAPPER_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_protocol_mapper_stmt = client
            .prepare_cached(&create_protocol_mapper_sql)
            .await
            .unwrap();
        let metadata = mapper.metadata.as_ref().unwrap();

        let response = client
            .execute(
                &create_protocol_mapper_stmt,
                &[
                    &metadata.tenant,
                    &mapper.realm_id,
                    &mapper.mapper_id,
                    &mapper.name,
                    &mapper.protocol,
                    &mapper.mapper_type,
                    &mapper.configs,
                    &metadata.created_by,
                    &metadata.created_at,
                    &metadata.version,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }

    async fn update_protocol_mapper(&self, mapper: &ProtocolMapperModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_protocol_mapper_sql = UpdateRequestBuilder::new()
            .table_name(client_tables::PROTOCOL_MAPPER_TABLE.table_name.clone())
            .columns(client_tables::PROTOCOL_MAPPER_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("mapper_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_protocol_mapper_stmt = client
            .prepare_cached(&update_protocol_mapper_sql)
            .await
            .unwrap();
        let metadata = mapper.metadata.as_ref().unwrap();

        let response = client
            .execute(
                &update_protocol_mapper_stmt,
                &[
                    &mapper.name,
                    &mapper.protocol,
                    &mapper.mapper_type,
                    &mapper.configs,
                    &metadata.updated_by,
                    &metadata.updated_at,
                    &metadata.tenant,
                    &mapper.realm_id,
                    &mapper.mapper_id,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }

    async fn load_protocol_mapper_by_mapper_id(
        &self,
        realm_id: &str,
        mapper_id: &str,
    ) -> Result<Option<ProtocolMapperModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_protocol_mapper_sql = SelectRequestBuilder::new()
            .table_name(client_tables::PROTOCOL_MAPPER_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("mapper_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_protocol_mapper_stmt = client
            .prepare_cached(&load_protocol_mapper_sql)
            .await
            .unwrap();
        let result = client
            .query_opt(&load_protocol_mapper_stmt, &[&realm_id, &mapper_id])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_protocol_mapper_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn delete_protocol_mapper(&self, realm_id: &str, mapper_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_protocol_mapper_sql = DeleteQueryBuilder::new()
            .table_name(client_tables::PROTOCOL_MAPPER_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("mapper_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let delete_protocol_mapper_stmt = client
            .prepare_cached(&delete_protocol_mapper_sql)
            .await
            .unwrap();
        let result = client
            .execute(&delete_protocol_mapper_stmt, &[&realm_id, &mapper_id])
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn exists_protocol_mapper_by_id(
        &self,
        realm_id: &str,
        mapper_id: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_protocol_mapper_sql = SelectCountRequestBuilder::new()
            .table_name(client_tables::PROTOCOL_MAPPER_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("mapper_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_protocol_mapper_stmt = client
            .prepare_cached(&load_protocol_mapper_sql)
            .await
            .unwrap();
        let result = client
            .query_one(&load_protocol_mapper_stmt, &[&realm_id, &mapper_id])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, u32>(0) as u32 > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn load_protocol_mappers_by_client_scope_id(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<Vec<ProtocolMapperModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_protocol_mapper_stmt = client
            .prepare_cached(
                &client_tables::PROTOCOL_MAPPER_TABLE_SELECT_PROTOCOL_MAPPER_BY_CLIENT_SCOPE_ID_QUERY,
            )
            .await
            .unwrap();
        let result = client
            .query(&load_protocol_mapper_stmt, &[&realm_id, &client_scope_id])
            .await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_protocol_mapper_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_protocol_mappers_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<ProtocolMapperModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_protocol_mapper_stmt = client
            .prepare_cached(
                &client_tables::PROTOCOL_MAPPER_TABLE_SELECT_PROTOCOL_MAPPER_BY_CLIENT_ID_QUERY,
            )
            .await
            .unwrap();
        let result = client
            .query(&load_protocol_mapper_stmt, &[&realm_id, &client_id])
            .await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_protocol_mapper_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_protocol_mappers_by_protocol(
        &self,
        realm_id: &str,
        protocol: ProtocolEnum,
    ) -> Result<Vec<ProtocolMapperModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_protocol_mapper_sql = SelectRequestBuilder::new()
            .table_name(client_tables::PROTOCOL_MAPPER_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("protocol".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_protocol_mapper_stmt = client
            .prepare_cached(&load_protocol_mapper_sql)
            .await
            .unwrap();
        let result = client
            .query(&load_protocol_mapper_stmt, &[&realm_id, &protocol])
            .await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_protocol_mapper_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IClientScopeProvider)]
pub struct RdsClientScopeProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsClientScopeProvider {
    fn read_client_scope_record(
        &self,
        row: Row,
        roles: Vec<RoleModel>,
        mappers: Vec<ProtocolMapperModel>,
    ) -> ClientScopeModel {
        ClientScopeModel {
            client_scope_id: row.get("client_scope_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            description: row.get("description"),
            protocol: row.get("protocol"),
            default_scope: row.get("default_scope"),
            roles: Some(roles),
            protocol_mappers: Some(mappers),
            configs: row.get("configs"),
            metadata: Some(AuditableModel {
                tenant: row.get("tenant"),
                created_by: row.get("created_by"),
                updated_by: row.get("updated_by"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                version: row.get("version"),
            }),
        }
    }
}

#[allow(dead_code)]
#[async_trait]
impl IClientScopeProvider for RdsClientScopeProvider {
    async fn create_client_scope(&self, client_scope: &ClientScopeModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_client_scope_sql = InsertRequestBuilder::new()
            .table_name(client_tables::CLIENT_SCOPE_TABLE.table_name.clone())
            .columns(client_tables::CLIENT_SCOPE_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_client_scope_stmt = client
            .prepare_cached(&create_client_scope_sql)
            .await
            .unwrap();

        let metadata = client_scope.metadata.as_ref().unwrap();

        let response = client
            .execute(
                &create_client_scope_stmt,
                &[
                    &metadata.tenant,
                    &client_scope.realm_id,
                    &client_scope.client_scope_id,
                    &client_scope.name,
                    &client_scope.description,
                    &client_scope.protocol,
                    &client_scope.default_scope,
                    &client_scope.configs,
                    &metadata.created_by,
                    &metadata.created_at,
                    &metadata.version,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }

    async fn update_client_scope(&self, client_scope: &ClientScopeModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_client_scope_sql = UpdateRequestBuilder::new()
            .table_name(client_tables::CLIENT_SCOPE_TABLE.table_name.clone())
            .columns(client_tables::CLIENT_SCOPE_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_scope_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_client_scope_stmt = client
            .prepare_cached(&update_client_scope_sql)
            .await
            .unwrap();
        let metadata = client_scope.metadata.as_ref().unwrap();

        let response = client
            .execute(
                &update_client_scope_stmt,
                &[
                    &client_scope.name,
                    &client_scope.description,
                    &client_scope.protocol,
                    &client_scope.default_scope,
                    &client_scope.configs,
                    &metadata.updated_by,
                    &metadata.updated_at,
                    &metadata.tenant,
                    &client_scope.realm_id,
                    &client_scope.client_scope_id,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }

    async fn load_client_scope_by_client_scope_id(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<Option<ClientScopeModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();

        let load_client_scope_sql = SelectRequestBuilder::new()
            .table_name(client_tables::PROTOCOL_MAPPER_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("mapper_id".to_string()),
            ])
            .sql_query()
            .unwrap();
        let result = client
            .query_opt(&load_client_scope_sql, &[&realm_id, &client_scope_id])
            .await;

        match result {
            Ok(res) => {
                if let Some(row) = res {
                    let scope_roles_stmt = client
                        .prepare_cached(
                            &client_tables::CLIENT_SCOPE_TABLE_SELECT_CLIENT_SCOPE_ROLES,
                        )
                        .await
                        .unwrap();
                    let roles_rows = client
                        .query(&scope_roles_stmt, &[&realm_id, &client_scope_id])
                        .await
                        .unwrap();

                    let role_reader = RdsRoleProvider {
                        database_manager: self.database_manager.clone(),
                    };

                    let roles = roles_rows
                        .into_iter()
                        .map(|row| role_reader.read_role_record(row))
                        .collect();

                    let protocol_mapper_stmt = client
                        .prepare_cached(
                            &client_tables::CLIENT_SCOPE_TABLE_SELECT_CLIENT_SCOPE_PROTOCOL_MAPPERS,
                        )
                        .await
                        .unwrap();
                    let protocol_mapper_rows = client
                        .query(&protocol_mapper_stmt, &[&realm_id, &client_scope_id])
                        .await
                        .unwrap();

                    let protocol_mapper_reader = RdsProtocolMapperProvider {
                        database_manager: self.database_manager.clone(),
                    };

                    let protocol_mappers = protocol_mapper_rows
                        .into_iter()
                        .map(|row| protocol_mapper_reader.read_protocol_mapper_record(row))
                        .collect();

                    Ok(Some(self.read_client_scope_record(
                        row,
                        roles,
                        protocol_mappers,
                    )))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn delete_client_scope(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

        let delete_client_scope_sql = DeleteQueryBuilder::new()
            .table_name(client_tables::CLIENT_SCOPE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_scope_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let mut client = client.unwrap();
        let delete_roles_stmt = client
            .prepare_cached(&client_tables::CLIENT_SCOPE_TABLE_DELETE_CLIENT_SCOPE_ROLES)
            .await
            .unwrap();

        let delete_protocol_mapper_stmt = client
            .prepare_cached(&client_tables::CLIENT_SCOPE_TABLE_DELETE_CLIENT_SCOPE_PROTOCOL_MAPPERS)
            .await
            .unwrap();

        /* Run in transaction */
        let transaction = client.transaction().await;
        match transaction {
            Ok(trx) => {
                trx.execute(&delete_client_scope_sql, &[&realm_id, &client_scope_id])
                    .await
                    .unwrap();

                trx.execute(&delete_protocol_mapper_stmt, &[&realm_id, &client_scope_id])
                    .await
                    .unwrap();

                trx.execute(&delete_roles_stmt, &[&realm_id, &client_scope_id])
                    .await
                    .unwrap();
                trx.commit().await.unwrap();
                Ok(())
            }
            Err(err) => Err(err.to_string()),
        }
    }
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IClientProvider)]
pub struct RdsClientProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsClientProvider {
    fn read_client_record(&self, row: Row) -> ClientModel {
        ClientModel {
            client_id: row.get("client_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            display_name: row.get("display_name"),
            description: row.get("description"),
            enabled: row.get("enabled"),
            web_origins: row.get("web_origins"),
            redirect_uris: row.get("redirect_uris"),
            registration_token: row.get("registration_token"),
            secret: row.get("secret"),
            public_client: row.get("public_client"),
            full_scope_allowed: row.get("full_scope_allowed"),
            protocol: row.get("protocol"),
            root_url: row.get("root_url"),
            consent_required: row.get("consent_required"),
            authorization_code_flow_enabled: row.get("authorization_code_flow_enabled"),
            implicit_flow_enabled: row.get("implicit_flow_enabled"),
            direct_grants_enabled: row.get("direct_grants_enabled"),
            standard_flow_enabled: row.get("standard_flow_enabled"),
            is_surrogate_auth_required: row.get("is_surrogate_auth_required"),
            bearer_only: row.get("bearer_only"),
            front_channel_logout: row.get("front_channel_logout"),
            attributes: row.get("attributes"),
            not_before: row.get("not_before"),
            client_authenticator_type: row.get("client_authenticator_type"),
            service_account_enabled: row.get("service_account_enabled"),
            auth_flow_binding_overrides: row.get("auth_flow_binding_overrides"),
            metadata: Some(AuditableModel {
                tenant: row.get("tenant"),
                created_by: row.get("created_by"),
                updated_by: row.get("updated_by"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                version: row.get("version"),
            }),
        }
    }
}

#[async_trait]
impl IClientProvider for RdsClientProvider {
    async fn create_client(&self, client: &ClientModel) -> Result<(), String> {
        todo!()
    }

    async fn update_client(&self, client: &ClientModel) -> Result<(), String> {
        todo!()
    }

    async fn load_client_by_name(
        &self,
        realm_id: &str,
        client_name: &str,
    ) -> Result<Option<ClientModel>, String> {
        todo!()
    }

    async fn load_client_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Option<ClientModel>, String> {
        todo!()
    }

    async fn load_clients_by_realm_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<ClientModel>, String> {
        todo!()
    }

    async fn add_client_role(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        todo!()
    }

    async fn remove_client_role(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        todo!()
    }

    async fn add_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> Result<(), String> {
        todo!()
    }

    async fn remove_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> Result<(), String> {
        todo!()
    }

    async fn add_client_protocol_mapper_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> Result<(), String> {
        todo!()
    }

    async fn remove_client_protocol_mapper_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> Result<(), String> {
        todo!()
    }

    async fn load_client_protocol_mappers_ids(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<String>, String> {
        todo!()
    }

    async fn load_client_scopes_ids(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<String>, String> {
        todo!()
    }

    async fn load_client_roles_scope(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<RoleModel>, String> {
        todo!()
    }

    async fn count_clients(&self, realm_id: &str) -> Result<u64, String> {
        todo!()
    }

    async fn load_client_by_role_id(&self, realm_id: &str, role_id: &str) -> Result<u64, String> {
        todo!()
    }
}
