use super::rds_authz_providers::RdsRoleProvider;
use crate::providers::{
    core::builder::*,
    interfaces::client_provider::{IClientProvider, IClientScopeProvider, IProtocolMapperProvider},
    rds::{client::postgres_client::IDataBaseManager, tables::client_tables},
};
use async_trait::async_trait;
use deadpool_postgres::Object;
use log;
use models::{
    auditable::AuditableModel,
    entities::{
        attributes::AttributesMap,
        authz::RoleModel,
        client::{ClientModel, ClientScopeModel, ProtocolEnum, ProtocolMapperModel},
    },
};
use postgres_types::ToSql;
use serde_json::json;
use shaku::Component;
use std::{collections::HashMap, sync::Arc};
use tokio_postgres::Row;

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IProtocolMapperProvider)]
pub struct RdsProtocolMapperProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsProtocolMapperProvider {
    pub fn read_record(row: Row) -> ProtocolMapperModel {
        let configs =
            serde_json::from_value::<AttributesMap>(row.get::<&str, serde_json::Value>("configs"))
                .map_or_else(|_| None, |p| Some(p));

        ProtocolMapperModel {
            mapper_id: row.get("mapper_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            mapper_type: row.get("mapper_type"),
            protocol: row.get("protocol"),
            configs: configs,
            metadata: AuditableModel {
                tenant: row.get("tenant"),
                created_by: row.get("created_by"),
                updated_by: row.get("updated_by"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                version: row.get("version"),
            },
        }
    }

    pub async fn load_protocol_mapper_by_query(
        client: &Object,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<ProtocolMapperModel>, String> {
        let load_protocol_mapper_stmt = client.prepare_cached(&query).await.unwrap();
        let result = client.query(&load_protocol_mapper_stmt, params).await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| RdsProtocolMapperProvider::read_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
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

        let response = client
            .execute(
                &create_protocol_mapper_stmt,
                &[
                    &mapper.metadata.tenant,
                    &mapper.realm_id,
                    &mapper.mapper_id,
                    &mapper.name,
                    &mapper.protocol,
                    &mapper.mapper_type,
                    &json!(mapper.configs),
                    &mapper.metadata.created_by,
                    &mapper.metadata.created_at,
                    &mapper.metadata.version,
                ],
            )
            .await;
        match response {
            Err(err) => {
                let error = err.to_string();
                log::error!("Failed to create protocol mapper: {}", error);
                Err(error)
            }
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

        let response = client
            .execute(
                &update_protocol_mapper_stmt,
                &[
                    &mapper.name,
                    &mapper.protocol,
                    &mapper.mapper_type,
                    &json!(mapper.configs),
                    &mapper.metadata.updated_by,
                    &mapper.metadata.updated_at,
                    &mapper.metadata.tenant,
                    &mapper.realm_id,
                    &mapper.mapper_id,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to update protocol mapper".to_string())
                }
            }
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
                    Ok(Some(RdsProtocolMapperProvider::read_record(r)))
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
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to delete protocol mapper".to_string())
                }
            }
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
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
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
                .map(|row| RdsProtocolMapperProvider::read_record(row))
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
                .map(|row| RdsProtocolMapperProvider::read_record(row))
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
                .map(|row| RdsProtocolMapperProvider::read_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn exists_protocol_mapper_by_name(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_protocol_mapper_sql = SelectCountRequestBuilder::new()
            .table_name(client_tables::PROTOCOL_MAPPER_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_protocol_mapper_stmt = client
            .prepare_cached(&load_protocol_mapper_sql)
            .await
            .unwrap();
        let result = client
            .query_one(&load_protocol_mapper_stmt, &[&realm_id, &name])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn load_protocol_mappers_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<ProtocolMapperModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_protocol_mapper_sql = SelectRequestBuilder::new()
            .table_name(client_tables::PROTOCOL_MAPPER_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_protocol_mapper_stmt = client
            .prepare_cached(&load_protocol_mapper_sql)
            .await
            .unwrap();
        let result = client.query(&load_protocol_mapper_stmt, &[&realm_id]).await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| RdsProtocolMapperProvider::read_record(row))
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
    fn read_record(
        row: &Row,
        roles: Vec<RoleModel>,
        mappers: Vec<ProtocolMapperModel>,
    ) -> ClientScopeModel {
        let configs = serde_json::from_value::<HashMap<String, Option<String>>>(
            row.get::<&str, serde_json::Value>("configs"),
        )
        .map_or_else(|_| None, |p| Some(p));
        ClientScopeModel {
            client_scope_id: row.get("client_scope_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            description: row.get("description"),
            protocol: row.get("protocol"),
            default_scope: row.get("default_scope"),
            roles: Some(roles),
            protocol_mappers: Some(mappers),
            configs: configs,
            metadata: AuditableModel {
                tenant: row.get("tenant"),
                created_by: row.get("created_by"),
                updated_by: row.get("updated_by"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                version: row.get("version"),
            },
        }
    }

    async fn read_client_scope(
        client: &Object,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<Option<ClientScopeModel>, String> {
        let load_client_scope_sql = SelectRequestBuilder::new()
            .table_name(client_tables::CLIENT_SCOPE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_scope_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let result = client
            .query_opt(&load_client_scope_sql, &[&realm_id, &client_scope_id])
            .await;

        match result {
            Ok(res) => {
                if let Some(row) = res {
                    let roles;
                    let loaded_roles = RdsRoleProvider::load_roles_by_query(
                        client,
                        &client_tables::CLIENT_SCOPE_TABLE_SELECT_CLIENT_SCOPE_ROLES,
                        &[&realm_id, &client_scope_id],
                    )
                    .await;
                    match loaded_roles {
                        Ok(rs) => {
                            roles = rs;
                        }
                        Err(err) => return Err(err.to_string()),
                    }

                    let protocol_mappers;
                    let loaded_protocol_mappers =
                        RdsProtocolMapperProvider::load_protocol_mapper_by_query(
                            client,
                            &client_tables::CLIENT_SCOPE_TABLE_SELECT_CLIENT_SCOPE_PROTOCOL_MAPPERS,
                            &[&realm_id, &client_scope_id],
                        )
                        .await;
                    match loaded_protocol_mappers {
                        Ok(pm) => {
                            protocol_mappers = pm;
                        }
                        Err(err) => return Err(err.to_string()),
                    }
                    Ok(Some(RdsClientScopeProvider::read_record(
                        &row,
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

    pub async fn load_clients_scopes_by_query(
        client: &Object,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<ClientScopeModel>, String> {
        let load_client_scope_stmt = client.prepare_cached(&query).await.unwrap();
        let result = client.query(&load_client_scope_stmt, params).await;
        match result {
            Ok(rows) => {
                let mut clients_scopes = Vec::new();
                for row in rows {
                    let realm_id = row.get("realm_id");
                    let client_scope_id = row.get("client_scope_id");
                    let cs = RdsClientScopeProvider::read_client_scope(
                        &client,
                        realm_id,
                        client_scope_id,
                    )
                    .await;
                    match cs {
                        Ok(Some(res)) => clients_scopes.push(res),
                        _ => {
                            return Err(format!(
                                "failed to read client scope {}, realm_id: {}",
                                client_scope_id, realm_id
                            ));
                        }
                    }
                }
                return Ok(clients_scopes);
            }
            Err(err) => return Err(err.to_string()),
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

        let response = client
            .execute(
                &create_client_scope_stmt,
                &[
                    &client_scope.metadata.tenant,
                    &client_scope.realm_id,
                    &client_scope.client_scope_id,
                    &client_scope.name,
                    &client_scope.description,
                    &client_scope.protocol,
                    &client_scope.default_scope,
                    &json!(client_scope.configs),
                    &client_scope.metadata.created_by,
                    &client_scope.metadata.created_at,
                    &client_scope.metadata.version,
                ],
            )
            .await;
        match response {
            Err(err) => {
                let error = err.to_string();
                log::error!("Failed to create client scope: {}", error);
                Err(error)
            }
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

        let response = client
            .execute(
                &update_client_scope_stmt,
                &[
                    &client_scope.name,
                    &client_scope.description,
                    &client_scope.protocol,
                    &client_scope.default_scope,
                    &json!(client_scope.configs),
                    &client_scope.metadata.updated_by,
                    &client_scope.metadata.updated_at,
                    &client_scope.metadata.tenant,
                    &client_scope.realm_id,
                    &client_scope.client_scope_id,
                ],
            )
            .await;
        match response {
            Err(err) => {
                let error = err.to_string();
                log::error!("Failed to create client scope: {}", error);
                Err(error)
            }
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
        RdsClientScopeProvider::read_client_scope(&client, &realm_id, &client_scope_id).await
    }

    async fn client_scope_exists_by_name(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_client_scope_sql = SelectCountRequestBuilder::new()
            .table_name(client_tables::CLIENT_SCOPE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_client_scope_stmt = client.prepare_cached(&load_client_scope_sql).await.unwrap();
        let result = client
            .query_one(&load_client_scope_stmt, &[&realm_id, &name])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn client_scope_exists_by_scope_id(
        &self,
        realm_id: &str,
        client_scope_id: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_client_scope_sql = SelectCountRequestBuilder::new()
            .table_name(client_tables::CLIENT_SCOPE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_scope_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_client_scope_stmt = client.prepare_cached(&load_client_scope_sql).await.unwrap();
        let result = client
            .query_one(&load_client_scope_stmt, &[&realm_id, &client_scope_id])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn add_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        client_scope_id: &str,
        mapper_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_client_scope_protocol_mapper_sql = InsertRequestBuilder::new()
            .table_name(
                client_tables::CLIENTS_SCOPES_PROTOCOLS_MAPPERS_TABLE
                    .table_name
                    .clone(),
            )
            .columns(
                client_tables::CLIENTS_SCOPES_PROTOCOLS_MAPPERS_TABLE
                    .insert_columns
                    .clone(),
            )
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_client_scope_protocol_stmt = client
            .prepare_cached(&create_client_scope_protocol_mapper_sql)
            .await
            .unwrap();

        let response = client
            .execute(
                &create_client_scope_protocol_stmt,
                &[&realm_id, &client_scope_id, &mapper_id],
            )
            .await;
        match response {
            Err(err) => {
                let error = err.to_string();
                log::error!(
                    "Failed to add protocol mapper to client scope: {}. Error: {}",
                    client_scope_id,
                    error
                );
                Err(error)
            }
            _ => Ok(()),
        }
    }

    async fn remove_client_scope_protocol_mapper(
        &self,
        realm_id: &str,
        client_scope_id: &str,
        mapper_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_client_scope_protocol_mapper_sql = DeleteQueryBuilder::new()
            .table_name(
                client_tables::CLIENTS_SCOPES_PROTOCOLS_MAPPERS_TABLE
                    .table_name
                    .clone(),
            )
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_scope_id".to_string()),
                SqlCriteriaBuilder::is_equals("mapper_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_client_scope_protocol_stmt = client
            .prepare_cached(&remove_client_scope_protocol_mapper_sql)
            .await
            .unwrap();
        let result = client
            .execute(
                &remove_client_scope_protocol_stmt,
                &[&realm_id, &client_scope_id, &mapper_id],
            )
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove protocol mapper from client scope".to_string())
                }
            }
        }
    }

    async fn add_client_scope_role_mapping(
        &self,
        realm_id: &str,
        client_scope_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_client_scope_role_sql = InsertRequestBuilder::new()
            .table_name(client_tables::CLIENTS_SCOPES_ROLES_TABLE.table_name.clone())
            .columns(
                client_tables::CLIENTS_SCOPES_ROLES_TABLE
                    .insert_columns
                    .clone(),
            )
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_client_scope_role_stmt = client
            .prepare_cached(&create_client_scope_role_sql)
            .await
            .unwrap();

        let response = client
            .execute(
                &create_client_scope_role_stmt,
                &[&realm_id, &client_scope_id, &role_id],
            )
            .await;
        match response {
            Err(err) => {
                let error = err.to_string();
                log::error!(
                    "Failed to add role to client scope: {}. Error: {}",
                    client_scope_id,
                    error
                );
                Err(error)
            }
            _ => Ok(()),
        }
    }

    async fn remove_client_scope_role_mapping(
        &self,
        realm_id: &str,
        client_scope_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_client_scope_role_sql = DeleteQueryBuilder::new()
            .table_name(client_tables::CLIENTS_SCOPES_ROLES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_scope_id".to_string()),
                SqlCriteriaBuilder::is_equals("role_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_client_scope_role_stmt = client
            .prepare_cached(&remove_client_scope_role_sql)
            .await
            .unwrap();
        let result = client
            .execute(
                &remove_client_scope_role_stmt,
                &[&realm_id, &client_scope_id, &role_id],
            )
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove role from client scope".to_string())
                }
            }
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

    async fn load_client_scopes_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<ClientScopeModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let client_scopes_stmt = client
            .prepare_cached(&client_tables::CLIENT_TABLE_SELECT_CLIENT_SCOPE_IDS_BY_CLIENT_ID)
            .await
            .unwrap();
        let client_scopes_rows = client
            .query(&client_scopes_stmt, &[&realm_id, &client_id])
            .await;

        let mut scopes: Vec<ClientScopeModel> = Vec::new();
        match client_scopes_rows {
            Ok(rows) => {
                for row in rows {
                    let client_scope = RdsClientScopeProvider::read_client_scope(
                        &client,
                        realm_id,
                        row.get::<&str, &str>("client_scope_id"),
                    )
                    .await;
                    if client_scope.is_ok() {
                        if let Some(s) = client_scope.unwrap() {
                            scopes.push(s);
                        }
                    } else {
                        return Err(client_scope.err().unwrap());
                    }
                }
            }
            Err(_) => {
                log::info!(
                    "Failed to load client scopes for client: {}, realm: {}",
                    client_id,
                    realm_id
                );
                return Err(format!(
                    "Failed to load client scopes for client: {client_id}, realm: {realm_id}",
                ));
            }
        }
        Ok(scopes)
    }

    async fn load_client_scope_names_by_protocol(
        &self,
        realm_id: &str,
        protocol: &str,
    ) -> Result<Vec<String>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_client_scope_name_sql = SelectRequestBuilder::new()
            .table_name(client_tables::CLIENT_SCOPE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("protocol".to_string()),
            ])
            .columns(vec!["name".to_owned()])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_client_scope_name_stmt = client
            .prepare_cached(&load_client_scope_name_sql)
            .await
            .unwrap();
        let result = client
            .query(&load_client_scope_name_stmt, &[&realm_id, &protocol])
            .await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| row.get::<&str, String>("name"))
                .collect()),
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
    fn read_record(row: &Row) -> ClientModel {
        let configs =
            serde_json::from_value::<AttributesMap>(row.get::<&str, serde_json::Value>("configs"))
                .map_or_else(|_| None, |p| Some(p));

        let auth_flow_overrides = serde_json::from_value::<AttributesMap>(
            row.get::<&str, serde_json::Value>("auth_flow_binding_overrides"),
        )
        .map_or_else(|_| None, |p| Some(p));

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
            direct_access_grants_enabled: row.get("direct_access_grants_enabled"),
            standard_flow_enabled: row.get("standard_flow_enabled"),
            is_surrogate_auth_required: row.get("is_surrogate_auth_required"),
            bearer_only: row.get("bearer_only"),
            front_channel_logout: row.get("front_channel_logout"),
            configs: configs,
            not_before: row.get("not_before"),
            client_authenticator_type: row.get("client_authenticator_type"),
            service_account_enabled: row.get("service_account_enabled"),
            auth_flow_binding_overrides: auth_flow_overrides,
            metadata: AuditableModel {
                tenant: row.get("tenant"),
                created_by: row.get("created_by"),
                updated_by: row.get("updated_by"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                version: row.get("version"),
            },
        }
    }

    pub async fn load_clients_by_query(
        client: &Object,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<ClientModel>, String> {
        let load_clients_stmt = client.prepare_cached(&query).await.unwrap();
        let result = client.query(&load_clients_stmt, params).await;
        match result {
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsClientProvider::read_record(&row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }
}

#[async_trait]
impl IClientProvider for RdsClientProvider {
    async fn create_client(&self, client_model: &ClientModel) -> Result<(), String> {
        let db_client = self.database_manager.connection().await;
        if let Err(err) = db_client {
            return Err(err);
        }
        let create_client_sql = InsertRequestBuilder::new()
            .table_name(client_tables::CLIENTS_TABLE.table_name.clone())
            .columns(client_tables::CLIENTS_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let db_client = db_client.unwrap();
        let create_client_stmt = db_client.prepare_cached(&create_client_sql).await.unwrap();

        let response = db_client
            .execute(
                &create_client_stmt,
                &[
                    &client_model.metadata.tenant,
                    &client_model.client_id,
                    &client_model.realm_id,
                    &client_model.name,
                    &client_model.display_name,
                    &client_model.description,
                    &client_model.enabled,
                    &client_model.metadata.created_by,
                    &client_model.metadata.created_at,
                    &client_model.metadata.version,
                ],
            )
            .await;
        match response {
            Err(err) => {
                let error = err.to_string();
                log::error!("Failed to create client scope: {}", error);
                Err(error)
            }
            _ => Ok(()),
        }
    }

    async fn update_client(&self, client: &ClientModel) -> Result<(), String> {
        let db_client = self.database_manager.connection().await;
        if let Err(err) = db_client {
            return Err(err);
        }
        let update_client_sql = UpdateRequestBuilder::new()
            .table_name(client_tables::CLIENTS_TABLE.table_name.clone())
            .columns(client_tables::CLIENTS_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let db_client = db_client.unwrap();
        let update_client_stmt = db_client.prepare_cached(&update_client_sql).await.unwrap();

        let response = db_client
            .execute(
                &update_client_stmt,
                &[
                    &client.name,
                    &client.display_name,
                    &client.description,
                    &client.enabled,
                    &client.secret,
                    &client.registration_token,
                    &client.public_client,
                    &client.full_scope_allowed,
                    &client.protocol,
                    &client.root_url,
                    &client.web_origins,
                    &client.redirect_uris,
                    &client.consent_required,
                    &client.authorization_code_flow_enabled,
                    &client.implicit_flow_enabled,
                    &client.direct_access_grants_enabled,
                    &client.standard_flow_enabled,
                    &client.is_surrogate_auth_required,
                    &client.not_before,
                    &client.bearer_only,
                    &client.front_channel_logout,
                    &json!(client.configs),
                    &client.client_authenticator_type,
                    &client.service_account_enabled,
                    &json!(client.auth_flow_binding_overrides),
                    &client.metadata.updated_by,
                    &client.metadata.updated_at,
                    &client.metadata.tenant,
                    &client.realm_id,
                    &client.client_id,
                ],
            )
            .await;
        match response {
            Err(err) => {
                let error = err.to_string();
                log::error!("Failed to create client: {}", error);
                Err(error)
            }
            _ => Ok(()),
        }
    }

    async fn load_client_by_name(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<Option<ClientModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_scope_sql = SelectRequestBuilder::new()
            .table_name(client_tables::CLIENTS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_scope_stmt = client.prepare_cached(&load_scope_sql).await.unwrap();
        let result = client
            .query_opt(&load_scope_stmt, &[&realm_id, &name])
            .await;

        match &result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(RdsClientProvider::read_record(&r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn delete_clients_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_protocol_mapper_sql = DeleteQueryBuilder::new()
            .table_name(client_tables::CLIENTS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let delete_protocol_mapper_stmt = client
            .prepare_cached(&delete_protocol_mapper_sql)
            .await
            .unwrap();
        let result = client
            .execute(&delete_protocol_mapper_stmt, &[&realm_id, &client_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to delete client".to_string())
                }
            }
        }
    }

    async fn load_client_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Option<ClientModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_scope_sql = SelectRequestBuilder::new()
            .table_name(client_tables::CLIENTS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_scope_stmt = client.prepare_cached(&load_scope_sql).await.unwrap();
        let result = client
            .query_opt(&load_scope_stmt, &[&realm_id, &client_id])
            .await;

        match &result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(RdsClientProvider::read_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_client_by_client_ids(
        &self,
        realm_id: &str,
        client_ids: &Vec<String>,
    ) -> Result<Vec<ClientModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_protocol_mapper_sql = SelectRequestBuilder::new()
            .table_name(client_tables::CLIENTS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_in("realm_id".to_string(), client_ids.len() as u16),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_protocol_mapper_stmt = client
            .prepare_cached(&load_protocol_mapper_sql)
            .await
            .unwrap();
        let result = client
            .query(&load_protocol_mapper_stmt, &[&realm_id, &client_ids])
            .await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| RdsClientProvider::read_record(&row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_clients_by_realm_id(&self, realm_id: &str) -> Result<Vec<ClientModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_protocol_mapper_sql = SelectRequestBuilder::new()
            .table_name(client_tables::CLIENTS_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_protocol_mapper_stmt = client
            .prepare_cached(&load_protocol_mapper_sql)
            .await
            .unwrap();
        let result = client.query(&load_protocol_mapper_stmt, &[&realm_id]).await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| RdsClientProvider::read_record(&row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn add_client_role(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_client_role_sql = InsertRequestBuilder::new()
            .table_name(client_tables::CLIENTS_ROLES_TABLE.table_name.clone())
            .columns(client_tables::CLIENTS_ROLES_TABLE.insert_columns.clone())
            .resolve_conflict(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_client_role_stmt = client
            .prepare_cached(&create_client_role_sql)
            .await
            .unwrap();

        let response = client
            .execute(&create_client_role_stmt, &[&realm_id, &client_id, &role_id])
            .await;
        match response {
            Err(err) => {
                let error = err.to_string();
                log::error!(
                    "Failed to add role to client: {}. Error: {}",
                    client_id,
                    error
                );
                Err(error)
            }
            _ => Ok(()),
        }
    }

    async fn remove_client_role(
        &self,
        realm_id: &str,
        client_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_client_role_sql = DeleteQueryBuilder::new()
            .table_name(client_tables::CLIENTS_ROLES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_id".to_string()),
                SqlCriteriaBuilder::is_equals("role_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_client_role_stmt = client
            .prepare_cached(&remove_client_role_sql)
            .await
            .unwrap();
        let result = client
            .execute(&remove_client_role_stmt, &[&realm_id, &client_id, &role_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove role from client".to_string())
                }
            }
        }
    }

    async fn add_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_client_client_scope_sql = InsertRequestBuilder::new()
            .table_name(
                client_tables::CLIENTS_CLIENTS_SCOPES_TABLE
                    .table_name
                    .clone(),
            )
            .columns(
                client_tables::CLIENTS_CLIENTS_SCOPES_TABLE
                    .insert_columns
                    .clone(),
            )
            .resolve_conflict(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_client_client_scope_stmt = client
            .prepare_cached(&create_client_client_scope_sql)
            .await
            .unwrap();

        let response = client
            .execute(
                &create_client_client_scope_stmt,
                &[&realm_id, &client_id, &client_scope_id],
            )
            .await;
        match response {
            Err(err) => {
                let error = err.to_string();
                log::error!(
                    "Failed to add client scope to client: {}. Error: {}",
                    client_id,
                    error
                );
                Err(error)
            }
            _ => Ok(()),
        }
    }

    async fn remove_client_scope_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        client_scope_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_client_role_sql = DeleteQueryBuilder::new()
            .table_name(
                client_tables::CLIENTS_CLIENTS_SCOPES_TABLE
                    .table_name
                    .clone(),
            )
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_scope_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_client_role_stmt = client
            .prepare_cached(&remove_client_role_sql)
            .await
            .unwrap();
        let result = client
            .execute(
                &remove_client_role_stmt,
                &[&realm_id, &client_id, &client_scope_id],
            )
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove client scope from client".to_string())
                }
            }
        }
    }

    async fn add_client_protocol_mapper_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_client_protocol_mapper_sql = InsertRequestBuilder::new()
            .table_name(
                client_tables::CLIENTS_PROTOCOLS_MAPPERS_TABLE
                    .table_name
                    .clone(),
            )
            .columns(
                client_tables::CLIENTS_PROTOCOLS_MAPPERS_TABLE
                    .insert_columns
                    .clone(),
            )
            .resolve_conflict(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_client_protocol_mapper_stmt = client
            .prepare_cached(&create_client_protocol_mapper_sql)
            .await
            .unwrap();

        let response = client
            .execute(
                &create_client_protocol_mapper_stmt,
                &[&realm_id, &client_id, &mapper_id],
            )
            .await;
        match response {
            Err(err) => {
                let error = err.to_string();
                log::error!(
                    "Failed to add protocol mapper to client: {}. Error: {}",
                    client_id,
                    error
                );
                Err(error)
            }
            _ => Ok(()),
        }
    }

    async fn remove_client_protocol_mapper_mapping(
        &self,
        realm_id: &str,
        client_id: &str,
        mapper_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_client_protocol_mapper_sql = DeleteQueryBuilder::new()
            .table_name(
                client_tables::CLIENTS_PROTOCOLS_MAPPERS_TABLE
                    .table_name
                    .clone(),
            )
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_id".to_string()),
                SqlCriteriaBuilder::is_equals("mapper_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_client_protocol_mapper_stmt = client
            .prepare_cached(&remove_client_protocol_mapper_sql)
            .await
            .unwrap();
        let result = client
            .execute(
                &remove_client_protocol_mapper_stmt,
                &[&realm_id, &client_id, &mapper_id],
            )
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove protocol mapper from client".to_string())
                }
            }
        }
    }

    async fn load_client_protocol_mappers_ids(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<String>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let proco_mapper_ids_stmt = client
            .prepare_cached(&client_tables::CLIENT_TABLE_SELECT_PROTOCOL_MAPPERS_IDS_BY_CLIENT_ID)
            .await
            .unwrap();
        let proco_mapper_ids_rows = client
            .query(&proco_mapper_ids_stmt, &[&realm_id, &client_id])
            .await;

        match proco_mapper_ids_rows {
            Ok(rows) => {
                let mapper_ids: Vec<String> = rows
                    .into_iter()
                    .map(|row| row.get::<&str, String>("mapper_id"))
                    .collect();
                Ok(mapper_ids)
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_client_scopes_ids(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<String>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let client_scopes_ids_stmt = client
            .prepare_cached(&client_tables::CLIENT_TABLE_SELECT_CLIENT_SCOPE_IDS_BY_CLIENT_ID)
            .await
            .unwrap();
        let client_scopes_ids_rows = client
            .query(&client_scopes_ids_stmt, &[&realm_id, &client_id])
            .await;

        match client_scopes_ids_rows {
            Ok(rows) => {
                let client_scope_ids: Vec<String> = rows
                    .into_iter()
                    .map(|row| row.get::<&str, String>("client_scope_id"))
                    .collect();
                Ok(client_scope_ids)
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_client_roles(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<RoleModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let client_roles_ids_stmt = client
            .prepare_cached(&client_tables::CLIENT_TABLE_SELECT_ROLES_BY_CLIENT_ID)
            .await
            .unwrap();
        let client_roles_ids_rows = client
            .query(&client_roles_ids_stmt, &[&realm_id, &client_id])
            .await;

        let role_reader = RdsRoleProvider {
            database_manager: self.database_manager.clone(),
        };
        match client_roles_ids_rows {
            Ok(rows) => {
                let roles: Vec<RoleModel> = rows
                    .into_iter()
                    .map(|row| RdsRoleProvider::read_record(&row))
                    .collect();
                Ok(roles)
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn count_clients(&self, realm_id: &str) -> Result<i64, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

        let count_clients_sql = SelectCountRequestBuilder::new()
            .table_name(client_tables::CLIENTS_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let count_clients_stmt = client.prepare_cached(&count_clients_sql).await.unwrap();
        let result = client.query_one(&count_clients_stmt, &[&realm_id]).await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0)),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn load_client_by_role_id(
        &self,
        realm_id: &str,
        role_id: &str,
    ) -> Result<Option<ClientModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_client_by_role_stmt = client
            .prepare_cached(&client_tables::CLIENT_TABLE_SELECT_CLIENT_BY_ROLE)
            .await
            .unwrap();
        let result = client
            .query_opt(&load_client_by_role_stmt, &[&realm_id, &role_id])
            .await;

        match &result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(RdsClientProvider::read_record(&r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn client_exists_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_client_sql = SelectCountRequestBuilder::new()
            .table_name(client_tables::CLIENTS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_client_stmt = client.prepare_cached(&load_client_sql).await.unwrap();
        let result = client
            .query_one(&load_client_stmt, &[&realm_id, &client_id])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}
