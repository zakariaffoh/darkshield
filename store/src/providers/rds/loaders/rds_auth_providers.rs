use std::sync::Arc;
use std::collections::HashMap;
use async_trait::async_trait;
use models::auditable::AuditableModel;
use models::entities::auth::*;
use tokio_postgres::Row;
use shaku::Component;

use crate::providers::core::builder::*;
use crate::providers::interfaces::auth_providers::*;
use crate::providers::rds::client::postgres_client::IDataBaseManager;
use crate::providers::rds::tables::auth_table;


#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRequiredActionProvider)]
pub struct RdsRequiredActionProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsRequiredActionProvider {
    fn read_required_action_record(&self, row: Row) -> RequiredActionModel {
        RequiredActionModel {
            action_id: row.get("action_id"),
            realm_id: row.get("realm_id"),
            provider_id: row.get("provider_id"),
            action: row.get("action"),
            name: row.get("name"),
            display_name: row.get("display_name"),
            description: row.get("description"),
            default_action: row.get("default_action"),
            enabled: row.get("enabled"),
            on_time_action: row.get("on_time_action"),
            priority: row.get("priority"),
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
impl IRequiredActionProvider for RdsRequiredActionProvider {
    async fn register_required_action(&self, action: &RequiredActionModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_required_action_sql = InsertRequestBuilder::new()
            .table_name(auth_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
            .columns(auth_table::REQUIRED_ACTIONS_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_required_action_stmt = client
            .prepare_cached(&create_required_action_sql)
            .await
            .unwrap();
        let metadata = action.metadata.as_ref().unwrap();
        let response = client
            .execute(
                &create_required_action_stmt,
                &[
                    &action.realm_id,
                    &action.provider_id,
                    &action.action,
                    &action.name,
                    &action.display_name,
                    &action.description,
                    &action.default_action,
                    &action.enabled,
                    &action.on_time_action,
                    &action.priority,
                    &metadata.tenant,
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

    async fn update_required_action(&self, action: &RequiredActionModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_required_action_sql = UpdateRequestBuilder::new()
            .table_name(auth_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
            .columns(auth_table::REQUIRED_ACTIONS_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("action_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_required_action_stmt = client
            .prepare_cached(&create_required_action_sql)
            .await
            .unwrap();
        let metadata = action.metadata.as_ref().unwrap();
        let response = client
            .execute(
                &update_required_action_stmt,
                &[
                    &action.provider_id,
                    &action.action,
                    &action.name,
                    &action.display_name,
                    &action.description,
                    &action.default_action,
                    &action.enabled,
                    &action.on_time_action,
                    &action.priority,
                    &metadata.updated_by,
                    &metadata.updated_at,
                    &metadata.tenant,
                    &action.realm_id,
                    &action.action_id,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }

    async fn update_required_action_priority(
        &self,
        _realm_id: &str,
        _priority_map: &HashMap<String, String>,
    ) -> Result<bool, String> {
        Ok(true)
    }

    async fn remove_required_action(
        &self,
        realm_id: &str,
        action_id: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_required_action_sql = DeleteQueryBuilder::new()
            .table_name(auth_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("action_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let delete_required_action_stmt = client
            .prepare_cached(&delete_required_action_sql)
            .await
            .unwrap();
        let result = client
            .execute(&delete_required_action_stmt, &[&realm_id, &action_id])
            .await;
        match result {
            Ok(result) => Ok(result > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn load_required_action_by_action_id(
        &self,
        realm_id: &str,
        action_id: &str,
    ) -> Result<Option<RequiredActionModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_required_action_sql = SelectRequestBuilder::new()
            .table_name(auth_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("action_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_required_action_stmt = client
            .prepare_cached(&load_required_action_sql)
            .await
            .unwrap();
        let result = client
            .query_opt(&load_required_action_stmt, &[&realm_id, &action_id])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_required_action_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_required_actions_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<RequiredActionModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_required_actions_sql = SelectRequestBuilder::new()
            .table_name(auth_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_required_actions_stmt = client
            .prepare_cached(&load_required_actions_sql)
            .await
            .unwrap();
        let result = client
            .query(&load_required_actions_stmt, &[&realm_id])
            .await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_required_action_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_required_actions_by_action_list(
        &self,
        realm_id: &str,
        actions: &Vec<RequiredActionEnum>,
    ) -> Result<Vec<RequiredActionModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_required_actions_sql = SelectRequestBuilder::new()
            .table_name(auth_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_in("action".to_string(), actions.len() as u16),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_required_actions_stmt = client
            .prepare_cached(&load_required_actions_sql)
            .await
            .unwrap();
        let result = client
            .query(&load_required_actions_stmt, &[&realm_id, &actions])
            .await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_required_action_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_required_action_by_action(
        &self,
        realm_id: &str,
        action: &RequiredActionEnum,
    ) -> Result<Option<RequiredActionModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_required_action_sql = SelectRequestBuilder::new()
            .table_name(auth_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("action".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_required_action_stmt = client
            .prepare_cached(&load_required_action_sql)
            .await
            .unwrap();
        let result = client
            .query_opt(&load_required_action_stmt, &[&realm_id, &action])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_required_action_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn required_action_exists_by_action(
        &self,
        realm_id: &str,
        action: &RequiredActionEnum,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_required_action_sql = SelectCountRequestBuilder::new()
            .table_name(auth_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("action".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_required_action_stmt = client
            .prepare_cached(&load_required_action_sql)
            .await
            .unwrap();
        let result = client
            .query_one(&load_required_action_stmt, &[&realm_id, &action])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, u32>(0) as u32 > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}


#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IAuthenticationFlowProvider)]
pub struct RdsAuthenticationFlowProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsAuthenticationFlowProvider {
    fn read_authentication_flow_record(&self, row: Row) -> AuthenticationFlowModel {
        AuthenticationFlowModel {
            flow_id: row.get("flow_id"),
            alias: row.get("alias"),
            realm_id: row.get("realm_id"),
            provider_id: row.get("provider_id"),
            description: row.get("description"),
            top_level: row.get("top_level"),
            built_in: row.get("built_in"),
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
impl IAuthenticationFlowProvider for RdsAuthenticationFlowProvider {
    async fn create_authentication_flow(&self, flow: &AuthenticationFlowModel) -> Result<(), String>
    {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_flow_sql = InsertRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATION_FLOW_TABLE.table_name.clone())
            .columns(auth_table::AUTHENTICATION_FLOW_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_flow_stmt = client
            .prepare_cached(&create_flow_sql)
            .await
            .unwrap();
        let metadata = flow.metadata.as_ref().unwrap();
        let response = client
            .execute(
                &create_flow_stmt,
                &[
                    &metadata.tenant,
                    &flow.flow_id,
                    &flow.realm_id,
                    &flow.alias,
                    &flow.provider_id,
                    &flow.description,
                    &flow.top_level,
                    &flow.built_in,
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
    
    async fn update_authentication_flow(&self, flow: &AuthenticationFlowModel) -> Result<(), String>
    {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_flow_sql = UpdateRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATION_FLOW_TABLE.table_name.clone())
            .columns(auth_table::AUTHENTICATION_FLOW_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("flow_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_flow_stmt = client
            .prepare_cached(&update_flow_sql)
            .await
            .unwrap();
        let metadata = flow.metadata.as_ref().unwrap();

        let response = client
            .execute(
                &update_flow_stmt,
                &[
                    &flow.alias,
                    &flow.provider_id,
                    &flow.description,
                    &flow.top_level,
                    &flow.built_in,
                    &metadata.updated_by,
                    &metadata.updated_at,
                    &metadata.tenant,
                    &flow.realm_id,
                    &flow.flow_id,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }
    
    async fn load_authentication_flow_by_flow_id(
        &self,
        realm_id: &str,
        flow_id: &str,
    ) -> Result<Option<AuthenticationFlowModel>, String>
    {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_flow_sql = SelectRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATION_FLOW_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("flow_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_flow_stmt = client
            .prepare_cached(&load_flow_sql)
            .await
            .unwrap();
        let result = client
            .query_opt(&load_flow_stmt, &[&realm_id, &flow_id])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_authentication_flow_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_authentication_flow_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<AuthenticationFlowModel>, String>
    {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_flow_sql = SelectRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATION_FLOW_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_flow_stmt = client
            .prepare_cached(&load_flow_sql)
            .await
            .unwrap();
        let result = client
            .query(&load_flow_stmt, &[&realm_id])
            .await;

        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_authentication_flow_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn remove_authentication_flow(&self, realm_id: &str, flow_id: &str) -> Result<bool, String>
    {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_flow_config_sql = DeleteQueryBuilder::new()
            .table_name(auth_table::AUTHENTICATION_FLOW_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("flow_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_config_stmt = client
            .prepare_cached(&remove_flow_config_sql)
            .await
            .unwrap();
        let result = client
            .execute(&remove_config_stmt, &[&realm_id, &flow_id])
            .await;
        match result {
            Ok(result) => Ok(result > 0),
            Err(error) => Err(error.to_string()),
        }
    
    }

    async fn exists_flow_by_alias(
        &self,
        realm_id: &str,
        alias: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_flow_alias_sql = SelectCountRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATION_FLOW_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("alias".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_flow_alias_stmt = client.prepare_cached(&load_flow_alias_sql).await.unwrap();
        let result = client
            .query_one(&load_flow_alias_stmt, &[&realm_id, &alias])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, u32>(0) as u32 > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IAuthenticationExecutionProvider)]
pub struct RdsAuthenticationExecutionProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsAuthenticationExecutionProvider {
    fn read_authentication_execution_record(&self, row: Row) -> AuthenticationExecutionModel {
        AuthenticationExecutionModel {
            execution_id: row.get("flow_id"),
            realm_id: row.get("realm_id"),
            alias: row.get("alias"),
            flow_id: row.get("flow_id"),
            parent_flow_id: row.get("parent_flow_id"),
            priority: row.get("priority"),
            authenticator: row.get("authenticator"),
            authenticator_flow: row.get("authenticator_flow"),
            authenticator_config: row.get("authenticator_config"),
            built_in: row.get("built_in"),
            requirement: row.get("requirement"),
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
impl IAuthenticationExecutionProvider for RdsAuthenticationExecutionProvider{
    async fn create_authentication_execution(&self, execution: &AuthenticationExecutionModel) -> Result<(), String>{
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_execution_sql = InsertRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATION_EXECUTION_TABLE.table_name.clone())
            .columns(auth_table::AUTHENTICATION_EXECUTION_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_execution_stmt = client
            .prepare_cached(&create_execution_sql)
            .await
            .unwrap();
        let metadata = execution.metadata.as_ref().unwrap();
        let response = client
            .execute(
                &create_execution_stmt,
                &[
                    &metadata.tenant,
                    &execution.execution_id,
                    &execution.realm_id,
                    &execution.alias,
                    &execution.flow_id,
                    &execution.parent_flow_id,
                    &execution.authenticator,
                    &execution.authenticator_flow,
                    &execution.authenticator_config,
                    &execution.built_in,
                    &execution.requirement,
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
    
    async fn update_authentication_execution(&self, execution: &AuthenticationExecutionModel) -> Result<(), String>{
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_execution_sql = UpdateRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATION_EXECUTION_TABLE.table_name.clone())
            .columns(auth_table::AUTHENTICATION_EXECUTION_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("execution_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_execution_stmt = client
            .prepare_cached(&update_execution_sql)
            .await
            .unwrap();
        let metadata = execution.metadata.as_ref().unwrap();
        let response = client
            .execute(
                &update_execution_stmt,
                &[
                    &execution.alias,
                    &execution.flow_id,
                    &execution.parent_flow_id,
                    &execution.priority,
                    &execution.authenticator,
                    &execution.authenticator_flow,
                    &execution.authenticator_config,
                    &execution.built_in,
                    &execution.requirement,
                    &metadata.updated_by,
                    &metadata.updated_at,
                    &metadata.tenant,
                    &execution.realm_id,
                    &execution.execution_id,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }
  
    async fn load_authentication_execution_by_execution_id(
        &self,
        realm_id: &str,
        execution_id: &str,
    ) -> Result<Option<AuthenticationExecutionModel>, String>{
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_execution_sql = SelectRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATION_EXECUTION_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("execution_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_execution_stmt = client
            .prepare_cached(&load_execution_sql)
            .await
            .unwrap();
        let result = client
            .query_opt(&load_execution_stmt, &[&realm_id, &execution_id])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_authentication_execution_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }
    
    async fn load_authentication_execution_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<AuthenticationExecutionModel>, String>{
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_execution_sql = SelectRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATION_EXECUTION_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_execution_stmt = client
            .prepare_cached(&load_execution_sql)
            .await
            .unwrap();
        let result = client
            .query(&load_execution_stmt, &[&realm_id])
            .await;

        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_authentication_execution_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }
    
    async fn remove_authentication_execution(&self, realm_id: &str, execution_id: &str) -> Result<bool, String>{
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_execution_config_sql = DeleteQueryBuilder::new()
            .table_name(auth_table::AUTHENTICATION_EXECUTION_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("execution_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_execution_stmt = client
            .prepare_cached(&remove_execution_config_sql)
            .await
            .unwrap();
        let result = client
            .execute(&remove_execution_stmt, &[&realm_id, &execution_id])
            .await;
        match result {
            Ok(result) => Ok(result > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn exists_execution_by_alias(
        &self,
        realm_id: &str,
        alias: &str,
    ) -> Result<bool, String>{
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_execution_alias_sql = SelectCountRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATION_EXECUTION_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("alias".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_execution_alias_stmt = client.prepare_cached(&load_execution_alias_sql).await.unwrap();
        let result = client
            .query_one(&load_execution_alias_stmt, &[&realm_id, &alias])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, u32>(0) as u32 > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IAuthenticatorConfigProvider)]
pub struct RdsAuthenticatorConfigProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsAuthenticatorConfigProvider {
    fn read_authenticator_config_record(&self, row: Row) -> AuthenticatorConfigModel {
        AuthenticatorConfigModel {
            config_id: row.get("flow_id"),
            realm_id: row.get("realm_id"),
            alias: row.get("alias"),
            configs: row.get("flow_id"),
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
impl IAuthenticatorConfigProvider for RdsAuthenticatorConfigProvider{
    async fn create_authenticator_config(&self, config: &AuthenticatorConfigModel) -> Result<(), String>{
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_config_sql = InsertRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATOR_CONFIG_TABLE.table_name.clone())
            .columns(auth_table::AUTHENTICATOR_CONFIG_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_config_stmt = client
            .prepare_cached(&create_config_sql)
            .await
            .unwrap();
        let metadata = config.metadata.as_ref().unwrap();
        let response = client
            .execute(
                &create_config_stmt,
                &[
                    &metadata.tenant,
                    &config.config_id,
                    &config.realm_id,
                    &config.alias,
                    &config.configs,
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
    
    async fn update_authenticator_config(&self, config: &AuthenticatorConfigModel) -> Result<(), String>{
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_config_sql = UpdateRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATOR_CONFIG_TABLE.table_name.clone())
            .columns(auth_table::AUTHENTICATOR_CONFIG_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("config_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_config_stmt = client
            .prepare_cached(&update_config_sql)
            .await
            .unwrap();
        let metadata = config.metadata.as_ref().unwrap();
        let response = client
            .execute(
                &update_config_stmt,
                &[
                    &config.alias,
                    &config.configs,
                    &metadata.updated_by,
                    &metadata.updated_at,
                    &metadata.tenant,
                    &config.realm_id,
                    &config.config_id,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }
    
    async fn load_authenticator_config_by_config_id(
        &self,
        realm_id: &str,
        config_id: &str,
    ) -> Result<Option<AuthenticatorConfigModel>, String>{
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_config_sql = SelectRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATOR_CONFIG_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("action_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_config_stmt = client
            .prepare_cached(&load_config_sql)
            .await
            .unwrap();
        let result = client
            .query_opt(&load_config_stmt, &[&realm_id, &config_id])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_authenticator_config_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }
    
    async fn load_authenticator_configs_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<AuthenticatorConfigModel>, String>{
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_configs_sql = SelectRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATOR_CONFIG_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_configs_stmt = client
            .prepare_cached(&load_configs_sql)
            .await
            .unwrap();
        let result = client
            .query(&load_configs_stmt, &[&realm_id])
            .await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_authenticator_config_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }
    
    async fn remove_authenticator_config(&self, realm_id: &str, config_id: &str) -> Result<bool, String>{
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_auth_config_sql = DeleteQueryBuilder::new()
            .table_name(auth_table::AUTHENTICATOR_CONFIG_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("config_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_config_stmt = client
            .prepare_cached(&remove_auth_config_sql)
            .await
            .unwrap();
        let result = client
            .execute(&remove_config_stmt, &[&realm_id, &config_id])
            .await;
        match result {
            Ok(result) => Ok(result > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn exists_config_by_alias(
        &self,
        realm_id: &str,
        alias: &str,
    ) -> Result<bool, String>{
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_config_alias_sql = SelectCountRequestBuilder::new()
            .table_name(auth_table::AUTHENTICATOR_CONFIG_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("alias".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_config_alias_stmt = client.prepare_cached(&load_config_alias_sql).await.unwrap();
        let result = client
            .query_one(&load_config_alias_stmt, &[&realm_id, &alias])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, u32>(0) as u32 > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}
