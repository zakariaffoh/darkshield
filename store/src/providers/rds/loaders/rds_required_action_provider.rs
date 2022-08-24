use async_trait::async_trait;
use models::auditable::AuditableModel;
use models::entities::required_action::{RequiredActionEnum, RequiredActionModel};
use tokio_postgres::Row;

use std::collections::HashMap;
use std::sync::Arc;

use shaku::Component;

use crate::providers::core::builder::{DeleteQueryBuilder, SelectCountRequestBuilder};
use crate::providers::interfaces::required_action_provider::IRequiredActionProvider;
use crate::providers::rds::client::postgres_client::IDataBaseManager;

use crate::providers::core::builder::{
    InsertRequestBuilder, SelectRequestBuilder, SqlCriteriaBuilder, UpdateRequestBuilder,
};
use crate::providers::rds::tables::action_table;

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
            .table_name(action_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
            .columns(action_table::REQUIRED_ACTIONS_TABLE.insert_columns.clone())
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
            .table_name(action_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
            .columns(action_table::REQUIRED_ACTIONS_TABLE.update_columns.clone())
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

    async fn update_required_action_priority(
        &self,
        realm_id: &str,
        priority_map: &HashMap<String, String>,
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
            .table_name(action_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
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
            .table_name(action_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
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
            .table_name(action_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
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
            .table_name(action_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
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
            .table_name(action_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
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
            .table_name(action_table::REQUIRED_ACTIONS_TABLE.table_name.clone())
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
