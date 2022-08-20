use std::sync::Arc;

use async_trait::async_trait;
use models::{auditable::AuditableModel, entities::realm::RealmModel};
use shaku::Component;
use tokio_postgres::Row;

use crate::providers::{
    core::builder::{
        DeleteQueryBuilder, InsertRequestBuilder, SelectRequestBuilder, SqlCriteriaBuilder,
        UpdateRequestBuilder,
    },
    interfaces::realm_provider::IRealmProvider,
    rds::client::postgres_client::DataBaseManager,
    rds::tables::realm_table,
};

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRealmProvider)]
pub struct RdsRealmProvider {
    database_manager: Arc<DataBaseManager>,
}

impl RdsRealmProvider {
    pub fn new(database_manager: Arc<DataBaseManager>) -> Self {
        Self {
            database_manager: database_manager,
        }
    }

    fn read_realm_record(&self, row: Row) -> RealmModel {
        RealmModel {
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            display_name: row.get("display_name"),
            enabled: row.get("enabled"),
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
}

#[async_trait]
impl IRealmProvider for RdsRealmProvider {
    async fn create_realm(&self, realm: &RealmModel) {
        let client = self.database_manager.connection().await.unwrap();
        let create_realm_sql = InsertRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .columns(realm_table::REALM_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let create_realm_stmt = client.prepare_cached(&create_realm_sql).await.unwrap();
        client
            .execute(
                &create_realm_stmt,
                &[
                    &realm.realm_id,
                    &realm.name,
                    &realm.display_name,
                    &realm.enabled,
                    &realm.metadata.tenant,
                    &realm.metadata.created_by,
                    &realm.metadata.created_at,
                    &realm.metadata.version,
                ],
            )
            .await
            .unwrap();
    }

    async fn update_realm(&self, realm: &RealmModel) {
        let client = self.database_manager.connection().await.unwrap();
        let create_realm_sql = UpdateRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .columns(realm_table::REALM_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let update_realm_stmt = client.prepare_cached(&create_realm_sql).await.unwrap();
        client
            .execute(
                &update_realm_stmt,
                &[
                    &realm.name,
                    &realm.display_name,
                    &realm.enabled,
                    &realm.metadata.updated_by,
                    &realm.metadata.updated_at,
                    &realm.metadata.tenant,
                    &realm.realm_id,
                ],
            )
            .await
            .unwrap();
    }

    async fn delete_realm(&self, tenant: &str, realm_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await.unwrap();
        let delete_realm_sql = DeleteQueryBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let delete_realm_stmt = client.prepare_cached(&delete_realm_sql).await.unwrap();
        let result = client
            .execute(&delete_realm_stmt, &[&tenant, &realm_id])
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn load_realm(&self, tenant: &str, realm_id: &str) -> Option<RealmModel> {
        let client = self.database_manager.connection().await.unwrap();
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client
            .query_one(&load_realm_stmt, &[&tenant, &realm_id])
            .await;
        match result {
            Ok(row) => Some(self.read_realm_record(row)),
            Err(_) => None,
        }
    }

    async fn load_realms(&self) -> Vec<RealmModel> {
        let client = self.database_manager.connection().await.unwrap();
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .sql_query()
            .unwrap();

        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client.query(&load_realm_stmt, &[]).await;
        match result {
            Ok(rows) => rows
                .into_iter()
                .map(|row| self.read_realm_record(row))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    async fn load_realm_by_name(&self, name: &str) -> Option<RealmModel> {
        let client = self.database_manager.connection().await.unwrap();
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("name".to_string())])
            .sql_query()
            .unwrap();

        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client.query_one(&load_realm_stmt, &[&name]).await;
        match result {
            Ok(row) => Some(self.read_realm_record(row)),
            Err(_) => None,
        }
    }

    async fn load_realm_by_display_name(&self, display_name: &str) -> Option<RealmModel> {
        let client = self.database_manager.connection().await.unwrap();
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals(
                "display_name".to_string(),
            )])
            .sql_query()
            .unwrap();

        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client.query_one(&load_realm_stmt, &[&display_name]).await;
        match result {
            Ok(row) => Some(self.read_realm_record(row)),
            Err(_) => None,
        }
    }
}
