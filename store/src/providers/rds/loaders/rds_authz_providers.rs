use std::sync::Arc;

use async_trait::async_trait;
use models::{
    auditable::AuditableModel,
    entities::authz_models::{GroupModel, RoleModel},
};
use shaku::Component;
use tokio_postgres::Row;

use crate::providers::{
    core::builder::{
        DeleteQueryBuilder, InsertRequestBuilder, SelectCountRequestBuilder, SelectRequestBuilder,
        SqlCriteriaBuilder, UpdateRequestBuilder,
    },
    interfaces::authz_provider::{IGroupProvider, IRoleProvider},
    rds::client::postgres_client::DataBaseManager,
    rds::tables::authz_tables,
};

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRoleProvider)]
pub struct RdsRoleProvider {
    database_manager: Arc<DataBaseManager>,
}

impl RdsRoleProvider {
    pub fn new(database_manager: Arc<DataBaseManager>) -> Self {
        Self {
            database_manager: database_manager,
        }
    }

    fn read_role_record(&self, row: Row) -> RoleModel {
        RoleModel {
            role_id: row.get("role_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            description: row.get("description"),
            is_client_role: row.get("is_client_role"),
            display_name: row.get("display_name"),
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

#[allow(dead_code)]
#[async_trait]
impl IRoleProvider for RdsRoleProvider {
    async fn create_role(&self, role_model: &RoleModel) {
        let client = self.database_manager.connection().await.unwrap();
        let create_role_sql = InsertRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .columns(authz_tables::ROLE_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let create_role_stmt = client.prepare_cached(&create_role_sql).await.unwrap();
        client
            .execute(
                &create_role_stmt,
                &[
                    &role_model.role_id,
                    &role_model.realm_id,
                    &role_model.name,
                    &role_model.description,
                    &role_model.display_name,
                    &role_model.is_client_role,
                    &role_model.metadata.tenant,
                    &role_model.metadata.created_by,
                    &role_model.metadata.created_at,
                    &role_model.metadata.version,
                ],
            )
            .await
            .unwrap();
    }

    async fn update_role(&self, role_model: &RoleModel) {
        let client = self.database_manager.connection().await.unwrap();
        let update_role_sql = UpdateRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .columns(authz_tables::ROLE_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let update_role_stmt = client.prepare_cached(&update_role_sql).await.unwrap();
        client
            .execute(
                &update_role_stmt,
                &[
                    &role_model.name,
                    &role_model.display_name,
                    &role_model.description,
                    &role_model.is_client_role,
                    &role_model.metadata.updated_by,
                    &role_model.metadata.updated_at,
                    &role_model.metadata.tenant,
                    &role_model.role_id,
                    &role_model.realm_id,
                ],
            )
            .await
            .unwrap();
    }

    async fn load_roles_by_ids(&self, realm_id: &str, roles_ids: Vec<String>) -> Vec<RoleModel> {
        let client = self.database_manager.connection().await.unwrap();
        let load_roles_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_in("roles_ids".to_string(), roles_ids.len() as u16),
            ])
            .sql_query()
            .unwrap();

        let load_roles_stmt = client.prepare_cached(&load_roles_sql).await.unwrap();
        let result = client
            .query_one(&load_roles_stmt, &[&realm_id, &roles_ids])
            .await;
        let result = client.query(&load_roles_stmt, &[]).await;
        match result {
            Ok(rows) => rows
                .into_iter()
                .map(|row| self.read_role_record(row))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    async fn load_roles_by_realm(&self, realm_id: &str) -> Vec<RoleModel> {
        let client = self.database_manager.connection().await.unwrap();
        let load_roles_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let load_roles_stmt = client.prepare_cached(&load_roles_sql).await.unwrap();
        let result = client.query_one(&load_roles_stmt, &[&realm_id]).await;
        let result = client.query(&load_roles_stmt, &[]).await;
        match result {
            Ok(rows) => rows
                .into_iter()
                .map(|row| self.read_role_record(row))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    async fn load_role_by_name(&self, realm_id: &str, role_name: &str) -> Option<RoleModel> {
        let client = self.database_manager.connection().await.unwrap();
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client
            .query_one(&load_realm_stmt, &[&realm_id, &role_name])
            .await;
        match result {
            Ok(row) => Some(self.read_role_record(row)),
            Err(_) => None,
        }
    }

    async fn delete_role(&self, realm_id: &str, role_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await.unwrap();
        let delete_role_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("role_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let delete_role_stmt = client.prepare_cached(&delete_role_sql).await.unwrap();
        let result = client
            .execute(&delete_role_stmt, &[&realm_id, &role_id])
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn load_realm_role(&self, realm_id: &str, name: &str) -> Option<RoleModel> {
        let client = self.database_manager.connection().await.unwrap();
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
                SqlCriteriaBuilder::is_equals("is_client_role".to_string()),
            ])
            .sql_query()
            .unwrap();

        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client
            .query_one(&load_realm_stmt, &[&realm_id, &name, &false])
            .await;
        match result {
            Ok(row) => Some(self.read_role_record(row)),
            Err(_) => None,
        }
    }

    async fn load_role_by_id(&self, realm_id: &str, role_id: &str) -> Option<RoleModel> {
        let client = self.database_manager.connection().await.unwrap();
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("role_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client
            .query_one(&load_realm_stmt, &[&realm_id, &role_id])
            .await;
        match result {
            Ok(row) => Some(self.read_role_record(row)),
            Err(_) => None,
        }
    }

    async fn exists_by_name(&self, realm_id: &str, name: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await.unwrap();
        let load_realm_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client
            .query_one(&load_realm_stmt, &[&realm_id, &name])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, u32>(0) as u32 > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IGroupProvider)]
pub struct RdsGroupProvider {
    database_manager: Arc<DataBaseManager>,
}

impl RdsGroupProvider {
    pub fn new(database_manager: Arc<DataBaseManager>) -> Self {
        Self {
            database_manager: database_manager,
        }
    }

    fn read_group_record(&self, row: Row) -> GroupModel {
        GroupModel {
            group_id: row.get("group_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            description: row.get("description"),
            is_default: row.get("is_default"),
            display_name: row.get("display_name"),
            roles: None,
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

#[allow(dead_code)]
#[async_trait]
impl IGroupProvider for RdsGroupProvider {
    async fn create_group(&self, role_model: &GroupModel) {}
}
