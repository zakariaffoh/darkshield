use std::sync::Arc;

use async_trait::async_trait;
use models::{
    auditable::AuditableModel,
    entities::authz::{GroupModel, RoleModel},
};
use shaku::Component;
use tokio_postgres::Row;

use crate::providers::{
    core::builder::{
        DeleteQueryBuilder, InsertRequestBuilder, SelectCountRequestBuilder, SelectRequestBuilder,
        SqlCriteriaBuilder, UpdateRequestBuilder,
    },
    interfaces::authz_provider::{IGroupProvider, IRoleProvider},
    rds::client::postgres_client::IDataBaseManager,
    rds::tables::authz_tables,
};

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRoleProvider)]
pub struct RdsRoleProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsRoleProvider {
    fn read_role_record(&self, row: Row) -> RoleModel {
        RoleModel {
            role_id: row.get("role_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            description: row.get("description"),
            is_client_role: row.get("is_client_role"),
            display_name: row.get("display_name"),
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
impl IRoleProvider for RdsRoleProvider {
    async fn create_role(&self, role_model: &RoleModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_role_sql = InsertRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .columns(authz_tables::ROLE_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_role_stmt = client.prepare_cached(&create_role_sql).await.unwrap();
        let metadata = role_model.metadata.as_ref().unwrap();

        let response = client
            .execute(
                &create_role_stmt,
                &[
                    &role_model.role_id,
                    &role_model.realm_id,
                    &role_model.name,
                    &role_model.description,
                    &role_model.display_name,
                    &role_model.is_client_role,
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

    async fn update_role(&self, role_model: &RoleModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
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

        let client = client.unwrap();
        let update_role_stmt = client.prepare_cached(&update_role_sql).await.unwrap();
        let metadata = role_model.metadata.as_ref().unwrap();

        let response = client
            .execute(
                &update_role_stmt,
                &[
                    &role_model.name,
                    &role_model.display_name,
                    &role_model.description,
                    &role_model.is_client_role,
                    &metadata.updated_by,
                    &metadata.updated_at,
                    &metadata.tenant,
                    &role_model.role_id,
                    &role_model.realm_id,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }

    async fn load_roles_by_ids(
        &self,
        realm_id: &str,
        roles_ids: &Vec<String>,
    ) -> Result<Vec<RoleModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_roles_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_in("roles_id".to_string(), roles_ids.len() as u16),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_roles_stmt = client.prepare_cached(&load_roles_sql).await.unwrap();
        let result = client
            .query(&load_roles_stmt, &[&realm_id, &roles_ids])
            .await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_role_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_roles_by_realm(&self, realm_id: &str) -> Result<Vec<RoleModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_roles_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_roles_stmt = client.prepare_cached(&load_roles_sql).await.unwrap();
        let result = client.query_one(&load_roles_stmt, &[&realm_id]).await;
        let result = client.query(&load_roles_stmt, &[]).await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_role_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_role_by_name(
        &self,
        realm_id: &str,
        role_name: &str,
    ) -> Result<Option<RoleModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let result = client
            .query_opt(&load_realm_sql, &[&realm_id, &role_name])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_role_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn delete_role(&self, realm_id: &str, role_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_role_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("role_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let delete_role_stmt = client.prepare_cached(&delete_role_sql).await.unwrap();
        let result = client
            .execute(&delete_role_stmt, &[&realm_id, &role_id])
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn load_realm_role(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<Option<RoleModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
                SqlCriteriaBuilder::is_equals("is_client_role".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client
            .query_opt(&load_realm_stmt, &[&realm_id, &name, &false])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_role_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_role_by_id(
        &self,
        realm_id: &str,
        role_id: &str,
    ) -> Result<Option<RoleModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("role_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let result = client
            .query_opt(&load_realm_sql, &[&realm_id, &role_id])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_role_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn exists_by_name(&self, realm_id: &str, name: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
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
    #[shaku(inject)]
    database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsGroupProvider {
    fn _read_group_record(&self, row: Row) -> GroupModel {
        GroupModel {
            group_id: row.get("group_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            description: row.get("description"),
            is_default: row.get("is_default"),
            display_name: row.get("display_name"),
            roles: None,
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

impl IGroupProvider for RdsGroupProvider {
    async fn create_group(&self, role_model: &GroupModel) -> Result<(), String> {
        Ok(())
    }
}
