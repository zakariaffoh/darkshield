use crate::providers::{
    core::builder::*,
    interfaces::authz_provider::*,
    rds::{
        client::postgres_client::IDataBaseManager,
        tables::{authz_tables, user_table},
    },
};
use async_trait::async_trait;
use deadpool_postgres::Object;
use log;
use models::{
    auditable::AuditableModel,
    entities::{attributes::AttributesMap, authz::*},
};
use serde_json::json;
use shaku::Component;
use std::sync::Arc;
use tokio_postgres::Row;

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRoleProvider)]
pub struct RdsRoleProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsRoleProvider {
    pub fn read_record(&self, row: &Row) -> RoleModel {
        RoleModel {
            role_id: row.get("role_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            description: row.get("description"),
            is_client_role: row.get("client_role"),
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
    async fn create_role(&self, role_model: &RoleModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            log::info!("Failed to connect to database: {}", err);
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

        let response = client
            .execute(
                &create_role_stmt,
                &[
                    &role_model.metadata.tenant,
                    &role_model.role_id,
                    &role_model.realm_id,
                    &role_model.name,
                    &role_model.display_name,
                    &role_model.description,
                    &role_model.is_client_role,
                    &role_model.metadata.created_by,
                    &role_model.metadata.created_at,
                    &role_model.metadata.version,
                ],
            )
            .await;

        match response {
            Err(err) => {
                let error = err.to_string();
                log::error!("Failed to create role: {}", error);
                Err(error)
            }
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
                SqlCriteriaBuilder::is_equals("role_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_role_stmt = client.prepare_cached(&update_role_sql).await.unwrap();

        let response = client
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
                    &role_model.realm_id,
                    &role_model.role_id,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to update role".to_string())
                }
            }
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
            Ok(rows) => Ok(rows.iter().map(|row| self.read_record(&row)).collect()),
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
        let result = client.query(&load_roles_stmt, &[&realm_id]).await;
        match result {
            Ok(rows) => Ok(rows.iter().map(|row| self.read_record(&row)).collect()),
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
        match &result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_record(r)))
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
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to delete role".to_string())
                }
            }
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
        match &result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_record(r)))
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
        match &result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_record(r)))
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
            Ok(row) => Ok(row.get::<usize, i32>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn client_role_exists_by_id(
        &self,
        realm_id: &str,
        role_id: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_role_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("role_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_role".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_role_stmt = client.prepare_cached(&load_role_sql).await.unwrap();
        let result = client
            .query_one(&load_role_stmt, &[&realm_id, &role_id, &true])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn role_exists_by_id(&self, realm_id: &str, role_id: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("role_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client
            .query_one(&load_realm_stmt, &[&realm_id, &role_id])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn count_roles(&self, realm_id: &str) -> Result<i64, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let count_role_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let count_roles_stmt = client.prepare_cached(&count_role_sql).await.unwrap();
        let result = client.query_one(&count_roles_stmt, &[&realm_id]).await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0)),
            Err(error) => Err(error.to_string()),
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
        let load_roles_stmt = client
            .prepare_cached(&authz_tables::CLIENT_ROLES_SELECT_BY_CLIENT_ID_QUERY)
            .await
            .unwrap();
        let result = client
            .query(&load_roles_stmt, &[&realm_id, &client_id])
            .await;
        match result {
            Ok(rows) => Ok(rows.iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_user_roles(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<RoleModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_roles_stmt = client
            .prepare_cached(&user_table::SELECT_USER_ROLES_BY_USER_ID)
            .await
            .unwrap();
        let result = client.query(&load_roles_stmt, &[&realm_id, &user_id]).await;
        match result {
            Ok(rows) => Ok(rows.iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }
}

#[derive(Component)]
#[shaku(interface = IGroupProvider)]
pub struct RdsGroupProvider {
    #[shaku(inject)]
    database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsGroupProvider {
    fn read_record(&self, row: Row, roles: Vec<RoleModel>) -> GroupModel {
        GroupModel {
            group_id: row.get("group_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            description: row.get("description"),
            is_default: row.get("is_default"),
            display_name: row.get("display_name"),
            roles: Some(roles),
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

    async fn read_group_roles(
        &self,
        client: &Object,
        realm_id: &str,
        group_id: &str,
    ) -> Result<Vec<RoleModel>, String> {
        let load_roles_stmt = client
            .prepare_cached(&authz_tables::GROUPS_ROLES_SELECT_BY_ROLE_ID_QUERY)
            .await
            .unwrap();
        let roles_rows = client
            .query(&load_roles_stmt, &[&realm_id, &group_id])
            .await;

        match &roles_rows {
            Ok(rs) => {
                let role_mapper = RdsRoleProvider {
                    database_manager: self.database_manager.clone(),
                };
                let roles: Vec<RoleModel> = roles_rows
                    .unwrap()
                    .iter()
                    .map(|r| role_mapper.read_record(&r))
                    .collect();
                Ok(roles)
            }
            Err(err) => Err(err.to_string()),
        }
    }
}

#[async_trait]
impl IGroupProvider for RdsGroupProvider {
    async fn create_group(&self, group_model: &GroupModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_group_sql = InsertRequestBuilder::new()
            .table_name(authz_tables::GROUP_TABLE.table_name.clone())
            .columns(authz_tables::GROUP_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_group_stmt = client.prepare_cached(&create_group_sql).await.unwrap();

        let response = client
            .execute(
                &create_group_stmt,
                &[
                    &group_model.metadata.tenant,
                    &group_model.group_id,
                    &group_model.realm_id,
                    &group_model.name,
                    &group_model.display_name,
                    &group_model.description,
                    &group_model.is_default,
                    &group_model.metadata.created_by,
                    &group_model.metadata.created_at,
                    &group_model.metadata.version,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }

    async fn update_group(&self, group_model: &GroupModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_group_sql = UpdateRequestBuilder::new()
            .table_name(authz_tables::GROUP_TABLE.table_name.clone())
            .columns(authz_tables::GROUP_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("group_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_group_stmt = client.prepare_cached(&update_group_sql).await.unwrap();

        let response = client
            .execute(
                &update_group_stmt,
                &[
                    &group_model.name,
                    &group_model.description,
                    &group_model.display_name,
                    &group_model.is_default,
                    &group_model.metadata.updated_by,
                    &group_model.metadata.updated_at,
                    &group_model.realm_id,
                    &group_model.group_id,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to update group".to_string())
                }
            }
        }
    }

    async fn delete_group(&self, realm_id: &str, group_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_group_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::GROUP_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("group_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let delete_group_stmt = client.prepare_cached(&delete_group_sql).await.unwrap();
        let result = client
            .execute(&delete_group_stmt, &[&realm_id, &group_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to delete group".to_string())
                }
            }
        }
    }

    async fn load_group_by_name(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<Option<GroupModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::GROUP_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let result = client.query_opt(&load_realm_sql, &[&realm_id, &name]).await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    let group_id = r.get::<&str, String>("group_id");
                    let roles_records = self.read_group_roles(&client, realm_id, &group_id).await;
                    match roles_records {
                        Ok(roles) => Ok(Some(self.read_record(r, roles))),
                        Err(err) => Err(err),
                    }
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_group_by_id(
        &self,
        realm_id: &str,
        group_id: &str,
    ) -> Result<Option<GroupModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::GROUP_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("group_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let result = client
            .query_opt(&load_realm_sql, &[&realm_id, &group_id])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    let group_id = r.get::<&str, String>("group_id");
                    let roles_records = self.read_group_roles(&client, realm_id, &group_id).await;
                    match roles_records {
                        Ok(roles) => Ok(Some(self.read_record(r, roles))),
                        Err(err) => Err(err),
                    }
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn count_groups(&self, realm_id: &str) -> Result<i64, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::GROUP_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let count_group_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client.query_one(&count_group_stmt, &[&realm_id]).await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0)),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn load_groups_by_realm(&self, realm_id: &str) -> Result<Vec<GroupModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_groups_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::GROUP_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_groups_stmt = client.prepare_cached(&load_groups_sql).await.unwrap();
        let result = client.query(&load_groups_stmt, &[&realm_id]).await;
        match result {
            Ok(rows) => {
                let mut groups = Vec::new();
                for r in rows {
                    let roles_records = self
                        .read_group_roles(&client, realm_id, &r.get::<&str, &str>("group_id"))
                        .await;
                    if roles_records.is_ok() {
                        groups.push(self.read_record(r, roles_records.unwrap()));
                    } else {
                        return Err(roles_records.err().unwrap());
                    }
                }
                Ok(groups)
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn exists_groups_by_id(&self, realm_id: &str, group_id: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_group_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::GROUP_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("group_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_group_stmt = client.prepare_cached(&load_group_sql).await.unwrap();
        let result = client
            .query_one(&load_group_stmt, &[&realm_id, &group_id])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn add_group_role_mapping(
        &self,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let add_group_role_sql = InsertRequestBuilder::new()
            .table_name(authz_tables::GROUPS_ROLES_TABLE.table_name.clone())
            .columns(authz_tables::GROUPS_ROLES_TABLE.insert_columns.clone())
            .resolve_conflict(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let add_group_role_stmt = client.prepare_cached(&add_group_role_sql).await.unwrap();
        let response = client
            .execute(&add_group_role_stmt, &[&realm_id, &group_id, &role_id])
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to add role to group".to_string())
                }
            }
        }
    }

    async fn remove_group_role_mapping(
        &self,
        realm_id: &str,
        group_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_group_role_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::GROUPS_ROLES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("group_id".to_string()),
                SqlCriteriaBuilder::is_equals("role_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let delete_group_role_stmt = client.prepare_cached(&delete_group_role_sql).await.unwrap();
        let result = client
            .execute(&delete_group_role_stmt, &[&realm_id, &group_id, &role_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove role from group".to_string())
                }
            }
        }
    }

    async fn load_user_groups(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<GroupModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_user_groups_stmt = client
            .prepare_cached(&user_table::SELECT_USER_GROUPS_BY_USER_ID)
            .await
            .unwrap();
        let result = client
            .query(&load_user_groups_stmt, &[&realm_id, &user_id])
            .await;
        match result {
            Ok(rows) => {
                let mut groups = Vec::new();
                for r in rows {
                    let roles_records = self
                        .read_group_roles(&client, realm_id, &r.get::<&str, &str>("group_id"))
                        .await;
                    if roles_records.is_ok() {
                        groups.push(self.read_record(r, roles_records.unwrap()));
                    } else {
                        return Err(roles_records.err().unwrap());
                    }
                }
                Ok(groups)
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_user_groups_paging(
        &self,
        realm_id: &str,
        user_id: &str,
        page_size: i32,
        page_index: i32,
    ) -> Result<GroupPagingResult, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_user_count_stmt = client
            .prepare_cached(&user_table::SELECT_USER_GROUPS_COUNT_BY_USER_ID)
            .await
            .unwrap();
        let count_result = client
            .query_one(&load_user_count_stmt, &[&realm_id, &user_id])
            .await;
        if let Err(err) = count_result {
            return Err(err.to_string());
        }
        let total_groups = count_result.unwrap().get::<usize, i64>(0);
        let page_offset = page_index * page_size;
        let load_user_groups_stmt = client
            .prepare_cached(&user_table::SELECT_USER_GROUPS_BY_USER_ID_PAGING)
            .await
            .unwrap();
        let result = client
            .query(
                &load_user_groups_stmt,
                &[&realm_id, &user_id, &page_offset, &page_size],
            )
            .await;

        match result {
            Ok(rows) => {
                let mut groups = Vec::new();
                for r in rows {
                    let roles_records = self
                        .read_group_roles(&client, realm_id, &r.get::<&str, &str>("group_id"))
                        .await;
                    if roles_records.is_ok() {
                        groups.push(self.read_record(r, roles_records.unwrap()));
                    } else {
                        return Err(roles_records.err().unwrap());
                    }
                }
                Ok(GroupPagingResult {
                    page_size: page_size as i64,
                    page_index: page_index as i64,
                    total_count: total_groups,
                    groups: groups,
                })
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn count_user_groups(&self, realm_id: &str, user_id: &str) -> Result<i64, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let count_user_groups_stmt = client
            .prepare_cached(&authz_tables::SELECT_USER_GROUPS_COUNT_BY_USER_ID)
            .await
            .unwrap();
        let result = client
            .query_one(&count_user_groups_stmt, &[&realm_id, &user_id])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0)),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IIdentityProvider)]
pub struct RdsIdentityProvider {
    #[shaku(inject)]
    database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsIdentityProvider {
    fn read_record(&self, row: Row) -> IdentityProviderModel {
        let configs =
            serde_json::from_value::<AttributesMap>(row.get::<&str, serde_json::Value>("configs"))
                .map_or_else(|_| None, |p| Some(p));

        IdentityProviderModel {
            internal_id: row.get("internal_id"),
            provider_id: row.get("provider_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            description: row.get("description"),
            display_name: row.get("display_name"),
            trust_email: row.get("trust_email"),
            enabled: row.get("enabled"),
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
}

#[async_trait]
impl IIdentityProvider for RdsIdentityProvider {
    async fn create_identity_provider(&self, idp: &IdentityProviderModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_idp_sql = InsertRequestBuilder::new()
            .table_name(authz_tables::IDENTITIES_PROVIDERS_TABLE.table_name.clone())
            .columns(
                authz_tables::IDENTITIES_PROVIDERS_TABLE
                    .insert_columns
                    .clone(),
            )
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_idp_stmt = client.prepare_cached(&create_idp_sql).await.unwrap();

        let response = client
            .execute(
                &create_idp_stmt,
                &[
                    &idp.metadata.tenant,
                    &idp.internal_id,
                    &idp.provider_id,
                    &idp.realm_id,
                    &idp.name,
                    &idp.display_name,
                    &idp.description,
                    &idp.trust_email,
                    &idp.enabled,
                    &json!(&idp.configs),
                    &idp.metadata.created_by,
                    &idp.metadata.created_at,
                    &idp.metadata.version,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }

    async fn udpate_identity_provider(&self, idp: &IdentityProviderModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_idp_sql = UpdateRequestBuilder::new()
            .table_name(authz_tables::IDENTITIES_PROVIDERS_TABLE.table_name.clone())
            .columns(
                authz_tables::IDENTITIES_PROVIDERS_TABLE
                    .update_columns
                    .clone(),
            )
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("internal_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_idp_stmt = client.prepare_cached(&update_idp_sql).await.unwrap();
        let response = client
            .execute(
                &update_idp_stmt,
                &[
                    &idp.provider_id,
                    &idp.name,
                    &idp.display_name,
                    &idp.description,
                    &idp.trust_email,
                    &idp.enabled,
                    &json!(idp.configs),
                    &idp.metadata.updated_by,
                    &idp.metadata.updated_at,
                    &idp.metadata.tenant,
                    &idp.realm_id,
                    &idp.internal_id,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to update identity provider".to_string())
                }
            }
        }
    }

    async fn load_identity_provider_by_internal_id(
        &self,
        realm_id: &str,
        internal_id: &str,
    ) -> Result<Option<IdentityProviderModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_idp_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::IDENTITIES_PROVIDERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("internal_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_idp_stmt = client.prepare_cached(&load_idp_sql).await.unwrap();
        let result = client
            .query_opt(&load_idp_stmt, &[&realm_id, &internal_id])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_identity_provider_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<IdentityProviderModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_idp_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::IDENTITIES_PROVIDERS_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_idp_stmt = client.prepare_cached(&load_idp_sql).await.unwrap();
        let result = client.query(&load_idp_stmt, &[&realm_id]).await;
        match result {
            Ok(rows) => Ok(rows.into_iter().map(|row| self.read_record(row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn remove_identity_provider(
        &self,
        realm_id: &str,
        internal_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_idp_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::IDENTITIES_PROVIDERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("internal_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_idp_stmt = client.prepare_cached(&remove_idp_sql).await.unwrap();
        let result = client
            .execute(&remove_idp_stmt, &[&realm_id, &internal_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to delete identity provider".to_string())
                }
            }
        }
    }

    async fn exists_by_alias(&self, realm_id: &str, alias: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_idp_by_alias_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::IDENTITIES_PROVIDERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("alias".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_idp_by_alias_stmt = client.prepare_cached(&load_idp_by_alias_sql).await.unwrap();
        let result = client
            .query_one(&load_idp_by_alias_stmt, &[&realm_id, &alias])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) as u32 > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IResourceServerProvider)]
pub struct RdsResourceServerProvider {
    #[shaku(inject)]
    database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsResourceServerProvider {
    fn read_record(&self, row: &Row) -> ResourceServerModel {
        let configs =
            serde_json::from_value::<AttributesMap>(row.get::<&str, serde_json::Value>("configs"))
                .map_or_else(|_| None, |p| Some(p));

        ResourceServerModel {
            server_id: row.get("server_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            display_name: row.get("display_name"),
            description: row.get("description"),
            enforcement_mode: row.get("policy_enforcement_mode"),
            decision_strategy: row.get("decision_strategy"),
            remote_resource_management: row.get("remote_resource_management"),
            user_managed_access_enabled: row.get("user_managed_access_enabled"),
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
}

#[async_trait]
impl IResourceServerProvider for RdsResourceServerProvider {
    async fn create_resource_server(&self, server: &ResourceServerModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_resource_server_sql = InsertRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_SERVERS_TABLE.table_name.clone())
            .columns(authz_tables::RESOURCES_SERVERS_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_resource_server_stmt = client
            .prepare_cached(&create_resource_server_sql)
            .await
            .unwrap();

        let response = client
            .execute(
                &create_resource_server_stmt,
                &[
                    &server.metadata.tenant,
                    &server.server_id,
                    &server.realm_id,
                    &server.name,
                    &server.display_name,
                    &server.description,
                    &server.enforcement_mode,
                    &server.decision_strategy,
                    &server.remote_resource_management,
                    &server.user_managed_access_enabled,
                    &json!(server.configs),
                    &server.metadata.created_by,
                    &server.metadata.created_at,
                    &server.metadata.version,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }

    async fn udpate_resource_server(&self, server: &ResourceServerModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_resource_server_sql = UpdateRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_SERVERS_TABLE.table_name.clone())
            .columns(authz_tables::RESOURCES_SERVERS_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_resource_server_stmt = client
            .prepare_cached(&update_resource_server_sql)
            .await
            .unwrap();

        let response = client
            .execute(
                &update_resource_server_stmt,
                &[
                    &server.name,
                    &server.display_name,
                    &server.description,
                    &server.enforcement_mode,
                    &server.decision_strategy,
                    &server.remote_resource_management,
                    &server.user_managed_access_enabled,
                    &server.metadata.updated_by,
                    &server.metadata.updated_at,
                    &server.realm_id,
                    &server.server_id,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to update resource server".to_string())
                }
            }
        }
    }

    async fn load_resource_server_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Option<ResourceServerModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_resource_server_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_SERVERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_resource_server_stmt = client
            .prepare_cached(&load_resource_server_sql)
            .await
            .unwrap();
        let result = client
            .query_opt(&load_resource_server_stmt, &[&realm_id, &server_id])
            .await;

        match &result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_resource_servers_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<ResourceServerModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_resource_servers_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_SERVERS_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_resources_server_stmt = client
            .prepare_cached(&load_resource_servers_sql)
            .await
            .unwrap();
        let result = client
            .query(&load_resources_server_stmt, &[&realm_id])
            .await;

        match result {
            Ok(rows) => Ok(rows.iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn delete_resource_server(&self, realm_id: &str, server_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_resource_server_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::RESOURCES_SERVERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let delete_resource_server_stmt = client
            .prepare_cached(&delete_resource_server_sql)
            .await
            .unwrap();
        let result = client
            .execute(&delete_resource_server_stmt, &[&realm_id, &server_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to delete resource server".to_string())
                }
            }
        }
    }

    async fn resource_server_exists_by_alias(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_resource_server_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_SERVERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_resource_server_stmt = client
            .prepare_cached(&load_resource_server_sql)
            .await
            .unwrap();
        let result = client
            .query_one(&load_resource_server_stmt, &[&realm_id, &name])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn resource_server_exists_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_resource_server_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_SERVERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_resource_server_stmt = client
            .prepare_cached(&load_resource_server_sql)
            .await
            .unwrap();
        let result = client
            .query_one(&load_resource_server_stmt, &[&realm_id, &server_id])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IResourceProvider)]
pub struct RdsResourceProvider {
    #[shaku(inject)]
    database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsResourceProvider {
    fn read_record(&self, row: &Row) -> ResourceModel {
        let configs =
            serde_json::from_value::<AttributesMap>(row.get::<&str, serde_json::Value>("configs"))
                .map_or_else(|_| None, |p| Some(p));

        ResourceModel {
            resource_id: row.get("resource_id"),
            server_id: row.get("server_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            display_name: row.get("display_name"),
            description: row.get("description"),
            resource_uris: row.get("resource_uris"),
            resource_type: row.get("resource_type"),
            resource_owner: row.get("resource_owner"),
            user_managed_access_enabled: row.get("user_managed_access_enabled"),
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
}

#[async_trait]
impl IResourceProvider for RdsResourceProvider {
    async fn create_resource(&self, resource: &ResourceModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_resource_sql = InsertRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_TABLE.table_name.clone())
            .columns(authz_tables::RESOURCES_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_resource_stmt = client.prepare_cached(&create_resource_sql).await.unwrap();

        let response = client
            .execute(
                &create_resource_stmt,
                &[
                    &resource.metadata.tenant,
                    &resource.realm_id,
                    &resource.server_id,
                    &resource.resource_id,
                    &resource.name,
                    &resource.display_name,
                    &resource.description,
                    &resource.resource_uris,
                    &resource.resource_type,
                    &resource.resource_owner,
                    &resource.user_managed_access_enabled,
                    &json!(resource.configs),
                    &resource.metadata.created_by,
                    &resource.metadata.created_at,
                    &resource.metadata.version,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }

    async fn udpate_resource(&self, resource: &ResourceModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_resource_sql = UpdateRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_TABLE.table_name.clone())
            .columns(authz_tables::RESOURCES_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("resource_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_resource_stmt = client.prepare_cached(&update_resource_sql).await.unwrap();
        let response = client
            .execute(
                &update_resource_stmt,
                &[
                    &resource.name,
                    &resource.display_name,
                    &resource.description,
                    &resource.resource_uris,
                    &resource.resource_type,
                    &resource.resource_owner,
                    &resource.user_managed_access_enabled,
                    &json!(resource.configs),
                    &resource.metadata.updated_by,
                    &resource.metadata.updated_at,
                    &resource.realm_id,
                    &resource.server_id,
                    &resource.resource_id,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to update resource".to_string())
                }
            }
        }
    }

    async fn load_resource_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> Result<Option<ResourceModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_resource_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("resource_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_resource_stmt = client.prepare_cached(&load_resource_sql).await.unwrap();
        let result = client
            .query_opt(&load_resource_stmt, &[&realm_id, &server_id, &resource_id])
            .await;

        match &result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn resource_exists_by_name(
        &self,
        realm_id: &str,
        server_id: &str,
        name: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_resource_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_SERVERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_resource_stmt = client.prepare_cached(&load_resource_sql).await.unwrap();
        let result = client
            .query_one(&load_resource_stmt, &[&realm_id, &server_id, &name])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn resource_exists_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_resource_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("resource_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_resource_stmt = client.prepare_cached(&load_resource_sql).await.unwrap();
        let result = client
            .query_one(&load_resource_stmt, &[&realm_id, &server_id, &resource_id])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn load_resource_by_realm(&self, realm_id: &str) -> Result<Vec<ResourceModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_resources_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_resources_stmt = client.prepare_cached(&load_resources_sql).await.unwrap();
        let result = client.query(&load_resources_stmt, &[&realm_id]).await;
        match result {
            Ok(rows) => Ok(rows.iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_resources_by_server(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Vec<ResourceModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_resources_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_resources_stmt = client.prepare_cached(&load_resources_sql).await.unwrap();
        let result = client
            .query(&load_resources_stmt, &[&realm_id, &server_id])
            .await;
        match result {
            Ok(rows) => Ok(rows.iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn delete_resource_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_resource_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::RESOURCES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("resource_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let delete_resource_stmt = client.prepare_cached(&delete_resource_sql).await.unwrap();
        let result = client
            .execute(
                &delete_resource_stmt,
                &[&realm_id, &server_id, &resource_id],
            )
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to delete resource".to_string())
                }
            }
        }
    }

    async fn add_resource_scope_mapping(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let add_resource_scope_sql = InsertRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_SCOPES_TABLE.table_name.clone())
            .columns(authz_tables::RESOURCES_SCOPES_TABLE.insert_columns.clone())
            .resolve_conflict(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let add_resource_scope_stmt = client
            .prepare_cached(&add_resource_scope_sql)
            .await
            .unwrap();
        let response = client
            .execute(
                &add_resource_scope_stmt,
                &[&realm_id, &server_id, &resource_id, &scope_id],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to add scope to resource".to_string())
                }
            }
        }
    }

    async fn remove_resource_scope_mapping(
        &self,
        realm_id: &str,
        server_id: &str,
        resource_id: &str,
        scope_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_resource_scope_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::RESOURCES_SCOPES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("resource_id".to_string()),
                SqlCriteriaBuilder::is_equals("scope_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_resource_scope_stmt = client
            .prepare_cached(&remove_resource_scope_sql)
            .await
            .unwrap();

        let response = client
            .execute(
                &remove_resource_scope_stmt,
                &[&realm_id, &server_id, &resource_id, &scope_id],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove scope from resource".to_string())
                }
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IScopeProvider)]
pub struct RdsScopeProvider {
    #[shaku(inject)]
    database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsScopeProvider {
    fn read_record(&self, row: &Row) -> ScopeModel {
        ScopeModel {
            scope_id: row.get("scope_id"),
            server_id: row.get("server_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            display_name: row.get("display_name"),
            description: row.get("description"),
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
impl IScopeProvider for RdsScopeProvider {
    async fn create_scope(&self, scope: &ScopeModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_scope_sql = InsertRequestBuilder::new()
            .table_name(authz_tables::SCOPES_TABLE.table_name.clone())
            .columns(authz_tables::SCOPES_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_scope_stmt = client.prepare_cached(&create_scope_sql).await.unwrap();
        let response = client
            .execute(
                &create_scope_stmt,
                &[
                    &scope.metadata.tenant,
                    &scope.scope_id,
                    &scope.server_id,
                    &scope.realm_id,
                    &scope.name,
                    &scope.display_name,
                    &scope.description,
                    &scope.metadata.created_by,
                    &scope.metadata.created_at,
                    &scope.metadata.version,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
        }
    }

    async fn udpate_scope(&self, scope: &ScopeModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_scope_sql = UpdateRequestBuilder::new()
            .table_name(authz_tables::SCOPES_TABLE.table_name.clone())
            .columns(authz_tables::SCOPES_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("scope_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_scope_stmt = client.prepare_cached(&update_scope_sql).await.unwrap();

        let response = client
            .execute(
                &update_scope_stmt,
                &[
                    &scope.name,
                    &scope.display_name,
                    &scope.description,
                    &scope.metadata.updated_by,
                    &scope.metadata.updated_at,
                    &scope.realm_id,
                    &scope.server_id,
                    &scope.scope_id,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to update scope".to_string())
                }
            }
        }
    }

    async fn load_scope_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> Result<Option<ScopeModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_scope_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::SCOPES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("scope_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_scope_stmt = client.prepare_cached(&load_scope_sql).await.unwrap();
        let result = client
            .query_opt(&load_scope_stmt, &[&realm_id, &server_id, &scope_id])
            .await;

        match &result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_scopes_by_realm(&self, realm_id: &str) -> Result<Vec<ScopeModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_scopes_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::SCOPES_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_scopes_stmt = client.prepare_cached(&load_scopes_sql).await.unwrap();
        let result = client.query(&load_scopes_stmt, &[&realm_id]).await;

        match result {
            Ok(rows) => Ok(rows.iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_scopes_by_realm_and_server(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Vec<ScopeModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_scopes_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::SCOPES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_scopes_stmt = client.prepare_cached(&load_scopes_sql).await.unwrap();
        let result = client
            .query(&load_scopes_stmt, &[&realm_id, &server_id])
            .await;

        match result {
            Ok(rows) => Ok(rows.iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn delete_scope_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_scope_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::SCOPES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("scope_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let delete_scope_stmt = client.prepare_cached(&delete_scope_sql).await.unwrap();
        let result = client
            .execute(&delete_scope_stmt, &[&realm_id, &server_id, &scope_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to update scope".to_string())
                }
            }
        }
    }

    async fn scope_exists_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_scope_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::SCOPES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("scope_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_scope_stmt = client.prepare_cached(&load_scope_sql).await.unwrap();
        let result = client
            .query_one(&load_scope_stmt, &[&realm_id, &server_id, &scope_id])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn scope_exists_by_name(
        &self,
        realm_id: &str,
        server_id: &str,
        name: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_scope_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::SCOPES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_scope_stmt = client.prepare_cached(&load_scope_sql).await.unwrap();
        let result = client
            .query_one(&load_scope_stmt, &[&realm_id, &server_id, &name])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IPolicyProvider)]
pub struct RdsPolicyProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsPolicyProvider {
    pub fn read_record(&self, row: &Row) -> PolicyModel {
        todo!()
    }
}

#[async_trait]
impl IPolicyProvider for RdsPolicyProvider {
    async fn create_policy(&self, policy: &PolicyModel) -> Result<(), String> {
        todo!()
    }

    async fn udpate_policy(&self, policy: &PolicyModel) -> Result<(), String> {
        todo!()
    }

    async fn load_policy_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> Result<Option<PolicyModel>, String> {
        todo!()
    }

    async fn load_policy_scopes_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> Result<Vec<PolicyModel>, String> {
        todo!()
    }

    async fn load_policy_resources_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> Result<Vec<PolicyModel>, String> {
        todo!()
    }

    async fn load_associated_policies_by_policy_id(
        &self,
        realm_id: &str,
        server_id: &str,
        scope_id: &str,
    ) -> Result<Vec<PolicyModel>, String> {
        todo!()
    }

    async fn load_policies_by_server_id(
        &self,
        realm_id: &str,
        server_id: &str,
        name: &str,
    ) -> Result<Vec<PolicyModel>, String> {
        todo!()
    }

    async fn count_policies(&self, realm_id: &str, server_id: &str) -> Result<u64, String> {
        todo!()
    }

    async fn search_policies(
        &self,
        realm_id: &str,
        search_query: &str,
    ) -> Result<Vec<PolicyModel>, String> {
        todo!()
    }

    async fn delete_policy_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> Result<bool, String> {
        todo!()
    }
}
