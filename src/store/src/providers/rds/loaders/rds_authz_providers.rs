use crate::providers::{
    core::builder::*,
    interfaces::authz_provider::*,
    rds::{
        client::postgres_client::IDataBaseManager,
        tables::{authz_tables, user_table},
    },
};
use async_recursion::async_recursion;
use async_trait::async_trait;
use deadpool_postgres::{Object, Transaction};
use log;
use models::{
    auditable::AuditableModel,
    entities::{attributes::AttributesMap, authz::*},
};
use postgres_types::ToSql;
use serde_json::{json, Map, Value};
use shaku::Component;
use std::{collections::BTreeMap, sync::Arc};
use tokio_postgres::Row;

use super::{
    rds_client_provider::{RdsClientProvider, RdsClientScopeProvider},
    rds_user_provider::RdsUserProvider,
};

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRoleProvider)]
pub struct RdsRoleProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsRoleProvider {
    pub fn read_record(row: &Row) -> RoleModel {
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

    pub async fn load_roles_by_query(
        client: &Object,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<RoleModel>, String> {
        let load_roles_stmt = client.prepare_cached(query).await.unwrap();
        let result = client.query(&load_roles_stmt, params).await;
        match result {
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsRoleProvider::read_record(&row))
                .collect()),
            Err(err) => Err(err.to_string()),
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
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsRoleProvider::read_record(&row))
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
        match &result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(RdsRoleProvider::read_record(r)))
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
                    Ok(Some(RdsRoleProvider::read_record(r)))
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
                    Ok(Some(RdsRoleProvider::read_record(r)))
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
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsRoleProvider::read_record(&row))
                .collect()),
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
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsRoleProvider::read_record(&row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_roles_by_ids(
        &self,
        realm_id: &str,
        role_ids: &[&str],
    ) -> Result<Vec<RoleModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::ROLE_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_in("role_id".to_string(), role_ids.len()),
            ])
            .sql_query()
            .unwrap();
        let load_roles_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
        params.push(&realm_id);
        for role_id in role_ids.iter() {
            params.push(role_id);
        }

        let result = client.query(&load_roles_stmt, params.as_slice()).await;
        match result {
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsRoleProvider::read_record(&row))
                .collect()),
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
    fn read_record(row: Row, roles: Vec<RoleModel>) -> GroupModel {
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
                let roles: Vec<RoleModel> = roles_rows
                    .unwrap()
                    .iter()
                    .map(|r| RdsRoleProvider::read_record(&r))
                    .collect();
                Ok(roles)
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_group_by_query(
        client: &Object,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<GroupModel>, String> {
        let load_groups_stmt = client.prepare_cached(query).await.unwrap();
        let result = client.query(&load_groups_stmt, params).await;
        match result {
            Ok(rows) => {
                let mut groups = Vec::new();
                for r in rows {
                    let roles_records = RdsGroupProvider::read_group_roles(
                        &client,
                        &r.get::<&str, &str>("realm_id"),
                        &r.get::<&str, &str>("group_id"),
                    )
                    .await;
                    if roles_records.is_ok() {
                        groups.push(RdsGroupProvider::read_record(r, roles_records.unwrap()));
                    } else {
                        return Err(roles_records.err().unwrap());
                    }
                }
                Ok(groups)
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
                    let roles_records =
                        RdsGroupProvider::read_group_roles(&client, realm_id, &group_id).await;
                    match roles_records {
                        Ok(roles) => Ok(Some(RdsGroupProvider::read_record(r, roles))),
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
                    let roles_records =
                        RdsGroupProvider::read_group_roles(&client, realm_id, &group_id).await;
                    match roles_records {
                        Ok(roles) => Ok(Some(RdsGroupProvider::read_record(r, roles))),
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
                    let roles_records = RdsGroupProvider::read_group_roles(
                        &client,
                        realm_id,
                        &r.get::<&str, &str>("group_id"),
                    )
                    .await;
                    if roles_records.is_ok() {
                        groups.push(RdsGroupProvider::read_record(r, roles_records.unwrap()));
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
                    let roles_records = RdsGroupProvider::read_group_roles(
                        &client,
                        realm_id,
                        &r.get::<&str, &str>("group_id"),
                    )
                    .await;
                    if roles_records.is_ok() {
                        groups.push(RdsGroupProvider::read_record(r, roles_records.unwrap()));
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
                    let roles_records = RdsGroupProvider::read_group_roles(
                        &client,
                        realm_id,
                        &r.get::<&str, &str>("group_id"),
                    )
                    .await;
                    if roles_records.is_ok() {
                        groups.push(RdsGroupProvider::read_record(r, roles_records.unwrap()));
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

    async fn load_group_by_ids(
        &self,
        realm_id: &str,
        group_ids: &[&str],
    ) -> Result<Vec<GroupModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::GROUP_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_in("group_id".to_string(), group_ids.len()),
            ])
            .sql_query()
            .unwrap();
        let load_roles_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();

        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
        params.push(&realm_id);
        for group_id in group_ids.iter() {
            params.push(group_id);
        }

        let result = client.query(&load_roles_stmt, params.as_slice()).await;
        match result {
            Ok(rows) => {
                let mut groups = Vec::new();
                for r in rows {
                    let roles_records = RdsGroupProvider::read_group_roles(
                        &client,
                        realm_id,
                        &r.get::<&str, &str>("group_id"),
                    )
                    .await;
                    if roles_records.is_ok() {
                        groups.push(RdsGroupProvider::read_record(r, roles_records.unwrap()));
                    } else {
                        return Err(roles_records.err().unwrap());
                    }
                }
                Ok(groups)
            }
            Err(err) => Err(err.to_string()),
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
    fn read_record(row: &Row) -> ResourceModel {
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

    async fn load_resources_by_query(
        client: &Object,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<ResourceModel>, String> {
        let load_resources_stmt = client.prepare_cached(&query).await.unwrap();
        let result = client.query(&load_resources_stmt, params).await;
        match result {
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsResourceProvider::read_record(&row))
                .collect()),
            Err(err) => Err(err.to_string()),
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
                    Ok(Some(RdsResourceProvider::read_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_resources_by_ids(
        &self,
        realm_id: &str,
        resource_ids: &[&str],
    ) -> Result<Vec<ResourceModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_resources_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::RESOURCES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_in("resource_id".to_string(), resource_ids.len()),
            ])
            .sql_query()
            .unwrap();

        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
        params.push(&realm_id);
        for resource_id in resource_ids.iter() {
            params.push(resource_id);
        }

        let client = client.unwrap();
        let load_resources_stmt = client.prepare_cached(&load_resources_sql).await.unwrap();
        let result = client.query(&load_resources_stmt, params.as_slice()).await;
        match result {
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsResourceProvider::read_record(&row))
                .collect()),
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
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsResourceProvider::read_record(&row))
                .collect()),
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
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsResourceProvider::read_record(&row))
                .collect()),
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
    fn read_record(row: &Row) -> ScopeModel {
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

    async fn load_scope_by_query(
        client: &Object,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<ScopeModel>, String> {
        let load_scopes_stmt = client.prepare_cached(&query).await.unwrap();
        let result = client.query(&load_scopes_stmt, params).await;

        match result {
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsScopeProvider::read_record(&row))
                .collect()),
            Err(err) => Err(err.to_string()),
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
                    Ok(Some(RdsScopeProvider::read_record(r)))
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
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsScopeProvider::read_record(&row))
                .collect()),
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
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsScopeProvider::read_record(&row))
                .collect()),
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

    async fn load_scopes_by_ids(
        &self,
        realm_id: &str,
        scope_ids: &[&str],
    ) -> Result<Vec<ScopeModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_scopes_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::SCOPES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_in("scope_id".to_string(), scope_ids.len()),
            ])
            .sql_query()
            .unwrap();

        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
        params.push(&realm_id);
        for scope_id in scope_ids.iter() {
            params.push(scope_id);
        }
        let client = client.unwrap();
        let load_scopes_stmt = client.prepare_cached(&load_scopes_sql).await.unwrap();
        let result = client.query(&load_scopes_stmt, params.as_slice()).await;

        match result {
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsScopeProvider::read_record(&row))
                .collect()),
            Err(err) => Err(err.to_string()),
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
    database_manager: Arc<dyn IDataBaseManager>,
}

#[async_trait]
impl IPolicyProvider for RdsPolicyProvider {
    async fn create_policy(&self, policy: &PolicyModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

        let create_policy_sql = InsertRequestBuilder::new()
            .table_name(authz_tables::POLICIES_TABLE.table_name.clone())
            .columns(authz_tables::POLICIES_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let mut client = client.unwrap();

        let transaction = client.transaction().await;

        let mut attributes_maps: Map<String, Value> = Map::new();

        match transaction {
            Ok(trx) => {
                self.associated_attributes_map(&policy, &mut attributes_maps);
                trx.execute(
                    &create_policy_sql,
                    &[
                        &policy.metadata.tenant,
                        &policy.policy_id,
                        &policy.realm_id,
                        &policy.server_id,
                        &policy.name,
                        &policy.description,
                        &policy.policy_type,
                        &policy.decision,
                        &policy.logic,
                        &policy.policy_owner,
                        &json!(policy.configs),
                        &json!(attributes_maps),
                        &policy.metadata.created_by,
                        &policy.metadata.created_at,
                        &policy.metadata.version,
                    ],
                )
                .await
                .unwrap();

                match self.save_policies_associated_entities(&trx, &policy).await {
                    Ok(_) => {}
                    Err(err) => return Err(err.to_string()),
                }

                trx.commit().await.unwrap();
                Ok(())
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn udpate_policy(&self, policy: &PolicyModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

        let udpate_policy_sql = UpdateRequestBuilder::new()
            .table_name(authz_tables::POLICIES_TABLE.table_name.clone())
            .columns(authz_tables::POLICIES_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let mut client = client.unwrap();

        let transaction = client.transaction().await;

        let mut attributes_maps: Map<String, Value> = Map::new();

        match transaction {
            Ok(trx) => {
                self.associated_attributes_map(&policy, &mut attributes_maps);
                trx.execute(
                    &udpate_policy_sql,
                    &[
                        &policy.name,
                        &policy.description,
                        &policy.policy_type,
                        &policy.decision,
                        &policy.logic,
                        &policy.policy_owner,
                        &json!(policy.configs),
                        &json!(attributes_maps),
                        &policy.metadata.updated_by,
                        &policy.metadata.updated_at,
                        &policy.realm_id,
                        &policy.server_id,
                        &policy.policy_id,
                    ],
                )
                .await
                .unwrap();

                match self.save_policies_associated_entities(&trx, &policy).await {
                    Ok(_) => {}
                    Err(err) => return Err(err.to_string()),
                }
                trx.commit().await.unwrap();
                Ok(())
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_policy_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> Result<Option<PolicyModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        self.load_policy_by_id_with_client(&client.unwrap(), &realm_id, &server_id, &policy_id)
            .await
    }

    async fn load_policy_scopes_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> Result<Vec<ScopeModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        RdsScopeProvider::load_scope_by_query(
            &client.unwrap(),
            &authz_tables::SELECT_SCOPES_BY_POLICY_ID,
            &[&realm_id, &server_id, &policy_id],
        )
        .await
    }

    async fn load_policy_resources_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> Result<Vec<ResourceModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        RdsResourceProvider::load_resources_by_query(
            &client.unwrap(),
            &authz_tables::SELECT_RESOURCES_BY_POLICY_ID,
            &[&realm_id, &server_id, &policy_id],
        )
        .await
    }

    async fn load_associated_policies_by_policy_id(
        &self,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> Result<Vec<PolicyModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        self.load_associated_policies(&client.unwrap(), &realm_id, &server_id, &policy_id)
            .await
    }

    async fn load_policies_by_server_id(
        &self,
        realm_id: &str,
        server_id: &str,
    ) -> Result<Vec<PolicyModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_policies_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_policies_stmt = client.prepare_cached(&load_policies_sql).await.unwrap();
        let results = client
            .query(&load_policies_stmt, &[&realm_id, &server_id])
            .await;

        match results {
            Ok(result_rows) => {
                let mut policies = Vec::new();
                for row in result_rows {
                    let mut policy = self.read_record(&row);
                    let attributes_map: Map<String, Value> =
                        serde_json::from_value(row.get::<&str, Value>("attributes")).unwrap();

                    if let Err(err) = self
                        .load_policy_associated_entities(
                            &client,
                            &realm_id,
                            &server_id,
                            &policy.policy_id.to_owned(),
                            &mut policy,
                            attributes_map,
                        )
                        .await
                    {
                        return Err(err);
                    } else {
                        policies.push(policy);
                    }
                }
                return Ok(policies);
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_policies_by_ids(
        &self,
        realm_id: &str,
        server_id: &str,
        policies_ids: &[&str],
    ) -> Result<Vec<PolicyModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_policies_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_in("policy_id".to_string(), policies_ids.len()),
            ])
            .sql_query()
            .unwrap();

        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
        params.push(&realm_id);
        params.push(&server_id);
        for policy_id in policies_ids.iter() {
            params.push(policy_id);
        }

        let client = client.unwrap();
        let load_policies_stmt = client.prepare_cached(&load_policies_sql).await.unwrap();
        let results = client.query(&load_policies_stmt, params.as_slice()).await;

        match results {
            Ok(result_rows) => {
                let mut policies = Vec::new();
                for row in result_rows {
                    let mut policy = self.read_record(&row);
                    let attributes_map: Map<String, Value> =
                        serde_json::from_value(row.get::<&str, Value>("attributes")).unwrap();

                    if let Err(err) = self
                        .load_policy_associated_entities(
                            &client,
                            &realm_id,
                            &server_id,
                            &policy.policy_id.to_owned(),
                            &mut policy,
                            attributes_map,
                        )
                        .await
                    {
                        return Err(err);
                    } else {
                        policies.push(policy);
                    }
                }
                return Ok(policies);
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn count_policies(&self, _realm_id: &str, _server_id: &str) -> Result<u64, String> {
        todo!()
    }

    async fn search_policies(
        &self,
        _realm_id: &str,
        _search_query: &str,
    ) -> Result<Vec<PolicyModel>, String> {
        todo!()
    }

    async fn delete_policy_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let mut client = client.unwrap();

        let remove_policy_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let remove_policy_roles_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::ROLES_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let remove_policy_groups_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::GROUPS_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let remove_policy_clients_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::CLIENTS_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let remove_policy_scopes_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::SCOPES_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let remove_policy_resources_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::RESOURCES_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let remove_policy_clients_scopes_sql = DeleteQueryBuilder::new()
            .table_name(
                authz_tables::CLIENTS_SCOPES_POLICIES_TABLE
                    .table_name
                    .clone(),
            )
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let remove_policy_users_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::USERS_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let remove_associated_policy_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::POLICIES_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let transaction = client.transaction().await;
        match transaction {
            Ok(trx) => {
                trx.execute(
                    &remove_policy_users_sql,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await
                .unwrap();

                trx.execute(
                    &remove_policy_scopes_sql,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await
                .unwrap();

                trx.execute(
                    &remove_policy_resources_sql,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await
                .unwrap();

                trx.execute(
                    &remove_policy_roles_sql,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await
                .unwrap();

                trx.execute(
                    &remove_policy_groups_sql,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await
                .unwrap();

                trx.execute(
                    &remove_policy_clients_sql,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await
                .unwrap();

                trx.execute(
                    &remove_policy_clients_scopes_sql,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await
                .unwrap();

                trx.execute(
                    &remove_associated_policy_sql,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await
                .unwrap();

                trx.execute(&remove_policy_sql, &[&realm_id, &server_id, &policy_id])
                    .await
                    .unwrap();

                return Ok(());
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn policy_exists_by_name(
        &self,
        realm_id: &str,
        server_id: &str,
        name: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_policy_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("name".to_string()),
            ])
            .sql_query()
            .unwrap();

        RdsPolicyProvider::policy_exists_by_query(
            &client.unwrap(),
            &load_policy_sql,
            &[&realm_id, &server_id, &name],
        )
        .await
    }

    async fn policy_exists_by_id(
        &self,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_policy_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        RdsPolicyProvider::policy_exists_by_query(
            &client.unwrap(),
            &load_policy_sql,
            &[&realm_id, &server_id, &policy_id],
        )
        .await
    }
}

impl RdsPolicyProvider {
    pub fn read_record(&self, row: &Row) -> PolicyModel {
        let configs = serde_json::from_value::<BTreeMap<String, String>>(
            row.get::<&str, serde_json::Value>("configs"),
        )
        .map_or_else(|_| None, |p| Some(p));

        PolicyModel {
            policy_id: row.get("policy_id"),
            server_id: row.get("server_id"),
            realm_id: row.get("realm_id"),
            policy_type: row.get("policy_type"),
            name: row.get("name"),
            description: row.get("description"),
            decision: row.get("decision"),
            logic: row.get("logic"),
            policy_owner: row.get("policy_owner"),
            configs: configs,
            policies: None,
            resources: None,
            scopes: None,
            roles: None,
            groups: None,
            regex: None,
            time: None,
            users: None,
            script: None,
            client_scopes: None,
            clients: None,
            resource_type: None,
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

    fn associated_attributes_map(
        &self,
        policy: &PolicyModel,
        attributes_maps: &mut Map<String, Value>,
    ) {
        if let Some(groups) = &policy.groups {
            attributes_maps.insert(
                "group_claim".to_owned(),
                Value::String(groups.group_claim.clone()),
            );
        }

        if let Some(regex) = &policy.regex {
            attributes_maps.insert(
                "target_regex".to_owned(),
                Value::String(regex.target_regex.clone()),
            );
            attributes_maps.insert(
                "target_claim".to_owned(),
                Value::String(regex.target_claim.clone()),
            );
        }

        if let Some(script) = &policy.script {
            attributes_maps.insert("script".to_owned(), Value::String(script.clone()));
        }

        if let Some(resource_type) = &policy.resource_type {
            attributes_maps.insert(
                "resource_type".to_owned(),
                Value::String(resource_type.to_owned()),
            );
        }
        if let Some(time) = &policy.time {
            attributes_maps.insert(
                "policy_time".to_owned(),
                serde_json::to_value(time).unwrap(),
            );
        }
    }

    async fn save_policies_associated_entities(
        &self,
        trx: &Transaction<'_>,
        policy: &PolicyModel,
    ) -> Result<(), String> {
        let delete_client_policies_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::CLIENTS_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        trx.execute(
            &delete_client_policies_sql,
            &[&policy.realm_id, &policy.policy_id],
        )
        .await
        .unwrap();

        if let Some(clients) = &policy.clients {
            if !clients.is_empty() {
                let create_client_policies_sql = InsertRequestBuilder::new()
                    .table_name(authz_tables::CLIENTS_POLICIES_TABLE.table_name.clone())
                    .columns(authz_tables::CLIENTS_POLICIES_TABLE.insert_columns.clone())
                    .resolve_conflict(false)
                    .sql_query()
                    .unwrap();
                for client in clients {
                    trx.execute(
                        &create_client_policies_sql,
                        &[&policy.realm_id, &client.client_id, &policy.policy_id],
                    )
                    .await
                    .unwrap();
                }
            }
        }

        let delete_users_policies_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::USERS_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        trx.execute(
            &delete_users_policies_sql,
            &[&policy.realm_id, &policy.policy_id],
        )
        .await
        .unwrap();

        if let Some(users) = &policy.users {
            if !users.is_empty() {
                let create_users_policies_sql = InsertRequestBuilder::new()
                    .table_name(authz_tables::USERS_POLICIES_TABLE.table_name.clone())
                    .columns(authz_tables::USERS_POLICIES_TABLE.insert_columns.clone())
                    .resolve_conflict(false)
                    .sql_query()
                    .unwrap();

                for user in users {
                    trx.execute(
                        &create_users_policies_sql,
                        &[&policy.realm_id, &user.user_id, &policy.policy_id],
                    )
                    .await
                    .unwrap();
                }
            }
        }

        let delete_roles_policies_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::ROLES_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        trx.execute(
            &delete_roles_policies_sql,
            &[&policy.realm_id, &policy.policy_id],
        )
        .await
        .unwrap();

        if let Some(roles) = &policy.roles {
            if !roles.is_empty() {
                let create_roles_policies_sql = InsertRequestBuilder::new()
                    .table_name(authz_tables::ROLES_POLICIES_TABLE.table_name.clone())
                    .columns(authz_tables::ROLES_POLICIES_TABLE.insert_columns.clone())
                    .resolve_conflict(false)
                    .sql_query()
                    .unwrap();

                for role in roles {
                    trx.execute(
                        &create_roles_policies_sql,
                        &[&policy.realm_id, &role.role_id, &policy.policy_id],
                    )
                    .await
                    .unwrap();
                }
            }
        }

        let delete_groups_policies_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::GROUPS_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        trx.execute(
            &delete_groups_policies_sql,
            &[&policy.realm_id, &policy.policy_id],
        )
        .await
        .unwrap();

        if let Some(groups) = &policy.groups {
            if !groups.groups.is_empty() {
                let create_groups_policies_sql = InsertRequestBuilder::new()
                    .table_name(authz_tables::GROUPS_POLICIES_TABLE.table_name.clone())
                    .columns(authz_tables::GROUPS_POLICIES_TABLE.insert_columns.clone())
                    .resolve_conflict(false)
                    .sql_query()
                    .unwrap();

                for group in &groups.groups {
                    trx.execute(
                        &create_groups_policies_sql,
                        &[&policy.realm_id, &group.group_id, &policy.policy_id],
                    )
                    .await
                    .unwrap();
                }
            }
        }

        let delete_associated_policies_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::POLICIES_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        trx.execute(
            &delete_associated_policies_sql,
            &[&policy.realm_id, &policy.policy_id],
        )
        .await
        .unwrap();

        if let Some(policies) = &policy.policies {
            if !policies.is_empty() {
                let create_associated_policies_sql = InsertRequestBuilder::new()
                    .table_name(authz_tables::GROUPS_POLICIES_TABLE.table_name.clone())
                    .columns(authz_tables::GROUPS_POLICIES_TABLE.insert_columns.clone())
                    .resolve_conflict(false)
                    .sql_query()
                    .unwrap();

                for associated_policy in policies {
                    trx.execute(
                        &create_associated_policies_sql,
                        &[
                            &policy.realm_id,
                            &policy.policy_id,
                            &associated_policy.policy_id,
                        ],
                    )
                    .await
                    .unwrap();
                }
            }
        }

        let delete_resources_policies_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::RESOURCES_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        trx.execute(
            &delete_resources_policies_sql,
            &[&policy.realm_id, &policy.policy_id],
        )
        .await
        .unwrap();

        if let Some(resources) = &policy.resources {
            if !resources.is_empty() {
                let create_resources_policies_sql = InsertRequestBuilder::new()
                    .table_name(authz_tables::RESOURCES_POLICIES_TABLE.table_name.clone())
                    .columns(
                        authz_tables::RESOURCES_POLICIES_TABLE
                            .insert_columns
                            .clone(),
                    )
                    .resolve_conflict(false)
                    .sql_query()
                    .unwrap();

                for resource in resources {
                    trx.execute(
                        &create_resources_policies_sql,
                        &[&policy.realm_id, &resource.resource_id, &policy.policy_id],
                    )
                    .await
                    .unwrap();
                }
            }
        }

        let delete_scopes_policies_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::SCOPES_POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        trx.execute(
            &delete_scopes_policies_sql,
            &[&policy.realm_id, &policy.policy_id],
        )
        .await
        .unwrap();

        if let Some(scopes) = &policy.scopes {
            if !scopes.is_empty() {
                let create_scope_policies_sql = InsertRequestBuilder::new()
                    .table_name(authz_tables::SCOPES_POLICIES_TABLE.table_name.clone())
                    .columns(authz_tables::SCOPES_POLICIES_TABLE.insert_columns.clone())
                    .resolve_conflict(false)
                    .sql_query()
                    .unwrap();

                for scope in scopes {
                    trx.execute(
                        &create_scope_policies_sql,
                        &[&policy.realm_id, &scope.scope_id, &policy.policy_id],
                    )
                    .await
                    .unwrap();
                }
            }
        }

        let delete_clients_scopes_policies_sql = DeleteQueryBuilder::new()
            .table_name(
                authz_tables::CLIENTS_SCOPES_POLICIES_TABLE
                    .table_name
                    .clone(),
            )
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        trx.execute(
            &delete_clients_scopes_policies_sql,
            &[&policy.realm_id, &policy.policy_id],
        )
        .await
        .unwrap();

        if let Some(client_scopes) = &policy.client_scopes {
            if !client_scopes.is_empty() {
                let create_clients_scopes_policies_sql = InsertRequestBuilder::new()
                    .table_name(
                        authz_tables::CLIENTS_SCOPES_POLICIES_TABLE
                            .table_name
                            .clone(),
                    )
                    .columns(
                        authz_tables::CLIENTS_SCOPES_POLICIES_TABLE
                            .insert_columns
                            .clone(),
                    )
                    .resolve_conflict(false)
                    .sql_query()
                    .unwrap();

                for client_scope in client_scopes {
                    trx.execute(
                        &create_clients_scopes_policies_sql,
                        &[
                            &policy.realm_id,
                            &client_scope.client_scope_id,
                            &policy.policy_id,
                        ],
                    )
                    .await
                    .unwrap();
                }
            }
        }

        Ok(())
    }

    #[async_recursion]
    async fn load_policy_associated_entities(
        &self,
        client: &Object,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
        policy: &mut PolicyModel,
        attributes_values: Map<String, Value>,
    ) -> Result<(), String> {
        let policy_type = &policy.policy_type;

        let loaded_associated_policies = self
            .load_associated_policies(&client, &realm_id, &server_id, &policy_id)
            .await;

        match loaded_associated_policies {
            Ok(policies) => {
                policy.policies = Some(policies);
            }
            Err(err) => return Err(err.to_string()),
        }

        match policy_type {
            PolicyTypeEnum::RolePolicy => {
                let loaded_roles = RdsRoleProvider::load_roles_by_query(
                    client,
                    &authz_tables::SELECT_GROUPS_BY_POLICY_ID,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await;
                match loaded_roles {
                    Ok(roles) => {
                        policy.roles = Some(roles);
                    }
                    Err(err) => return Err(err.to_string()),
                }
            }
            PolicyTypeEnum::GroupPolicy => {
                let group_claim: String;
                match attributes_values.get("group_claim") {
                    Some(Value::String(claim_value)) => group_claim = claim_value.to_owned(),
                    _ => {
                        return Err(
                            "failed to read group policy, missing group claim field".to_owned()
                        )
                    }
                }

                let loaded_groups = RdsGroupProvider::load_group_by_query(
                    client,
                    &authz_tables::SELECT_GROUPS_BY_POLICY_ID,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await;
                match loaded_groups {
                    Ok(grps) => {
                        policy.groups = Some(GroupPolicyConfig {
                            group_claim: group_claim,
                            groups: grps,
                        });
                    }
                    Err(err) => return Err(err.to_string()),
                }
            }
            PolicyTypeEnum::ScopePermission => {
                match attributes_values.get("resource_type") {
                    Some(Value::String(rsctype)) => {
                        policy.resource_type = Some(rsctype.to_owned());
                    }
                    _ => {
                        return Err(
                            "failed to read scope permission policy, missing resource_type field"
                                .to_owned(),
                        )
                    }
                }

                let loaded_scopes = RdsScopeProvider::load_scope_by_query(
                    client,
                    &authz_tables::SELECT_SCOPES_BY_POLICY_ID,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await;
                match loaded_scopes {
                    Ok(scps) => policy.scopes = Some(scps),
                    Err(err) => return Err(err.to_string()),
                }
            }
            PolicyTypeEnum::ResourcePermission => {
                match attributes_values.get("resource_type") {
                    Some(Value::String(rsctype)) => {
                        policy.resource_type = Some(rsctype.to_owned());
                    }
                    _ => return Err(
                        "failed to read resource permission policy, missing resource_type field"
                            .to_owned(),
                    ),
                }

                let loaded_resources = RdsResourceProvider::load_resources_by_query(
                    client,
                    &authz_tables::SELECT_RESOURCES_BY_POLICY_ID,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await;
                match loaded_resources {
                    Ok(rscs) => policy.resources = Some(rscs),
                    Err(err) => return Err(err.to_string()),
                }
            }
            PolicyTypeEnum::UserPolicy => {
                let loaded_users = RdsUserProvider::load_users_by_query(
                    client,
                    &authz_tables::SELECT_USERS_BY_POLICY_ID,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await;
                match loaded_users {
                    Ok(usrs) => policy.users = Some(usrs),
                    Err(err) => return Err(err.to_string()),
                }
            }
            PolicyTypeEnum::ClientPolicy => {
                let loaded_clients = RdsClientProvider::load_clients_by_query(
                    client,
                    &authz_tables::SELECT_CLIENTS_BY_POLICY_ID,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await;
                match loaded_clients {
                    Ok(cls) => policy.clients = Some(cls),
                    Err(err) => return Err(err.to_string()),
                }
            }
            PolicyTypeEnum::TimePolicy => match attributes_values.get("policy_time") {
                Some(time) => match serde_json::from_value::<TimePolicyConfig>(time.clone()) {
                    Ok(cf) => policy.time = Some(cf),
                    Err(err) => return Err(err.to_string()),
                },
                _ => return Err("failed to read regex policy".to_owned()),
            },
            PolicyTypeEnum::RegexPolicy => {
                let target_regex;
                let target_claim;
                match attributes_values.get("target_regex") {
                    Some(Value::String(t_regex)) => {
                        target_regex = t_regex;
                    }
                    _ => return Err("failed to read regex policy".to_owned()),
                }
                match attributes_values.get("target_claim") {
                    Some(Value::String(t_claim)) => {
                        target_claim = t_claim;
                    }
                    _ => return Err("failed to read regex policy".to_owned()),
                }

                policy.regex = Some(RegexConfig {
                    target_claim: target_claim.to_owned(),
                    target_regex: target_regex.to_owned(),
                })
            }
            PolicyTypeEnum::ClientScopePolicy => {
                let loaded_clients_scopes = RdsClientScopeProvider::load_clients_scopes_by_query(
                    client,
                    &authz_tables::SELECT_CLIENTS_SCOPES_BY_POLICY_ID,
                    &[&realm_id, &server_id, &policy_id],
                )
                .await;
                match loaded_clients_scopes {
                    Ok(cls) => policy.client_scopes = Some(cls),
                    Err(err) => return Err(err.to_string()),
                }
            }
            PolicyTypeEnum::PyPolicy => match attributes_values.get("script") {
                Some(Value::String(script_value)) => {
                    policy.script = Some(script_value.to_owned());
                }
                _ => return Err("failed to read py policy, missing script field".to_owned()),
            },
            PolicyTypeEnum::AggregatedPolicy => {}
        }
        Ok(())
    }

    #[async_recursion]
    async fn load_associated_policies(
        &self,
        client: &Object,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> Result<Vec<PolicyModel>, String> {
        let mut policies = Vec::new();

        let associated_policy_select_stmt = client
            .prepare_cached(&authz_tables::SELECT_ASSOCIATED_POLICIES_BY_POLICY_ID)
            .await
            .unwrap();

        let associated_polciy_records = client
            .query(
                &associated_policy_select_stmt,
                &[&realm_id, &server_id, &policy_id],
            )
            .await;

        match associated_polciy_records {
            Ok(rows) => {
                let associated_policy_ids: Vec<String> = rows
                    .iter()
                    .map(|r| r.get::<&str, String>("associated_policy_id"))
                    .collect();
                for associated_policy_id in associated_policy_ids {
                    let loaded_policy = self
                        .load_policy_by_id_with_client(
                            &client,
                            realm_id,
                            server_id,
                            &associated_policy_id,
                        )
                        .await;
                    match loaded_policy {
                        Ok(Some(policy)) => policies.push(policy),
                        Ok(_) => {
                            return Err(format!(
                                "failed to load associated policy {} for policy {}",
                                &associated_policy_id, &policy_id
                            ));
                        }
                        Err(err) => return Err(err.to_string()),
                    }
                }
                return Ok(policies);
            }
            Err(err) => return Err(err.to_string()),
        }
    }

    #[async_recursion]
    async fn load_policy_by_id_with_client(
        &self,
        client: &Object,
        realm_id: &str,
        server_id: &str,
        policy_id: &str,
    ) -> Result<Option<PolicyModel>, String> {
        let load_policy_sql = SelectRequestBuilder::new()
            .table_name(authz_tables::POLICIES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("server_id".to_string()),
                SqlCriteriaBuilder::is_equals("policy_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let load_policy_stmt = client.prepare_cached(&load_policy_sql).await.unwrap();
        let result = client
            .query_opt(&load_policy_stmt, &[&realm_id, &server_id, &policy_id])
            .await;

        match result {
            Ok(result_row) => match result_row {
                Some(row) => {
                    let mut policy = self.read_record(&row);
                    let attributes_map: Map<String, Value> =
                        serde_json::from_value(row.get::<&str, Value>("attributes")).unwrap();

                    if let Err(err) = self
                        .load_policy_associated_entities(
                            &client,
                            &realm_id,
                            &server_id,
                            &policy_id,
                            &mut policy,
                            attributes_map,
                        )
                        .await
                    {
                        return Err(err);
                    } else {
                        return Ok(Some(policy));
                    }
                }
                _ => return Ok(None),
            },
            Err(err) => return Err(err.to_string()),
        }
    }

    async fn policy_exists_by_query(
        client: &Object,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<bool, String> {
        let load_policy_stmt = client.prepare_cached(&query).await.unwrap();
        let result = client.query_one(&load_policy_stmt, params).await;
        match result {
            Ok(row) => Ok(row.get::<usize, i32>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}
