use async_trait::async_trait;
use deadpool_postgres::Object;
use models::auditable::AuditableModel;
use models::entities::attributes::AttributesMap;
use models::entities::authz::RolePagingResult;
use models::entities::credentials::UserCredentialModel;
use models::entities::user::{UserModel, UserPagingResult};
use postgres_types::ToSql;
use serde_json::json;
use tokio_postgres::Row;

use std::sync::Arc;

use shaku::Component;

use crate::providers::core::builder::{DeleteQueryBuilder, SelectCountRequestBuilder};
use crate::providers::interfaces::user_provider::IUserProvider;
use crate::providers::rds::client::postgres_client::IDataBaseManager;

use crate::providers::rds::tables::credential_table;
use crate::providers::{
    core::builder::{
        InsertRequestBuilder, SelectRequestBuilder, SqlCriteriaBuilder, UpdateRequestBuilder,
    },
    rds::tables::user_table,
};

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IUserProvider)]
pub struct RdsUserProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsUserProvider {
    fn read_record(row: &Row) -> UserModel {
        let attributes = serde_json::from_value::<AttributesMap>(
            row.get::<&str, serde_json::Value>("attributes"),
        )
        .map_or_else(|_| None, |p| Some(p));

        UserModel {
            user_id: row.get("user_id"),
            realm_id: row.get("realm_id"),
            user_name: row.get("user_name"),
            enabled: row.get("enabled"),
            email: row.get("email"),
            email_verified: row.get("email_verified"),
            required_actions: row.get("required_actions"),
            not_before: row.get("not_before"),
            user_storage: row.get("user_storage"),
            attributes: attributes,
            is_service_account: row.get("is_service_account"),
            service_account_client_link: row.get("service_account_client_link"),
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

    pub async fn load_users_by_query(
        client: &Object,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<UserModel>, String> {
        let load_users_stmt = client.prepare_cached(&query).await.unwrap();
        let result = client.query(&load_users_stmt, params).await;
        match result {
            Ok(rows) => Ok(rows
                .iter()
                .map(|row| RdsUserProvider::read_record(&row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    pub async fn load_user_by_query(
        client: &Object,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<UserModel>, String> {
        let load_users_stmt = client.prepare_cached(&query).await.unwrap();
        let result = client.query_opt(&load_users_stmt, params).await;
        match result {
            Ok(Some(row)) => Ok(Some(RdsUserProvider::read_record(&row))),
            Ok(_) => Ok(None),
            Err(err) => Err(err.to_string()),
        }
    }

    pub async fn user_exist_by_criteria(
        client: &Object,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<bool, String> {
        let load_user_stmt = client.prepare_cached(&query).await.unwrap();
        let result = client.query_one(&load_user_stmt, &params).await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[async_trait]
impl IUserProvider for RdsUserProvider {
    async fn create_user(&self, user: &UserModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_user_sql = InsertRequestBuilder::new()
            .table_name(user_table::USERS_TABLE.table_name.clone())
            .columns(user_table::USERS_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();
        let mut client = client.unwrap();
        let transaction = client.transaction().await;

        match transaction {
            Ok(trx) => {
                let response = trx
                    .execute(
                        &create_user_sql,
                        &[
                            &user.metadata.tenant,
                            &user.realm_id,
                            &user.user_id,
                            &user.user_name,
                            &user.enabled,
                            &user.email,
                            &user.email_verified,
                            &json!(user.required_actions),
                            &user.not_before,
                            &user.user_storage,
                            &json!(user.attributes),
                            &user.is_service_account,
                            &user.service_account_client_link,
                            &user.metadata.created_by,
                            &user.metadata.created_at,
                            &user.metadata.version,
                        ],
                    )
                    .await;

                match response {
                    Err(err) => return Err(err.to_string()),
                    _ => {}
                }

                match trx.commit().await {
                    Err(err) => return Err(err.to_string()),
                    Ok(_) => Ok(()),
                }
            }
            Err(err) => return Err(err.to_string()),
        }
    }

    async fn udpate_user(&self, user: &UserModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_user_sql = UpdateRequestBuilder::new()
            .table_name(user_table::USERS_TABLE.table_name.clone())
            .columns(user_table::USERS_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_role_stmt = client.prepare_cached(&update_user_sql).await.unwrap();

        let response = client
            .execute(
                &update_role_stmt,
                &[
                    &user.user_name,
                    &user.enabled,
                    &json!(user.required_actions),
                    &user.not_before,
                    &user.user_storage,
                    &json!(user.attributes),
                    &user.is_service_account,
                    &user.service_account_client_link,
                    &user.metadata.updated_by,
                    &user.metadata.updated_at,
                    &user.metadata.tenant,
                    &user.realm_id,
                    &user.user_id,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    return Ok(());
                } else {
                    return Err("Failed to update role".to_string());
                }
            }
        }
    }

    async fn delete_user(&self, realm_id: &str, user_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();

        let delete_user_sql = DeleteQueryBuilder::new()
            .table_name(user_table::USERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .sql_query()
            .unwrap();
        let delete_user_stmt = client.prepare(&delete_user_sql).await.unwrap();

        let delete_user_groups_sql = DeleteQueryBuilder::new()
            .table_name(user_table::USERS_GROUPS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let delete_user_groups_stmt = client.prepare(&delete_user_groups_sql).await.unwrap();

        let delete_user_roles_sql = DeleteQueryBuilder::new()
            .table_name(user_table::USERS_ROLES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let delete_user_roles_stmt = client.prepare(&delete_user_roles_sql).await.unwrap();

        let delete_user_credentials_sql = DeleteQueryBuilder::new()
            .table_name(credential_table::USERS_CREDENTIALS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let delete_user_credentials_stmt =
            client.prepare(&delete_user_credentials_sql).await.unwrap();

        let mut client = client;
        let transaction = client.transaction().await;

        match transaction {
            Ok(trx) => {
                if let Err(err) = trx
                    .execute(&delete_user_roles_stmt, &[&realm_id, &user_id])
                    .await
                {
                    return Err(err.to_string());
                }

                if let Err(err) = trx
                    .execute(&delete_user_groups_stmt, &[&realm_id, &user_id])
                    .await
                {
                    return Err(err.to_string());
                }

                if let Err(err) = trx
                    .execute(&delete_user_credentials_stmt, &[&realm_id, &user_id])
                    .await
                {
                    return Err(err.to_string());
                }

                if let Err(err) = trx.execute(&delete_user_stmt, &[&realm_id, &user_id]).await {
                    return Err(err.to_string());
                }

                if let Err(err) = trx.commit().await {
                    return Err(err.to_string());
                };
                return Ok(());
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn user_exists_by_user_name(
        &self,
        realm_id: &str,
        user_name: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_user_sql = SelectCountRequestBuilder::new()
            .table_name(user_table::USERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_name".to_string()),
            ])
            .sql_query()
            .unwrap();
        let params: Vec<&(dyn ToSql + Sync)> = vec![&realm_id, &user_name];
        RdsUserProvider::user_exist_by_criteria(&client.unwrap(), &load_user_sql, &params).await
    }

    async fn user_exists_by_email(&self, realm_id: &str, email: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_user_sql = SelectCountRequestBuilder::new()
            .table_name(user_table::USERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("email".to_string()),
            ])
            .sql_query()
            .unwrap();
        let params: Vec<&(dyn ToSql + Sync)> = vec![&realm_id, &email];
        RdsUserProvider::user_exist_by_criteria(&client.unwrap(), &load_user_sql, &params).await
    }

    async fn user_exists_by_id(&self, realm_id: &str, user_id: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_user_sql = SelectCountRequestBuilder::new()
            .table_name(user_table::USERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .sql_query()
            .unwrap();
        let params: Vec<&(dyn ToSql + Sync)> = vec![&realm_id, &user_id];
        RdsUserProvider::user_exist_by_criteria(&client.unwrap(), &load_user_sql, &params).await
    }

    async fn add_user_role_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let add_user_role_sql = InsertRequestBuilder::new()
            .table_name(user_table::USERS_ROLES_TABLE.table_name.clone())
            .columns(user_table::USERS_ROLES_TABLE.insert_columns.clone())
            .resolve_conflict(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let add_user_role_stmt = client.prepare_cached(&add_user_role_sql).await.unwrap();
        let response = client
            .execute(&add_user_role_stmt, &[&realm_id, &user_id, &role_id])
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to add role to user".to_string())
                }
            }
        }
    }

    async fn remove_user_role_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        role_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_user_role_sql = DeleteQueryBuilder::new()
            .table_name(user_table::USERS_ROLES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
                SqlCriteriaBuilder::is_equals("role_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let delete_user_role_stmt = client.prepare_cached(&delete_user_role_sql).await.unwrap();
        let result = client
            .execute(&delete_user_role_stmt, &[&realm_id, &user_id, &role_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove role from user".to_string())
                }
            }
        }
    }

    async fn add_user_group_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let add_user_group_sql = InsertRequestBuilder::new()
            .table_name(user_table::USERS_GROUPS_TABLE.table_name.clone())
            .columns(user_table::USERS_GROUPS_TABLE.insert_columns.clone())
            .resolve_conflict(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let add_user_group_stmt = client.prepare_cached(&add_user_group_sql).await.unwrap();
        let response = client
            .execute(&add_user_group_stmt, &[&realm_id, &user_id, &group_id])
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to add group to user".to_string())
                }
            }
        }
    }

    async fn remove_user_group_mapping(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_user_group_sql = DeleteQueryBuilder::new()
            .table_name(user_table::USERS_GROUPS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
                SqlCriteriaBuilder::is_equals("group_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let delete_user_group_stmt = client.prepare_cached(&delete_user_group_sql).await.unwrap();
        let result = client
            .execute(&delete_user_group_stmt, &[&realm_id, &user_id, &group_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove group from user".to_string())
                }
            }
        }
    }

    async fn load_user_by_user_name_or_email(
        &self,
        realm_id: &str,
        user_name: &str,
        email: &str,
    ) -> Result<Option<UserModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

        let client = client.unwrap();
        let params: Vec<&(dyn ToSql + Sync)> = vec![&realm_id, &user_name, &email];
        RdsUserProvider::load_user_by_query(
            &client,
            &user_table::SELECT_USER_BY_USER_NAME_EMAIL,
            &params,
        )
        .await
    }

    async fn load_user_by_user_name(
        &self,
        realm_id: &str,
        user_name: &str,
    ) -> Result<Option<UserModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_user_sql = SelectRequestBuilder::new()
            .table_name(user_table::USERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let params: Vec<&(dyn ToSql + Sync)> = vec![&realm_id, &user_name];
        RdsUserProvider::load_user_by_query(&client, &load_user_sql, &params).await
    }

    async fn load_user_by_email(
        &self,
        realm_id: &str,
        email: &str,
    ) -> Result<Option<UserModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_user_sql = SelectRequestBuilder::new()
            .table_name(user_table::USERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("email".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let params: Vec<&(dyn ToSql + Sync)> = vec![&realm_id, &email];
        RdsUserProvider::load_user_by_query(&client, &load_user_sql, &params).await
    }

    async fn load_user_by_id(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<UserModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_user_sql = SelectRequestBuilder::new()
            .table_name(user_table::USERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let params: Vec<&(dyn ToSql + Sync)> = vec![&realm_id, &user_id];
        RdsUserProvider::load_user_by_query(&client, &load_user_sql, &params).await
    }

    async fn load_user_by_ids(
        &self,
        realm_id: &str,
        user_ids: &[&str],
    ) -> Result<Vec<UserModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_users_sql = SelectRequestBuilder::new()
            .table_name(user_table::USERS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_in("user_id".to_string(), user_ids.len()),
            ])
            .sql_query()
            .unwrap();

        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
        params.push(&realm_id);
        for user_id in user_ids.iter() {
            params.push(user_id);
        }
        RdsUserProvider::load_users_by_query(&client.unwrap(), &load_users_sql, &params).await
    }

    async fn count_users(&self, realm_id: &str) -> Result<u64, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let count_users_sql = SelectCountRequestBuilder::new()
            .table_name(user_table::USERS_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let count_users_stmt = client.prepare_cached(&count_users_sql).await.unwrap();
        let result = client.query_one(&count_users_stmt, &[&realm_id]).await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) as u64),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn load_users_paging(
        &self,
        realm_id: &str,
        page_index: &Option<u64>,
        page_size: &Option<u64>,
    ) -> Result<UserPagingResult, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let count_user_roles_stmt = client
            .prepare_cached(&user_table::SELECT_COUNT_USERS)
            .await
            .unwrap();

        let count_result = client.query_one(&count_user_roles_stmt, &[&realm_id]).await;
        if let Err(err) = count_result {
            return Err(err.to_string());
        }
        let total_users = count_result.unwrap().get::<usize, i64>(0);

        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
        params.push(&realm_id);
        let load_users_sql;
        let page_offset;
        let page_size_v;

        if page_index.is_none() || page_size.is_none() {
            load_users_sql = user_table::SELECT_USERS_BY_REALM.clone();
        } else {
            load_users_sql = user_table::SELECT_USERS_BY_REALM_PAGING.clone();
            page_offset = (page_index.unwrap() * page_size.unwrap()) as i64;
            page_size_v = (page_size.unwrap() as i64);
            params.push(&page_offset);
            params.push(&page_size_v);
        }

        let load_users_stmt = client.prepare_cached(&load_users_sql).await.unwrap();
        let result = client.query(&load_users_stmt, &params).await;
        match result {
            Ok(rows) => {
                let users = rows
                    .iter()
                    .map(|row| RdsUserProvider::read_record(&row))
                    .collect();
                return Ok(UserPagingResult {
                    page_size: page_size.clone(),
                    page_index: page_index.clone(),
                    total_count: Some(total_users as u64),
                    users: users,
                });
            }
            Err(err) => Err(err.to_string()),
        }
    }
}
