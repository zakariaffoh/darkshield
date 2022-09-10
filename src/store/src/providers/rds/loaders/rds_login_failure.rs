use crate::providers::{
    core::builder::*,
    interfaces::login_failure::IUserLoginFailureProvider,
    rds::{client::postgres_client::IDataBaseManager, tables::login_table},
};

use async_trait::async_trait;
use models::authentication::login_failure::UserLoginFailure;
use shaku::Component;
use std::sync::Arc;
use tokio_postgres::Row;

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IUserLoginFailureProvider)]
pub struct RdsUserLoginFailureProvider {
    #[shaku(inject)]
    database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsUserLoginFailureProvider {
    pub fn read_record(&self, row: &Row) -> UserLoginFailure {
        UserLoginFailure::from_record(
            row.get("tenant"),
            row.get("failure_id"),
            row.get("user_id"),
            row.get("realm_id"),
            row.get("failed_login_not_before"),
            row.get("num_failures"),
            row.get("last_failure"),
            row.get("last_ip_failure"),
        )
    }
}

#[async_trait]
impl IUserLoginFailureProvider for RdsUserLoginFailureProvider {
    async fn add_user_login_failure(&self, login_failure: &UserLoginFailure) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_login_failure_sql = InsertRequestBuilder::new()
            .table_name(login_table::LOGIN_FAILURES_TABLE.table_name.clone())
            .columns(login_table::LOGIN_FAILURES_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_login_failure_stmt = client
            .prepare_cached(&create_login_failure_sql)
            .await
            .unwrap();
        let response = client
            .execute(
                &create_login_failure_stmt,
                &[
                    &login_failure.get_tenant(),
                    &login_failure.get_failure_id(),
                    &login_failure.get_realm_id(),
                    &login_failure.get_user_id(),
                    &login_failure.get_failed_login_not_before(),
                    &login_failure.get_num_failures(),
                    &login_failure.get_last_failure(),
                    &login_failure.get_last_ip_failure(),
                ],
            )
            .await;

        match response {
            Err(err) => {
                log::error!("Failed to create login failure entry. Error: {}", err);
                Err(err.to_string())
            }
            Ok(_) => Ok(()),
        }
    }

    async fn increment_login_failure(
        &self,
        login_failure: &UserLoginFailure,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let increment_login_failure_stmt = client
            .prepare_cached(&login_table::INCREMENT_LOGIN_FAILURE_QUERY)
            .await
            .unwrap();
        let response = client
            .execute(
                &increment_login_failure_stmt,
                &[
                    &login_failure.get_failed_login_not_before(),
                    &login_failure.get_num_failures(),
                    &login_failure.get_last_failure(),
                    &login_failure.get_last_ip_failure(),
                    &login_failure.get_tenant(),
                    &login_failure.get_realm_id(),
                    &login_failure.get_user_id(),
                ],
            )
            .await;

        match response {
            Err(err) => {
                log::error!("Failed to increment login failure. Error: {}", err);
                Err(err.to_string())
            }
            Ok(_) => Ok(()),
        }
    }

    async fn load_user_login_failure(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<UserLoginFailure>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_login_failure_sql = SelectRequestBuilder::new()
            .table_name(login_table::LOGIN_FAILURES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_login_failure_stmt = client
            .prepare_cached(&load_login_failure_sql)
            .await
            .unwrap();
        let result = client
            .query_opt(&load_login_failure_stmt, &[&realm_id, &user_id])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_record(&r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn remove_user_login_failure(&self, realm_id: &str, user_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_user_login_sql = DeleteQueryBuilder::new()
            .table_name(login_table::LOGIN_FAILURES_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_user_login_stmt = client.prepare_cached(&remove_user_login_sql).await.unwrap();
        let result = client
            .execute(&remove_user_login_stmt, &[&realm_id, &user_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to delete user login failure".to_string())
                }
            }
        }
    }

    async fn remove_all_user_login_failures(&self, realm_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_user_login_sql = DeleteQueryBuilder::new()
            .table_name(login_table::LOGIN_FAILURES_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_user_login_stmt = client.prepare_cached(&remove_user_login_sql).await.unwrap();
        let result = client.execute(&remove_user_login_stmt, &[&realm_id]).await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove all user logins failure".to_string())
                }
            }
        }
    }
}
