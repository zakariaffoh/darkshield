use crate::providers::{
    core::builder::*,
    interfaces::tokens_providers::{IRevokedTokenStoreProvider, ISingleUseTokenProvider},
    rds::{client::postgres_client::IDataBaseManager, tables::tokens_table},
};

use async_trait::async_trait;
use models::authentication::auth_tokens::SingleUseToken;
use shaku::Component;
use std::sync::Arc;
use tokio_postgres::Row;

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = ISingleUseTokenProvider)]
pub struct RdsSingleUseTokenProvider {
    #[shaku(inject)]
    database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsSingleUseTokenProvider {
    pub fn read_record(&self, row: &Row) -> SingleUseToken {
        SingleUseToken {
            tenant: row.get("tenant"),
            realm_id: row.get("realm_id"),
            token_id: row.get("token_id"),
            lifespan_in_secs: row.get("lifespan_in_secs"),
        }
    }
}

#[async_trait]
impl ISingleUseTokenProvider for RdsSingleUseTokenProvider {
    async fn add_token(
        &self,
        tenant: &str,
        realm_id: &str,
        token_id: &str,
        lifespan_in_secs: f64,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_single_user_token_sql = InsertRequestBuilder::new()
            .table_name(tokens_table::SINGLE_USE_TOKENS_TABLE.table_name.clone())
            .columns(tokens_table::SINGLE_USE_TOKENS_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_single_user_token_stmt = client
            .prepare_cached(&create_single_user_token_sql)
            .await
            .unwrap();
        let response = client
            .execute(
                &create_single_user_token_stmt,
                &[&tenant, &realm_id, &token_id, &lifespan_in_secs],
            )
            .await;

        match response {
            Err(err) => {
                log::error!("Failed to create single use token. Error: {}", err);
                Err(err.to_string())
            }
            Ok(_) => Ok(()),
        }
    }

    async fn token_exists(&self, realm_id: &str, token_id: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_single_use_token_sql = SelectCountRequestBuilder::new()
            .table_name(tokens_table::SINGLE_USE_TOKENS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("token_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_single_use_token_stmt = client
            .prepare_cached(&load_single_use_token_sql)
            .await
            .unwrap();
        let result = client
            .query_one(&load_single_use_token_stmt, &[&realm_id, &token_id])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) as u32 > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn delete_token(&self, realm_id: &str, token_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_single_use_token_sql = DeleteQueryBuilder::new()
            .table_name(tokens_table::SINGLE_USE_TOKENS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("token_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_single_use_token_stmt = client
            .prepare_cached(&remove_single_use_token_sql)
            .await
            .unwrap();
        let result = client
            .execute(&remove_single_use_token_stmt, &[&realm_id, &token_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove single use token".to_string())
                }
            }
        }
    }

    async fn load_token(
        &self,
        realm_id: &str,
        token_id: &str,
    ) -> Result<Option<SingleUseToken>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_single_use_token_sql = SelectRequestBuilder::new()
            .table_name(tokens_table::SINGLE_USE_TOKENS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("token_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_single_use_token_stmt = client
            .prepare_cached(&load_single_use_token_sql)
            .await
            .unwrap();
        let result = client
            .query_opt(&load_single_use_token_stmt, &[&realm_id, &token_id])
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
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRevokedTokenStoreProvider)]
pub struct RdsRevokedTokenStoreProvider {
    #[shaku(inject)]
    database_manager: Arc<dyn IDataBaseManager>,
}

#[async_trait]
impl IRevokedTokenStoreProvider for RdsRevokedTokenStoreProvider {
    async fn revoke_token(
        &self,
        tenant: &str,
        realm_id: &str,
        token_id: &str,
        current_time: f64,
        lifespan_in_secs: f64,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_roken_token_entry_sql = InsertRequestBuilder::new()
            .table_name(tokens_table::REVOKED_TOKENS_TABLE.table_name.clone())
            .columns(tokens_table::REVOKED_TOKENS_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_roken_token_entry_stmt = client
            .prepare_cached(&create_roken_token_entry_sql)
            .await
            .unwrap();
        let response = client
            .execute(
                &create_roken_token_entry_stmt,
                &[
                    &tenant,
                    &realm_id,
                    &token_id,
                    &current_time,
                    &lifespan_in_secs,
                ],
            )
            .await;

        match response {
            Err(err) => {
                log::error!("Failed to create single use token. Error: {}", err);
                Err(err.to_string())
            }
            Ok(_) => Ok(()),
        }
    }

    async fn is_token_revoked(&self, realm_id: &str, token_id: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_revoked_token_sql = SelectCountRequestBuilder::new()
            .table_name(tokens_table::REVOKED_TOKENS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("token_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_revoked_token_stmt = client
            .prepare_cached(&load_revoked_token_sql)
            .await
            .unwrap();
        let result = client
            .query_one(&load_revoked_token_stmt, &[&realm_id, &token_id])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) as u32 > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}
