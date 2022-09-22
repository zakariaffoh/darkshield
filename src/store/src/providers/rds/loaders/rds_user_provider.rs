use async_trait::async_trait;
use models::auditable::AuditableModel;
use models::entities::attributes::AttributesMap;
use models::entities::user::UserModel;
use tokio_postgres::Row;

use std::sync::Arc;

use shaku::Component;

use crate::providers::core::builder::SelectCountRequestBuilder;
use crate::providers::interfaces::user_provider::IUserProvider;
use crate::providers::rds::client::postgres_client::IDataBaseManager;

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
    fn read_user_record(&self, row: Row) -> UserModel {
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
impl IUserProvider for RdsUserProvider {
    /*async fn create_user(&self, user: UserModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_user_sql = InsertRequestBuilder::new()
            .table_name(user_table::USER_TABLE.table_name.clone())
            .columns(user_table::USER_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let metadata = user.metadata.as_ref().unwrap();
        let response = client
            .execute(
                &create_user_sql,
                &[
                    &user.realm_id,
                    &user.user_name,
                    &user.enabled,
                    &user.email,
                    &user.email_verified,
                    &user.required_actions,
                    &user.not_before,
                    &user.user_storage,
                    &user.attributes,
                    &user.is_service_account,
                    &user.service_account_client_link,
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

    async fn update_user(&self, user: &UserModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_role_sql = UpdateRequestBuilder::new()
            .table_name(user_table::USER_TABLE.table_name.clone())
            .columns(user_table::USER_TABLE.update_columns.clone())
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let metadata = user.metadata.as_ref().unwrap();

        let response = client
            .execute(
                &update_role_sql,
                &[
                    &user.enabled,
                    &user.email,
                    &user.email_verified,
                    &user.required_actions,
                    &user.not_before,
                    &user.user_storage,
                    &user.attributes,
                    &user.is_service_account,
                    &user.service_account_client_link,
                    &metadata.updated_by,
                    &metadata.updated_at,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
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
            .table_name(user_table::USER_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let result = client
            .query_one(&load_user_sql, &[&realm_id, &user_name])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, u32>(0) as u32 > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn user_exists_by_email(&self, realm_id: &str, email: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_user_sql = SelectCountRequestBuilder::new()
            .table_name(user_table::USER_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("email".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let result = client.query_one(&load_user_sql, &[&realm_id, &email]).await;
        match result {
            Ok(row) => Ok(row.get::<usize, u32>(0) as u32 > 0),
            Err(error) => Err(error.to_string()),
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
        let load_user_stmt = client
            .prepare_cached(&user_table::SELECT_USER_BY_USER_NAME_EMAIL)
            .await
            .unwrap();
        let result = client
            .query_opt(&load_user_stmt, &[&realm_id, &user_name, &email])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_user_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
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
            .table_name(user_table::USER_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_name".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_user_stmt = client.prepare_cached(&load_user_sql).await.unwrap();
        let result = client
            .query_opt(&load_user_stmt, &[&realm_id, &user_name])
            .await;
        match result {
            Ok(row) => {
                if let Some(r) = row {
                    Ok(Some(self.read_user_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }*/
}
