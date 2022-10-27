use crate::providers::{
    core::builder::*,
    interfaces::credential_provider::ICredentialProvider,
    rds::{client::postgres_client::IDataBaseManager, tables::credential_table},
};
use async_trait::async_trait;
use log;
use models::entities::credentials::{CredentialFieldsMap, CredentialModel};
use models::{auditable::AuditableModel, entities::credentials::CredentialTypeEnum};
use serde_json::json;
use shaku::Component;
use std::sync::Arc;
use tokio_postgres::Row;

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = ICredentialProvider)]
pub struct RdsCredentialProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsCredentialProvider {
    pub fn read_record(&self, row: &Row) -> CredentialModel {
        let secret_data = serde_json::from_value::<CredentialFieldsMap>(
            row.get::<&str, serde_json::Value>("secret_data"),
        )
        .map_or_else(|_| None, |p| Some(p));

        let credential_data = serde_json::from_value::<CredentialFieldsMap>(
            row.get::<&str, serde_json::Value>("credential_data"),
        )
        .map_or_else(|_| None, |p| Some(p));

        CredentialModel {
            credential_type: row.get("credential_type"),
            realm_id: row.get("realm_id"),
            user_id: row.get("user_id"),
            credential_id: row.get("credential_id"),
            user_label: row.get("user_label"),
            credential_data: credential_data,
            secret_data: secret_data,
            priority: row.get("priority"),
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
impl ICredentialProvider for RdsCredentialProvider {
    async fn create_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        credential: CredentialModel,
    ) -> Result<CredentialModel, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_credential_sql = InsertRequestBuilder::new()
            .table_name(credential_table::USERS_CREDENTIALS_TABLE.table_name.clone())
            .columns(
                credential_table::USERS_CREDENTIALS_TABLE
                    .insert_columns
                    .clone(),
            )
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_credential_stmt = client.prepare_cached(&create_credential_sql).await.unwrap();

        let response = client
            .execute(
                &create_credential_stmt,
                &[
                    &credential.metadata.tenant,
                    &credential.credential_id,
                    &realm_id,
                    &user_id,
                    &credential.credential_type,
                    &credential.user_label,
                    &json!(credential.secret_data),
                    &json!(credential.credential_data),
                    &credential.priority,
                    &credential.metadata.created_by,
                    &credential.metadata.created_at,
                    &credential.metadata.version,
                ],
            )
            .await;
        match response {
            Err(err) => {
                let error = err.to_string();
                log::error!("Failed to create credential data: {}", error);
                Err(error)
            }
            Ok(_) => Ok(credential),
        }
    }

    async fn update_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        credential: &CredentialModel,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

        let update_credential_sql = UpdateRequestBuilder::new()
            .table_name(credential_table::USERS_CREDENTIALS_TABLE.table_name.clone())
            .columns(
                credential_table::USERS_CREDENTIALS_TABLE
                    .update_columns
                    .clone(),
            )
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
                SqlCriteriaBuilder::is_equals("credential_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_credential_stmt = client.prepare_cached(&update_credential_sql).await.unwrap();

        let response = client
            .execute(
                &update_credential_stmt,
                &[
                    &credential.credential_type,
                    &credential.user_label,
                    &json!(credential.secret_data),
                    &json!(credential.credential_data),
                    &credential.priority,
                    &credential.metadata.updated_by,
                    &credential.metadata.updated_at,
                    &realm_id,
                    &user_id,
                    &credential.credential_id,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(true)
                } else {
                    Err("Failed to update user credential".to_string())
                }
            }
        }
    }

    async fn remove_stored_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
        priority: i64,
        priority_difference: i64,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_credential_sql = DeleteQueryBuilder::new()
            .table_name(credential_table::USERS_CREDENTIALS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
                SqlCriteriaBuilder::is_equals("credential_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let mut client = client.unwrap();
        let delete_credential_stmt = client.prepare_cached(&delete_credential_sql).await.unwrap();
        let decrement_credential_stmt = client
            .prepare_cached(&credential_table::DECREMENT_CREDENTIAL_PRIORITY)
            .await
            .unwrap();

        let transaction = client.transaction().await;
        match transaction {
            Ok(trx) => {
                trx.execute(
                    &delete_credential_stmt,
                    &[&realm_id, &user_id, &credential_id],
                )
                .await
                .unwrap();

                trx.execute(
                    &decrement_credential_stmt,
                    &[&priority_difference, &realm_id, &user_id, &priority],
                )
                .await
                .unwrap();

                trx.commit().await.unwrap();
                Ok(true)
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_stored_user_credential_by_id(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
    ) -> Result<Option<CredentialModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_credential_sql = SelectRequestBuilder::new()
            .table_name(credential_table::USERS_CREDENTIALS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
                SqlCriteriaBuilder::is_equals("credential_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let result = client
            .query_opt(&load_credential_sql, &[&realm_id, &user_id, &credential_id])
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

    async fn load_stored_credential_by_name_and_type(
        &self,
        realm_id: &str,
        user_id: &str,
        user_label: &str,
        credential_type: &str,
    ) -> Result<Option<CredentialModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_credential_sql = SelectRequestBuilder::new()
            .table_name(credential_table::USERS_CREDENTIALS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_label".to_string()),
                SqlCriteriaBuilder::is_equals("credential_type".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let result = client
            .query_opt(
                &load_credential_sql,
                &[&realm_id, &user_id, &user_label, &credential_type],
            )
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

    async fn reset_password_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        credential: &CredentialModel,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_credential_sql = InsertRequestBuilder::new()
            .table_name(credential_table::USERS_CREDENTIALS_TABLE.table_name.clone())
            .columns(
                credential_table::USERS_CREDENTIALS_TABLE
                    .insert_columns
                    .clone(),
            )
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let mut client = client.unwrap();

        let transaction = client.transaction().await;
        match transaction {
            Ok(trx) => {
                trx.execute(
                    &credential_table::UPDATE_PASSWORD_CREDENTIAL.to_string(),
                    &[
                        &CredentialTypeEnum::PasswordHistory,
                        &realm_id,
                        &user_id,
                        &CredentialTypeEnum::PASSWORD,
                    ],
                )
                .await
                .unwrap();

                trx.execute(
                    &credential_table::INCREMENT_PASSWORD_CREDENTIAL_PRIORITY.to_string(),
                    &[&realm_id, &user_id],
                )
                .await
                .unwrap();

                trx.execute(
                    &create_credential_sql,
                    &[
                        &credential.metadata.tenant,
                        &credential.credential_id,
                        &realm_id,
                        &user_id,
                        &credential.credential_type,
                        &credential.user_label,
                        &json!(credential.secret_data),
                        &json!(credential.credential_data),
                        &credential.priority,
                        &credential.metadata.created_by,
                        &credential.metadata.created_at,
                        &credential.metadata.version,
                    ],
                )
                .await
                .unwrap();

                trx.commit().await.unwrap();
                Ok(true)
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_stored_credentials(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<CredentialModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_credentials_sql = SelectRequestBuilder::new()
            .table_name(credential_table::USERS_CREDENTIALS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let load_credentials_stmt = client.prepare_cached(&load_credentials_sql).await.unwrap();
        let result = client
            .query(&load_credentials_stmt, &[&realm_id, &user_id])
            .await;
        match result {
            Ok(rows) => Ok(rows.iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_stored_credentials_by_type(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_type: &str,
    ) -> Result<Vec<CredentialModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_credentials_sql = SelectRequestBuilder::new()
            .table_name(credential_table::USERS_CREDENTIALS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
                SqlCriteriaBuilder::is_equals("credential_type".to_string()),
            ])
            .sql_query()
            .unwrap();

        let load_credentials_stmt = client.prepare_cached(&load_credentials_sql).await.unwrap();
        let result = client
            .query(
                &load_credentials_stmt,
                &[&realm_id, &user_id, &credential_type],
            )
            .await;
        match result {
            Ok(rows) => Ok(rows.iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_stored_credentials_by_realm_id(
        &self,
        realm_id: &str,
    ) -> Result<Vec<CredentialModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_credentials_sql = SelectRequestBuilder::new()
            .table_name(credential_table::USERS_CREDENTIALS_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let load_credentials_stmt = client.prepare_cached(&load_credentials_sql).await.unwrap();
        let result = client.query(&load_credentials_stmt, &[&realm_id]).await;
        match result {
            Ok(rows) => Ok(rows.iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn update_credential_priorities(
        &self,
        realm_id: &str,
        credential_data: &Vec<(String, i64)>,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_credential_priority_sql = UpdateRequestBuilder::new()
            .table_name(credential_table::USERS_CREDENTIALS_TABLE.table_name.clone())
            .columns(vec!["priority".to_owned()])
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("credential_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let mut client = client.unwrap();
        let update_credential_priority_stmt = client
            .prepare_cached(&update_credential_priority_sql)
            .await
            .unwrap();

        let transaction = client.transaction().await;
        match transaction {
            Ok(trx) => {
                for (credential_id, priority) in credential_data.iter() {
                    trx.execute(
                        &update_credential_priority_stmt,
                        &[&priority, &realm_id, &credential_id],
                    )
                    .await
                    .unwrap();
                }
                trx.commit().await.unwrap();
                Ok(true)
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn update_user_credential_label(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
        user_label: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_user_credential_sql = UpdateRequestBuilder::new()
            .table_name(credential_table::USERS_CREDENTIALS_TABLE.table_name.clone())
            .columns(vec!["user_label".to_owned()])
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
                SqlCriteriaBuilder::is_equals("credential_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_user_credential_stmt = client
            .prepare_cached(&update_user_credential_sql)
            .await
            .unwrap();

        let response = client
            .execute(
                &update_user_credential_stmt,
                &[&user_label, &realm_id, &user_id, &credential_id],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to update user credential label".to_string())
                }
            }
        }
    }
}
