use async_trait::async_trait;
use models::auditable::AuditableModel;
use models::entities::realm::{PasswordPolicy, RealmModel};
use serde_json::{self, json};
use shaku::Component;
use std::collections::HashMap;
use std::sync::Arc;
use tokio_postgres::Row;

use crate::providers::core::builder::SelectCountRequestBuilder;
use crate::providers::rds::client::postgres_client::IDataBaseManager;

use crate::providers::{
    core::builder::{
        DeleteQueryBuilder, InsertRequestBuilder, SelectRequestBuilder, SqlCriteriaBuilder,
        UpdateRequestBuilder,
    },
    interfaces::realm_provider::IRealmProvider,
    rds::tables::realm_table,
};

#[derive(Component)]
#[shaku(interface = IRealmProvider)]
pub struct RdsRealmProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsRealmProvider {
    fn read_record(&self, row: Row) -> RealmModel {
        let password_policy = serde_json::from_value::<PasswordPolicy>(
            row.get::<&str, serde_json::Value>("password_policy"),
        )
        .map_or_else(|_| None, |p| Some(p));

        let attributes = serde_json::from_value::<HashMap<String, Option<String>>>(
            row.get::<&str, serde_json::Value>("attributes"),
        )
        .map_or_else(|_| None, |p| Some(p));

        RealmModel {
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            display_name: row.get("display_name"),
            enabled: row.get("enabled"),
            registration_allowed: row.get("registration_allowed"),
            register_email_as_username: row.get("register_email_as_username"),
            verify_email: row.get("verify_email"),
            reset_password_allowed: row.get("reset_password_allowed"),
            revoke_refresh_token: row.get("revoke_refresh_token"),
            login_with_email_allowed: row.get("login_with_email_allowed"),
            duplicated_email_allowed: row.get("duplicated_email_allowed"),
            ssl_enforcement: row.get("ssl_enforcement"),
            password_policy: password_policy,
            edit_user_name_allowed: row.get("edit_user_name_allowed"),
            refresh_token_max_reuse: row.get("refresh_token_max_reuse"),
            access_token_lifespan: row.get("access_token_lifespan"),
            access_code_lifespan: row.get("access_code_lifespan"),
            access_code_lifespan_login: row.get("access_code_lifespan_login"),
            access_code_lifespan_user_action: row.get("access_code_lifespan_user_action"),
            action_tokens_lifespan: row.get("action_tokens_lifespan"),
            master_admin_client: row.get("master_admin_client"),
            not_before: row.get("not_before"),
            remember_me: row.get("remember_me"),
            events_enabled: row.get("events_enabled"),
            admin_events_enabled: row.get("admin_events_enabled"),
            attributes: attributes,
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
impl IRealmProvider for RdsRealmProvider {
    async fn create_realm(&self, realm: &RealmModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

        let create_realm_sql = InsertRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .columns(realm_table::REALM_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_realm_stmt = client.prepare_cached(&create_realm_sql).await.unwrap();
        let metadata = realm.metadata.as_ref().unwrap();

        client
            .execute(
                &create_realm_stmt,
                &[
                    &metadata.tenant,
                    &realm.realm_id,
                    &realm.name,
                    &realm.display_name,
                    &realm.enabled,
                    &metadata.created_by,
                    &metadata.created_at,
                    &metadata.version,
                ],
            )
            .await
            .unwrap();
        Ok(())
    }

    async fn update_realm(&self, realm: &RealmModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

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

        let client = client.unwrap();
        let update_realm_stmt = client.prepare_cached(&create_realm_sql).await.unwrap();
        let metadata = realm.metadata.as_ref().unwrap();

        client
            .execute(
                &update_realm_stmt,
                &[
                    &realm.name,
                    &realm.display_name,
                    &realm.enabled,
                    &realm.registration_allowed,
                    &realm.verify_email,
                    &realm.reset_password_allowed,
                    &realm.login_with_email_allowed,
                    &realm.duplicated_email_allowed,
                    &realm.register_email_as_username,
                    &realm.ssl_enforcement,
                    &json!(&realm.password_policy),
                    &realm.edit_user_name_allowed,
                    &realm.revoke_refresh_token,
                    &realm.refresh_token_max_reuse,
                    &realm.access_token_lifespan,
                    &realm.access_code_lifespan,
                    &realm.access_code_lifespan_login,
                    &realm.access_code_lifespan_user_action,
                    &realm.action_tokens_lifespan,
                    &realm.not_before,
                    &realm.remember_me,
                    &realm.master_admin_client,
                    &realm.events_enabled,
                    &realm.admin_events_enabled,
                    &json!(&realm.attributes),
                    &metadata.updated_by,
                    &metadata.updated_at,
                    &metadata.tenant,
                    &realm.realm_id,
                ],
            )
            .await
            .unwrap();
        Ok(())
    }

    async fn delete_realm(&self, realm_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_realm_sql = DeleteQueryBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let delete_realm_stmt = client.prepare_cached(&delete_realm_sql).await.unwrap();
        let result = client.execute(&delete_realm_stmt, &[&realm_id]).await;
        match result {
            Err(error) => Err(error.to_string()),
            _ => Ok(()),
        }
    }

    async fn load_realm(&self, realm_id: &str) -> Result<Option<RealmModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let result = client.query_opt(&load_realm_sql, &[&realm_id]).await;
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

    async fn load_realms(&self) -> Result<Vec<RealmModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client.query(&load_realm_stmt, &[]).await;
        match result {
            Ok(rows) => Ok(rows.into_iter().map(|row| self.read_record(row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_realm_by_name(&self, name: &str) -> Result<Option<RealmModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("name".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client.query_opt(&load_realm_stmt, &[&name]).await;
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

    async fn load_realm_by_display_name(
        &self,
        display_name: &str,
    ) -> Result<Option<RealmModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals(
                "display_name".to_string(),
            )])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client.query_opt(&load_realm_stmt, &[&display_name]).await;
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

    async fn realm_exists_by_id(&self, realm_id: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_realm_sql = SelectCountRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_realm_stmt = client.prepare_cached(&load_realm_sql).await.unwrap();
        let result = client.query_one(&load_realm_stmt, &[&realm_id]).await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn realm_exists_by_criteria(
        &self,
        realm_id: &str,
        name: &str,
        display_name: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let exists_realm_stmt = client
            .prepare_cached(&realm_table::REALM_TABLE_EXISTS_BY_CRITERIA_QUERY)
            .await
            .unwrap();
        let result = client
            .query_one(&exists_realm_stmt, &[&realm_id, &name, &display_name])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn realm_exists_by_tenant_and_name(
        &self,
        tenant: &str,
        name: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let exists_realm_sql = SelectRequestBuilder::new()
            .table_name(realm_table::REALM_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
            ])
            .sql_query()
            .unwrap();
        let exists_realm_stmt = client.prepare_cached(&exists_realm_sql).await.unwrap();

        let result = client
            .query_one(&exists_realm_stmt, &[&tenant, &name])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}
