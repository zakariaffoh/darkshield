use crate::providers::{
    core::builder::*,
    interfaces::session_providers::{
        IAuthenticationSessionProvider, IRootAuthenticationSessionProvider, IUserSessionProvider,
    },
    rds::{client::postgres_client::IDataBaseManager, tables::sessions_table},
};

use async_trait::async_trait;
use models::{
    authentication::{
        auth_tokens::SingleUseToken,
        sessions::{
            AuthExecutionStatusEnum, AuthenticationSessionModel, ClientSessionModel,
            RootAuthenticationSession, RootAuthenticationSessionModel, UserSession,
            UserSessionModel,
        },
    },
    entities::auth::RequiredActionEnum,
};
use serde_json::json;
use shaku::Component;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio_postgres::Row;

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRootAuthenticationSessionProvider)]
pub struct RdsRootAuthenticationSessionProvider {
    #[shaku(inject)]
    database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsRootAuthenticationSessionProvider {
    pub fn read_record(&self, row: &Row) -> RootAuthenticationSessionModel {
        RootAuthenticationSessionModel {
            tenant: row.get("tenant"),
            session_id: row.get("session_id"),
            realm_id: row.get("realm_id"),
            timestamp: row.get("timestamp"),
        }
    }
}

#[async_trait]
impl IRootAuthenticationSessionProvider for RdsRootAuthenticationSessionProvider {
    async fn create_root_authentication_session(
        &self,
        root_session: &RootAuthenticationSession,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_root_authentication_session_sql = InsertRequestBuilder::new()
            .table_name(sessions_table::ROOT_AUTH_SESSIONS_TABLE.table_name.clone())
            .columns(
                sessions_table::ROOT_AUTH_SESSIONS_TABLE
                    .insert_columns
                    .clone(),
            )
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_root_authentication_session_stmt = client
            .prepare_cached(&create_root_authentication_session_sql)
            .await
            .unwrap();
        let response = client
            .execute(
                &create_root_authentication_session_stmt,
                &[
                    &root_session.session_model().tenant,
                    &root_session.session_model().realm_id,
                    &root_session.session_model().session_id,
                    &root_session.session_model().timestamp,
                ],
            )
            .await;
        match response {
            Err(err) => {
                log::error!(
                    "Failed to create root authentication session. Error: {}",
                    err
                );
                Err(err.to_string())
            }
            _ => Ok(()),
        }
    }

    async fn update_root_authentication_session(
        &self,
        root_session: &RootAuthenticationSession,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_root_authentication_session_sql = UpdateRequestBuilder::new()
            .table_name(sessions_table::ROOT_AUTH_SESSIONS_TABLE.table_name.clone())
            .columns(
                sessions_table::ROOT_AUTH_SESSIONS_TABLE
                    .update_columns
                    .clone(),
            )
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_root_authentication_session_stmt = client
            .prepare_cached(&update_root_authentication_session_sql)
            .await
            .unwrap();

        let response = client
            .execute(
                &update_root_authentication_session_stmt,
                &[
                    &root_session.session_model().timestamp,
                    &root_session.session_model().tenant,
                    &root_session.session_model().realm_id,
                    &root_session.session_model().session_id,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to update root authentication session".to_string())
                }
            }
        }
    }

    async fn load_root_authentication_session(
        &self,
        realm_id: &str,
        auth_session_id: &str,
    ) -> Result<Option<RootAuthenticationSessionModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_root_authentication_session_sql = SelectRequestBuilder::new()
            .table_name(sessions_table::ROOT_AUTH_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_root_authentication_session_stmt = client
            .prepare_cached(&load_root_authentication_session_sql)
            .await
            .unwrap();
        let result = client
            .query_opt(
                &load_root_authentication_session_stmt,
                &[&realm_id, &auth_session_id],
            )
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

    async fn remove_realm_authentication_sessions(&self, realm_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_root_authentication_sessions_sql = DeleteQueryBuilder::new()
            .table_name(sessions_table::ROOT_AUTH_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let remove_authentication_sessions_sql = DeleteQueryBuilder::new()
            .table_name(sessions_table::AUTH_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        /* Run in transaction */
        let mut client = client.unwrap();
        let transaction = client.transaction().await;
        match transaction {
            Ok(trx) => {
                trx.execute(&remove_root_authentication_sessions_sql, &[&realm_id])
                    .await
                    .unwrap();

                trx.execute(&remove_authentication_sessions_sql, &[&realm_id])
                    .await
                    .unwrap();
                trx.commit().await.unwrap();
                Ok(())
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn remove_root_authentication_session(
        &self,
        realm_id: &str,
        root_session_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_root_authentication_session_sql = DeleteQueryBuilder::new()
            .table_name(sessions_table::ROOT_AUTH_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_root_authentication_session_stmt = client
            .prepare_cached(&remove_root_authentication_session_sql)
            .await
            .unwrap();
        let result = client
            .execute(
                &remove_root_authentication_session_stmt,
                &[&realm_id, &root_session_id],
            )
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove root authentication session".to_string())
                }
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IAuthenticationSessionProvider)]
pub struct RdsAuthenticationSessionProvider {
    #[shaku(inject)]
    database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsAuthenticationSessionProvider {
    pub fn read_record(&self, row: &Row) -> AuthenticationSessionModel {
        let read_set = |r: &Row, column: &str| {
            let record = serde_json::from_value::<HashSet<String>>(
                row.get::<&str, serde_json::Value>(column),
            )
            .map_or_else(|_| None, |p| Some(p));
            record
        };

        let read_required_action = serde_json::from_value::<HashSet<RequiredActionEnum>>(
            row.get::<&str, serde_json::Value>("required_actions"),
        )
        .map_or_else(|_| None, |p| Some(p));

        let read_map = |r: &Row, column: &str| {
            let record = serde_json::from_value::<HashMap<String, String>>(
                row.get::<&str, serde_json::Value>(column),
            )
            .map_or_else(|_| None, |p| Some(p));
            record
        };

        let execution_status = serde_json::from_value::<HashMap<String, AuthExecutionStatusEnum>>(
            row.get::<&str, serde_json::Value>("execution_status"),
        )
        .map_or_else(|_| None, |p| Some(p));

        AuthenticationSessionModel {
            tenant: row.get("tenant"),
            tab_id: row.get("tab_id"),
            auth_user_id: row.get("auth_user_id"),
            realm_id: row.get("realm_id"),
            root_session_id: row.get("root_session_id"),
            client_id: row.get("client_id"),
            redirect_uri: row.get("redirect_uri"),
            client_scopes: read_set(row, "client_scopes"),
            timestamp: row.get("timestamp"),
            action: row.get("action"),
            protocol: row.get("protocol"),
            execution_status: execution_status,
            client_notes: read_map(row, "client_notes"),
            auth_notes: read_map(row, "auth_notes"),
            required_actions: read_required_action,
            user_session_notes: read_map(row, "user_session_notes"),
        }
    }
}

#[async_trait]
impl IAuthenticationSessionProvider for RdsAuthenticationSessionProvider {
    async fn create_authentication_session(
        &self,
        session_model: &AuthenticationSessionModel,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_authentication_session_sql = InsertRequestBuilder::new()
            .table_name(sessions_table::AUTH_SESSIONS_TABLE.table_name.clone())
            .columns(sessions_table::AUTH_SESSIONS_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_authentication_session_stmt = client
            .prepare_cached(&create_authentication_session_sql)
            .await
            .unwrap();
        let response = client
            .execute(
                &create_authentication_session_stmt,
                &[
                    &session_model.tenant,
                    &session_model.realm_id,
                    &session_model.tab_id,
                    &session_model.auth_user_id,
                    &session_model.root_session_id,
                    &session_model.client_id,
                    &session_model.redirect_uri,
                    &json!(session_model.client_scopes),
                    &session_model.timestamp,
                    &session_model.action,
                    &session_model.protocol,
                    &json!(session_model.execution_status),
                    &json!(session_model.client_notes),
                    &json!(session_model.auth_notes),
                    &json!(session_model.required_actions),
                    &json!(session_model.user_session_notes),
                ],
            )
            .await;
        match response {
            Err(err) => {
                log::error!("Failed to create authentication session. Error: {}", err);
                Err(err.to_string())
            }
            _ => Ok(()),
        }
    }

    async fn update_authentication_session(
        &self,
        session_model: &AuthenticationSessionModel,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_authentication_session_sql = UpdateRequestBuilder::new()
            .table_name(sessions_table::AUTH_SESSIONS_TABLE.table_name.clone())
            .columns(sessions_table::AUTH_SESSIONS_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("root_session_id".to_string()),
                SqlCriteriaBuilder::is_equals("tab_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_authentication_session_stmt = client
            .prepare_cached(&update_authentication_session_sql)
            .await
            .unwrap();

        let response = client
            .execute(
                &update_authentication_session_stmt,
                &[
                    &session_model.auth_user_id,
                    &session_model.redirect_uri,
                    &json!(session_model.client_scopes),
                    &session_model.timestamp,
                    &session_model.action,
                    &session_model.protocol,
                    &json!(session_model.execution_status),
                    &json!(session_model.client_notes),
                    &json!(session_model.auth_notes),
                    &json!(session_model.required_actions),
                    &json!(session_model.user_session_notes),
                    &session_model.tenant,
                    &session_model.realm_id,
                    &session_model.root_session_id,
                    &session_model.tab_id,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to update authentication session".to_string())
                }
            }
        }
    }

    async fn remove_authentication_session(
        &self,
        realm_id: &str,
        client_id: &str,
        tab_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_authentication_session_sql = DeleteQueryBuilder::new()
            .table_name(sessions_table::AUTH_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_id".to_string()),
                SqlCriteriaBuilder::is_equals("tab_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_authentication_session_stmt = client
            .prepare_cached(&remove_authentication_session_sql)
            .await
            .unwrap();
        let result = client
            .execute(
                &remove_authentication_session_stmt,
                &[&realm_id, &client_id, &tab_id],
            )
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to remove authentication session".to_string())
                }
            }
        }
    }

    async fn load_authentication_sessions(
        &self,
        realm_id: &str,
        auth_session_id: &str,
    ) -> Result<Vec<AuthenticationSessionModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_authentication_sessions_sql = SelectRequestBuilder::new()
            .table_name(sessions_table::AUTH_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("root_session_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_authentication_sessions_stmt = client
            .prepare_cached(&load_authentication_sessions_sql)
            .await
            .unwrap();
        let result = client
            .query(&load_authentication_sessions_stmt, &[&realm_id])
            .await;
        match result {
            Ok(rows) => Ok(rows.into_iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IUserSessionProvider)]
pub struct RdsUserSessionProvider {
    #[shaku(inject)]
    database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsUserSessionProvider {
    pub fn read_record(&self, row: &Row) -> UserSessionModel {
        let read_map = |r: &Row, column: &str| {
            let record = serde_json::from_value::<HashMap<String, String>>(
                r.get::<&str, serde_json::Value>(column),
            )
            .map_or_else(|_| None, |p| Some(p));
            record
        };

        UserSessionModel {
            tenant: row.get("tenant"),
            session_id: row.get("session_id"),
            realm_id: row.get("realm_id"),
            user_id: row.get("user_id"),
            login_username: row.get("login_username"),
            broker_session_id: row.get("broker_session_id"),
            broker_user_id: row.get("broker_user_id"),
            auth_method: row.get("auth_method"),
            ip_address: row.get("ip_address"),
            started_at: row.get("started_at"),
            expiration: row.get("expiration"),
            state: row.get("state"),
            remember_me: row.get("remember_me"),
            last_session_refresh: row.get("last_session_refresh"),
            is_offline: row.get("is_offline"),
            notes: read_map(row, "notes"),
        }
    }

    pub fn read_client_record(&self, row: &Row) -> ClientSessionModel {
        let read_map = |r: &Row, column: &str| {
            let record = serde_json::from_value::<HashMap<String, String>>(
                r.get::<&str, serde_json::Value>(column),
            )
            .map_or_else(|_| None, |p| Some(p));
            record
        };
        ClientSessionModel {
            tenant: row.get("tenant"),
            session_id: row.get("session_id"),
            realm_id: row.get("realm_id"),
            user_id: row.get("user_id"),
            user_session_id: row.get("user_session_id"),
            client_id: row.get("client_id"),
            auth_method: row.get("auth_method"),
            redirect_uri: row.get("redirect_uri"),
            action: row.get("action"),
            started_at: row.get("started_at"),
            expiration: row.get("expiration"),
            notes: read_map(row, "notes"),
            current_refresh_token: row.get("refresh_token"),
            current_refresh_token_use_count: row.get("refresh_token_use_count"),
            offline: row.get("offline"),
        }
    }
}

#[async_trait]
impl IUserSessionProvider for RdsUserSessionProvider {
    async fn create_user_session(&self, user_session: &UserSessionModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_user_session_sql = InsertRequestBuilder::new()
            .table_name(sessions_table::USER_SESSIONS_TABLE.table_name.clone())
            .columns(sessions_table::USER_SESSIONS_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_user_session_stmt = client
            .prepare_cached(&create_user_session_sql)
            .await
            .unwrap();
        let response = client
            .execute(
                &create_user_session_stmt,
                &[
                    &user_session.tenant,
                    &user_session.realm_id,
                    &user_session.session_id,
                    &user_session.user_id,
                    &user_session.login_username,
                    &user_session.broker_session_id,
                    &user_session.auth_method,
                    &user_session.ip_address,
                    &user_session.started_at,
                    &user_session.expiration,
                    &user_session.remember_me,
                    &user_session.last_session_refresh,
                    &user_session.is_offline,
                    &json!(user_session.notes),
                    &user_session.state,
                ],
            )
            .await;

        match response {
            Err(err) => {
                log::error!("Failed to create user session. Error: {}", err);
                Err(err.to_string())
            }
            _ => Ok(()),
        }
    }

    async fn create_client_session(
        &self,
        client_session: &ClientSessionModel,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_client_session_sql = InsertRequestBuilder::new()
            .table_name(sessions_table::CLIENT_SESSIONS_TABLE.table_name.clone())
            .columns(sessions_table::CLIENT_SESSIONS_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_client_session_stmt = client
            .prepare_cached(&create_client_session_sql)
            .await
            .unwrap();
        let response = client
            .execute(
                &create_client_session_stmt,
                &[
                    &client_session.tenant,
                    &client_session.realm_id,
                    &client_session.session_id,
                    &client_session.user_id,
                    &client_session.user_session_id,
                    &client_session.client_id,
                    &client_session.auth_method,
                    &client_session.redirect_uri,
                    &client_session.action,
                    &client_session.started_at,
                    &client_session.expiration,
                    &json!(client_session.notes),
                    &client_session.current_refresh_token,
                    &client_session.current_refresh_token_use_count,
                    &client_session.offline,
                ],
            )
            .await;

        match response {
            Err(err) => {
                log::error!("Failed to create client session. Error: {}", err);
                Err(err.to_string())
            }
            _ => Ok(()),
        }
    }

    async fn attach_client_session(
        &self,
        user_session: &UserSessionModel,
        client_session: &ClientSessionModel,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_client_session_sql = InsertRequestBuilder::new()
            .table_name(sessions_table::CLIENT_SESSIONS_TABLE.table_name.clone())
            .columns(sessions_table::CLIENT_SESSIONS_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let update_user_session_sql = UpdateRequestBuilder::new()
            .table_name(sessions_table::USER_SESSIONS_TABLE.table_name.clone())
            .columns(sessions_table::USER_SESSIONS_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let mut client = client.unwrap();
        let transaction = client.transaction().await;
        match transaction {
            Ok(trx) => {
                trx.execute(
                    &create_client_session_sql,
                    &[
                        &client_session.tenant,
                        &client_session.realm_id,
                        &client_session.session_id,
                        &client_session.user_id,
                        &client_session.user_session_id,
                        &client_session.client_id,
                        &client_session.auth_method,
                        &client_session.redirect_uri,
                        &client_session.action,
                        &client_session.started_at,
                        &client_session.expiration,
                        &json!(client_session.notes),
                        &client_session.current_refresh_token,
                        &client_session.current_refresh_token_use_count,
                        &client_session.offline,
                    ],
                )
                .await
                .unwrap();

                trx.execute(
                    &update_user_session_sql,
                    &[
                        &user_session.auth_method,
                        &user_session.ip_address,
                        &user_session.started_at,
                        &user_session.remember_me,
                        &user_session.last_session_refresh,
                        &user_session.is_offline,
                        &json!(user_session.notes),
                        &user_session.state,
                        &user_session.tenant,
                        &user_session.realm_id,
                        &user_session.session_id,
                    ],
                )
                .await
                .unwrap();
                trx.commit().await.unwrap();
                Ok(())
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn update_user_session(&self, user_session: &UserSessionModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

        let update_user_session_sql = UpdateRequestBuilder::new()
            .table_name(sessions_table::USER_SESSIONS_TABLE.table_name.clone())
            .columns(sessions_table::USER_SESSIONS_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_user_session_stmt = client
            .prepare_cached(&update_user_session_sql)
            .await
            .unwrap();

        let response = client
            .execute(
                &update_user_session_stmt,
                &[
                    &user_session.auth_method,
                    &user_session.ip_address,
                    &user_session.started_at,
                    &user_session.remember_me,
                    &user_session.last_session_refresh,
                    &user_session.is_offline,
                    &json!(user_session.notes),
                    &user_session.state,
                    &user_session.tenant,
                    &user_session.realm_id,
                    &user_session.session_id,
                ],
            )
            .await;
        match response {
            Err(err) => Err(err.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to update user session".to_string())
                }
            }
        }
    }

    async fn restart_user_session(&self, user_session: &UserSessionModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let delete_client_session_sql = DeleteQueryBuilder::new()
            .table_name(sessions_table::CLIENT_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_session_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let update_authentication_session_sql = UpdateRequestBuilder::new()
            .table_name(sessions_table::USER_SESSIONS_TABLE.table_name.clone())
            .columns(sessions_table::USER_SESSIONS_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("tenant".to_string()),
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let mut client = client.unwrap();
        let transaction = client.transaction().await;
        match transaction {
            Ok(trx) => {
                trx.execute(
                    &delete_client_session_sql,
                    &[&user_session.realm_id, &user_session.session_id],
                )
                .await
                .unwrap();

                trx.execute(
                    &update_authentication_session_sql,
                    &[
                        &user_session.auth_method,
                        &user_session.ip_address,
                        &user_session.started_at,
                        &user_session.remember_me,
                        &user_session.last_session_refresh,
                        &user_session.is_offline,
                        &json!(user_session.notes),
                        &user_session.state,
                        &user_session.tenant,
                        &user_session.realm_id,
                        &user_session.session_id,
                    ],
                )
                .await
                .unwrap();
                trx.commit().await.unwrap();
                Ok(())
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn full_update_user_session(
        &self,
        user_session: &UserSessionModel,
        client_sessions: &Vec<ClientSessionModel>,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

        let update_user_session_sql = UpdateRequestBuilder::new()
            .table_name(sessions_table::USER_SESSIONS_TABLE.table_name.clone())
            .columns(sessions_table::USER_SESSIONS_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let update_client_session_sql = UpdateRequestBuilder::new()
            .table_name(sessions_table::CLIENT_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let mut client = client.unwrap();
        let transaction = client.transaction().await;
        match transaction {
            Ok(trx) => {
                trx.execute(
                    &update_user_session_sql,
                    &[
                        &user_session.auth_method,
                        &user_session.ip_address,
                        &user_session.started_at,
                        &user_session.remember_me,
                        &user_session.last_session_refresh,
                        &user_session.is_offline,
                        &json!(user_session.notes),
                        &user_session.state,
                        &user_session.tenant,
                        &user_session.realm_id,
                        &user_session.session_id,
                    ],
                )
                .await
                .unwrap();
                for client_session in client_sessions.iter() {
                    trx.execute(
                        &update_client_session_sql,
                        &[
                            &client_session.auth_method,
                            &client_session.redirect_uri,
                            &client_session.action,
                            &client_session.started_at,
                            &client_session.expiration,
                            &json!(&client_session.notes),
                            &client_session.current_refresh_token,
                            &client_session.current_refresh_token_use_count,
                            &client_session.offline,
                            &client_session.realm_id,
                            &client_session.session_id,
                            &client_session.user_id,
                        ],
                    )
                    .await
                    .unwrap();
                }

                trx.commit().await.unwrap();
                Ok(())
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn full_update_client_session(
        &self,
        user_session: &UserSessionModel,
        client_session: &ClientSessionModel,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

        let update_user_session_sql = UpdateRequestBuilder::new()
            .table_name(sessions_table::USER_SESSIONS_TABLE.table_name.clone())
            .columns(sessions_table::USER_SESSIONS_TABLE.update_columns.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let update_client_session_sql = UpdateRequestBuilder::new()
            .table_name(sessions_table::CLIENT_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let mut client = client.unwrap();
        let transaction = client.transaction().await;
        match transaction {
            Ok(trx) => {
                trx.execute(
                    &update_user_session_sql,
                    &[
                        &user_session.auth_method,
                        &user_session.ip_address,
                        &user_session.started_at,
                        &user_session.remember_me,
                        &user_session.last_session_refresh,
                        &user_session.is_offline,
                        &json!(user_session.notes),
                        &user_session.state,
                        &user_session.tenant,
                        &user_session.realm_id,
                        &user_session.session_id,
                    ],
                )
                .await
                .unwrap();

                trx.execute(
                    &update_client_session_sql,
                    &[
                        &client_session.auth_method,
                        &client_session.redirect_uri,
                        &client_session.action,
                        &client_session.started_at,
                        &client_session.expiration,
                        &json!(&client_session.notes),
                        &client_session.current_refresh_token,
                        &client_session.current_refresh_token_use_count,
                        &client_session.offline,
                        &client_session.realm_id,
                        &client_session.session_id,
                        &client_session.user_id,
                    ],
                )
                .await
                .unwrap();

                trx.commit().await.unwrap();
                Ok(())
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn update_client_session(
        &self,
        client_session: &ClientSessionModel,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

        let update_client_session_sql = UpdateRequestBuilder::new()
            .table_name(sessions_table::CLIENT_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .manage_version(true)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let update_client_session_stmt = client
            .prepare_cached(&update_client_session_sql)
            .await
            .unwrap();
        let response = client
            .execute(
                &update_client_session_stmt,
                &[
                    &client_session.auth_method,
                    &client_session.redirect_uri,
                    &client_session.action,
                    &client_session.started_at,
                    &client_session.expiration,
                    &json!(&client_session.notes),
                    &client_session.current_refresh_token,
                    &client_session.current_refresh_token_use_count,
                    &client_session.offline,
                    &client_session.realm_id,
                    &client_session.session_id,
                    &client_session.user_id,
                ],
            )
            .await;

        match response {
            Err(err) => {
                log::error!("Failed to update client session. Error: {}", err);
                Err(err.to_string())
            }
            _ => Ok(()),
        }
    }

    async fn count_active_users_sessions(
        &self,
        realm_id: &str,
        client_id: &str,
        offline: bool,
    ) -> Result<i64, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_user_sessions_stmt = client
            .prepare_cached(&sessions_table::COUNT_USER_SESSION_QUERY)
            .await
            .unwrap();
        let result = client
            .query_one(&load_user_sessions_stmt, &[&realm_id, &client_id, &offline])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0)),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn clear_client_sessions(self, realm_id: &str, client_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_client_sessions_sql = DeleteQueryBuilder::new()
            .table_name(sessions_table::CLIENT_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("client_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_client_sessions_stmt = client
            .prepare_cached(&remove_client_sessions_sql)
            .await
            .unwrap();
        let result = client
            .execute(&remove_client_sessions_stmt, &[&realm_id, &client_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to clear client sessions".to_string())
                }
            }
        }
    }

    async fn load_user_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        offline: bool,
    ) -> Result<Option<UserSessionModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_user_sessions_sql = SelectRequestBuilder::new()
            .table_name(sessions_table::AUTH_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
                SqlCriteriaBuilder::is_equals("offline".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_user_sessions_stmt = client
            .prepare_cached(&load_user_sessions_sql)
            .await
            .unwrap();
        let result = client
            .query_opt(
                &load_user_sessions_stmt,
                &[&realm_id, &user_session_id, &offline],
            )
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

    async fn load_user_session_entities(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<UserSessionModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_user_sessions_sql = SelectRequestBuilder::new()
            .table_name(sessions_table::AUTH_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_user_sessions_stmt = client
            .prepare_cached(&load_user_sessions_sql)
            .await
            .unwrap();
        let result = client.query(&load_user_sessions_stmt, &[&realm_id]).await;
        match result {
            Ok(rows) => Ok(rows.into_iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_user_sessions_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<UserSessionModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let load_user_sessions_stmt = client
            .prepare_cached(&sessions_table::SELECT_USER_SESSIONS_QUERY)
            .await
            .unwrap();
        let result = client.query(&load_user_sessions_stmt, &[&realm_id]).await;
        match result {
            Ok(rows) => Ok(rows.into_iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn load_user_sessions_stream(
        &self,
        realm_id: &str,
        user_id: &str,
        offline: bool,
    ) -> Result<Vec<UserSessionModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_user_sessions_stream_sql = SelectRequestBuilder::new()
            .table_name(sessions_table::AUTH_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
                SqlCriteriaBuilder::is_equals("offline".to_string()),
            ])
            .sql_query()
            .unwrap();
        let client = client.unwrap();
        let load_user_sessions_stream_stmt = client
            .prepare_cached(&load_user_sessions_stream_sql)
            .await
            .unwrap();
        let result = client
            .query(
                &load_user_sessions_stream_stmt,
                &[&realm_id, &user_id, &offline],
            )
            .await;
        match result {
            Ok(rows) => Ok(rows.into_iter().map(|row| self.read_record(&row)).collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn delete_user_session_by_realm_id(
        &self,
        realm_id: &str,
        offline: &Option<bool>,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let client = client.unwrap();
        let result_records;
        match offline {
            Some(off) => {
                let remove_user_session_sql = DeleteQueryBuilder::new()
                    .table_name(sessions_table::USER_SESSIONS_TABLE.table_name.clone())
                    .where_clauses(vec![
                        SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                        SqlCriteriaBuilder::is_equals("offline".to_string()),
                    ])
                    .sql_query()
                    .unwrap();
                let remove_user_session_stmt = client
                    .prepare_cached(&remove_user_session_sql)
                    .await
                    .unwrap();
                result_records = client
                    .execute(&remove_user_session_stmt, &[&realm_id, off])
                    .await;
            }
            None => {
                let remove_user_session_sql = DeleteQueryBuilder::new()
                    .table_name(sessions_table::USER_SESSIONS_TABLE.table_name.clone())
                    .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
                    .sql_query()
                    .unwrap();
                let remove_user_session_stmt = client
                    .prepare_cached(&remove_user_session_sql)
                    .await
                    .unwrap();
                result_records = client
                    .execute(&remove_user_session_stmt, &[&realm_id])
                    .await;
            }
        }
        match result_records {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to delete user session".to_string())
                }
            }
        }
    }

    async fn delete_user_session(&self, realm_id: &str, session_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_user_session_sql = DeleteQueryBuilder::new()
            .table_name(sessions_table::USER_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_user_session_stmt = client
            .prepare_cached(&remove_user_session_sql)
            .await
            .unwrap();
        let result = client
            .execute(&remove_user_session_stmt, &[&realm_id, &session_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to delete user session".to_string())
                }
            }
        }
    }

    async fn delete_user_session_by_user_id(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_user_session_sql = DeleteQueryBuilder::new()
            .table_name(sessions_table::USER_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("user_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_user_session_stmt = client
            .prepare_cached(&remove_user_session_sql)
            .await
            .unwrap();
        let result = client
            .execute(&remove_user_session_stmt, &[&realm_id, &user_id])
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to delete user session".to_string())
                }
            }
        }
    }

    async fn delete_client_session(&self, realm_id: &str, session_id: &str) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_delete_client_session_sql = DeleteQueryBuilder::new()
            .table_name(sessions_table::CLIENT_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let remove_delete_client_session_stmt = client
            .prepare_cached(&remove_delete_client_session_sql)
            .await
            .unwrap();
        let result = client
            .execute(
                &remove_delete_client_session_stmt,
                &[&realm_id, &session_id],
            )
            .await;
        match result {
            Err(error) => Err(error.to_string()),
            Ok(response) => {
                if response == 1 {
                    Ok(())
                } else {
                    Err("Failed to delete user session".to_string())
                }
            }
        }
    }

    async fn load_client_sessions(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> Result<Vec<ClientSessionModel>, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }

        let load_client_sessions_sql = SelectRequestBuilder::new()
            .table_name(sessions_table::AUTH_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
            ])
            .sql_query()
            .unwrap();
        let client = client.unwrap();
        let load_client_sessions_stmt = client
            .prepare_cached(&load_client_sessions_sql)
            .await
            .unwrap();
        let result = client
            .query(&load_client_sessions_stmt, &[&realm_id, &session_id])
            .await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_client_record(&row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn user_session_exists(&self, realm_id: &str, session_id: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_user_session_sql = SelectCountRequestBuilder::new()
            .table_name(sessions_table::USER_SESSIONS_TABLE.table_name.clone())
            .where_clauses(vec![
                SqlCriteriaBuilder::is_equals("realm_id".to_string()),
                SqlCriteriaBuilder::is_equals("session_id".to_string()),
            ])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_user_session_stmt = client.prepare_cached(&load_user_session_sql).await.unwrap();
        let result = client
            .query_one(&load_user_session_stmt, &[&realm_id, &session_id])
            .await;
        match result {
            Ok(row) => Ok(row.get::<usize, i64>(0) > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}
