use std::sync::Arc;

use async_trait::async_trait;
use models::{auditable::AuditableModel, entities::authz::*};
use shaku::Component;
use tokio_postgres::Row;

use crate::providers::{
    core::builder::*,
    interfaces::authz_provider::*,
    rds::{client::postgres_client::IDataBaseManager, tables::authz_tables},
};

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRoleProvider)]
pub struct RdsRoleProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

impl RdsRoleProvider {
    pub fn read_role_record(&self, row: Row) -> RoleModel {
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
                SqlCriteriaBuilder::is_equals("role_id".to_string()),
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
                    &role_model.realm_id,
                    &role_model.role_id,
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
        let result = client.query(&load_roles_stmt, &[&realm_id]).await;
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

    async fn count_roles(&self, realm_id: &str) -> Result<u32, String> {
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
            Ok(row) => Ok(row.get::<usize, u32>(0) as u32),
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
    fn read_group_record(&self, row: Row) -> GroupModel {
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
        let metadata = group_model.metadata.as_ref().unwrap();

        let response = client
            .execute(
                &create_group_stmt,
                &[
                    &metadata.tenant,
                    &group_model.group_id,
                    &group_model.realm_id,
                    &group_model.name,
                    &group_model.description,
                    &group_model.display_name,
                    &group_model.is_default,
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
        let metadata = group_model.metadata.as_ref().unwrap();

        let response = client
            .execute(
                &update_group_stmt,
                &[
                    &group_model.name,
                    &group_model.description,
                    &group_model.display_name,
                    &group_model.is_default,
                    &metadata.updated_at,
                    &metadata.updated_by,
                    &group_model.realm_id,
                    &group_model.group_id,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
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
            Ok(_) => Ok(()),
            Err(error) => Err(error.to_string()),
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
                    Ok(Some(self.read_group_record(r)))
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
                    Ok(Some(self.read_group_record(r)))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }

    async fn count_groups(&self, realm_id: &str) -> Result<u32, String> {
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
            Ok(row) => Ok(row.get::<usize, u32>(0) as u32),
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
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_group_record(row))
                .collect()),
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
    fn read_idp_record(&self, row: Row) -> IdentityProviderModel {
        IdentityProviderModel {
            internal_id: row.get("internal_id"),
            provider_id: row.get("provider_id"),
            realm_id: row.get("realm_id"),
            name: row.get("name"),
            description: row.get("description"),
            display_name: row.get("display_name"),
            trust_email: row.get("trust_email"),
            enabled: row.get("enabled"),
            configs: row.get("configs"),
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
impl IIdentityProvider for RdsIdentityProvider {
    async fn create_identity_provider(&self, idp: &IdentityProviderModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let create_idp_sql = InsertRequestBuilder::new()
            .table_name(authz_tables::IDENTITY_PROVIDER_TABLE.table_name.clone())
            .columns(authz_tables::IDENTITY_PROVIDER_TABLE.insert_columns.clone())
            .resolve_conflict(false)
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let create_idp_stmt = client.prepare_cached(&create_idp_sql).await.unwrap();

        let metadata = idp.metadata.as_ref().unwrap();
        let response = client
            .execute(
                &create_idp_stmt,
                &[
                    &metadata.tenant,
                    &idp.internal_id,
                    &idp.provider_id,
                    &idp.realm_id,
                    &idp.name,
                    &idp.display_name,
                    &idp.description,
                    &idp.trust_email,
                    &idp.enabled,
                    &idp.configs,
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

    async fn udpate_identity_provider(&self, idp: &IdentityProviderModel) -> Result<(), String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let update_idp_sql = UpdateRequestBuilder::new()
            .table_name(authz_tables::IDENTITY_PROVIDER_TABLE.table_name.clone())
            .columns(authz_tables::IDENTITY_PROVIDER_TABLE.update_columns.clone())
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
        let metadata = idp.metadata.as_ref().unwrap();
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
                    &idp.configs,
                    &metadata.updated_at,
                    &metadata.updated_by,
                    &metadata.tenant,
                    &idp.realm_id,
                    &idp.internal_id,
                ],
            )
            .await;

        match response {
            Err(err) => Err(err.to_string()),
            Ok(_) => Ok(()),
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
            .table_name(authz_tables::IDENTITY_PROVIDER_TABLE.table_name.clone())
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
                    Ok(Some(self.read_idp_record(r)))
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
            .table_name(authz_tables::IDENTITY_PROVIDER_TABLE.table_name.clone())
            .where_clauses(vec![SqlCriteriaBuilder::is_equals("realm_id".to_string())])
            .sql_query()
            .unwrap();

        let client = client.unwrap();
        let load_idp_stmt = client.prepare_cached(&load_idp_sql).await.unwrap();
        let result = client.query(&load_idp_stmt, &[&realm_id]).await;
        match result {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| self.read_idp_record(row))
                .collect()),
            Err(err) => Err(err.to_string()),
        }
    }

    async fn remove_identity_provider(
        &self,
        realm_id: &str,
        internal_id: &str,
    ) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let remove_idp_sql = DeleteQueryBuilder::new()
            .table_name(authz_tables::IDENTITY_PROVIDER_TABLE.table_name.clone())
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
            Ok(result) => Ok(result > 0),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn exists_by_alias(&self, realm_id: &str, alias: &str) -> Result<bool, String> {
        let client = self.database_manager.connection().await;
        if let Err(err) = client {
            return Err(err);
        }
        let load_idp_by_alias_sql = SelectCountRequestBuilder::new()
            .table_name(authz_tables::IDENTITY_PROVIDER_TABLE.table_name.clone())
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
            Ok(row) => Ok(row.get::<usize, u32>(0) as u32 > 0),
            Err(error) => Err(error.to_string()),
        }
    }
}
