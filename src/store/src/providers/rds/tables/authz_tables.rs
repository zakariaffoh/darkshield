use lazy_static::lazy_static;

use crate::providers::rds::tables::rds_table::RdsTable;

lazy_static! {
    pub static ref ROLE_TABLE: RdsTable = RdsTable {
        table_name: "ROLES".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "role_id".to_owned(),
            "realm_id".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "client_role".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned(),
        ],
        update_columns: vec![
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "client_role".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
    pub static ref GROUP_TABLE: RdsTable = RdsTable {
        table_name: "GROUPS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "group_id".to_owned(),
            "realm_id".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "is_default".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned(),
        ],
        update_columns: vec![
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "is_default".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
    pub static ref GROUPS_ROLES_TABLE: RdsTable = RdsTable {
        table_name: "GROUPS_ROLES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "group_id".to_owned(),
            "role_id".to_owned()
        ],
        update_columns: Vec::new()
    };
    pub static ref GROUPS_ROLES_SELECT_BY_ROLE_ID_QUERY: &'static str = r#"SELECT r.* FROM ROLES r INNER JOIN GROUPS_ROLES gr ON (r.role_id = gr.role_id AND r.realm_id = gr.realm_id) WHERE gr.realm_id = $1 AND gr.group_id = $2"#;
    pub static ref IDENTITIES_PROVIDERS_TABLE: RdsTable = RdsTable {
        table_name: "IDENTITIES_PROVIDERS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "internal_id".to_owned(),
            "provider_id".to_owned(),
            "realm_id".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "trust_email".to_owned(),
            "enabled".to_owned(),
            "configs".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned(),
        ],
        update_columns: vec![
            "provider_id".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "trust_email".to_owned(),
            "enabled".to_owned(),
            "configs".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
    pub static ref RESOURCES_SERVERS_TABLE: RdsTable = RdsTable {
        table_name: "RESOURCES_SERVERS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "server_id".to_owned(),
            "realm_id".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "policy_enforcement_mode".to_owned(),
            "decision_strategy".to_owned(),
            "remote_resource_management".to_owned(),
            "user_managed_access_enabled".to_owned(),
            "configs".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned(),
        ],
        update_columns: vec![
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "policy_enforcement_mode".to_owned(),
            "decision_strategy".to_owned(),
            "remote_resource_management".to_owned(),
            "user_managed_access_enabled".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
    pub static ref SCOPES_TABLE: RdsTable = RdsTable {
        table_name: "SCOPES".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "scope_id".to_owned(),
            "server_id".to_owned(),
            "realm_id".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned(),
        ],
        update_columns: vec![
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
    pub static ref RESOURCES_TABLE: RdsTable = RdsTable {
        table_name: "RESOURCES".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "realm_id".to_owned(),
            "server_id".to_owned(),
            "resource_id".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "resource_uris".to_owned(),
            "resource_type".to_owned(),
            "resource_owner".to_owned(),
            "user_managed_access_enabled".to_owned(),
            "configs".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned(),
        ],
        update_columns: vec![
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "resource_uris".to_owned(),
            "resource_type".to_owned(),
            "resource_owner".to_owned(),
            "user_managed_access_enabled".to_owned(),
            "configs".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
    pub static ref RESOURCES_SCOPES_TABLE: RdsTable = RdsTable {
        table_name: "RESOURCES_SCOPES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "server_id".to_owned(),
            "resource_id".to_owned(),
            "scope_id".to_owned()
        ],
        update_columns: vec![]
    };
}
