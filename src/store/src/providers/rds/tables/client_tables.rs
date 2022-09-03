use lazy_static::lazy_static;

use crate::providers::rds::tables::rds_table::RdsTable;

lazy_static! {
    pub static ref PROTOCOL_MAPPER_TABLE: RdsTable = RdsTable {
        table_name: "PROTOCOL_MAPPERS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "realm_id".to_owned(),
            "mapper_id".to_owned(),
            "name".to_owned(),
            "protocol".to_owned(),
            "mapper_type".to_owned(),
            "configs".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned(),
        ],
        update_columns: vec![
            "name".to_owned(),
            "protocol".to_owned(),
            "mapper_type".to_owned(),
            "configs".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
    pub static ref PROTOCOL_MAPPER_TABLE_SELECT_PROTOCOL_MAPPER_BY_CLIENT_ID_QUERY: &'static str = r#"SELECT p.* FROM PROTOCOL_MAPPERS p INNER JOIN CLIENT_PROTOCOLS_MAPPERS cp ON p.mapper_id = cp.mapper_id WHERE cp.realm_id = $1 AND cp.client_id = $2"#;
    pub static ref PROTOCOL_MAPPER_TABLE_SELECT_PROTOCOL_MAPPER_BY_CLIENT_SCOPE_ID_QUERY: &'static str = r#"SELECT p.* FROM PROTOCOL_MAPPERS p INNER JOIN CLIENT_SCOPE_PROTOCOL_MAPPERS cspm ON cspm.mapper_id = cp.mapper_id WHERE cp.realm_id = $1 AND cspm.client_scope_id = $2"#;
    pub static ref CLIENT_SCOPE_TABLE: RdsTable = RdsTable {
        table_name: "GROUPS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "realm_id".to_owned(),
            "client_scope_id".to_owned(),
            "name".to_owned(),
            "description".to_owned(),
            "protocol".to_owned(),
            "default_scope".to_owned(),
            "configs".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned(),
        ],
        update_columns: vec![
            "name".to_owned(),
            "description".to_owned(),
            "protocol".to_owned(),
            "default_scope".to_owned(),
            "configs".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
    pub static ref CLIENT_SCOPE_TABLE_SELECT_CLIENT_SCOPE_ROLES: &'static str = r#"SELECT r.* FROM ROLES r INNER JOIN CLIENT_SCOPES_ROLES csr
                ON csr.role_id = r.role_id WHERE csr.realm_id = $1 AND csr.client_scope_id = $2"#;
    pub static ref CLIENT_SCOPE_TABLE_DELETE_CLIENT_SCOPE_ROLES: &'static str = r#"DELETE FROM CLIENT_SCOPES_ROLES csr WHERE csr.realm_id = $1 AND csr.client_scope_id = $2"#;
    pub static ref CLIENT_SCOPE_TABLE_SELECT_CLIENT_SCOPE_PROTOCOL_MAPPERS: &'static str = r#"SELECT * FROM PROTOCOL_MAPPERS p INNER JOIN CLIENT_SCOPE_PROTOCOL_MAPPERS cscp  ON
                cscp.mapper_id = p.mapper_id  WHERE cscp.realm_id = $1 AND cscp.client_scope_id = $2"#;
    pub static ref CLIENT_SCOPE_TABLE_DELETE_CLIENT_SCOPE_PROTOCOL_MAPPERS: &'static str = r#"DELETE FROM CLIENT_SCOPE_PROTOCOL_MAPPERS cscp WHERE cscp.realm_id = $1 AND cscp.client_scope_id = $2"#;
    pub static ref CLIENT_TABLE: RdsTable = RdsTable {
        table_name: "IDENTITY_PROVIDER".to_owned(),
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
}
