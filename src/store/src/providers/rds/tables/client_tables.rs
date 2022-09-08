use lazy_static::lazy_static;

use crate::providers::rds::tables::rds_table::RdsTable;

lazy_static! {
    pub static ref PROTOCOL_MAPPER_TABLE: RdsTable = RdsTable {
        table_name: "PROTOCOLS_MAPPERS".to_owned(),
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
    pub static ref PROTOCOL_MAPPER_TABLE_SELECT_PROTOCOL_MAPPER_BY_CLIENT_ID_QUERY: &'static str = r#"SELECT p.* FROM PROTOCOLS_MAPPERS p INNER JOIN CLIENT_PROTOCOLS_MAPPERS cp ON p.mapper_id = cp.mapper_id WHERE cp.realm_id = $1 AND cp.client_id = $2"#;
    pub static ref PROTOCOL_MAPPER_TABLE_SELECT_PROTOCOL_MAPPER_BY_CLIENT_SCOPE_ID_QUERY: &'static str = r#"SELECT p.* FROM PROTOCOLS_MAPPERS p INNER JOIN CLIENT_SCOPE_PROTOCOL_MAPPERS cspm ON cspm.mapper_id = cp.mapper_id WHERE cp.realm_id = $1 AND cspm.client_scope_id = $2"#;
    pub static ref CLIENT_SCOPE_TABLE: RdsTable = RdsTable {
        table_name: "CLIENTS_SCOPES".to_owned(),
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
    pub static ref CLIENTS_SCOPES_ROLES_TABLE: RdsTable = RdsTable {
        table_name: "CLIENTS_SCOPES_ROLES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "client_scope_id".to_owned(),
            "role_id".to_owned()
        ],
        update_columns: vec![]
    };
    pub static ref CLIENTS_SCOPES_PROTOCOLS_MAPPERS_TABLE: RdsTable = RdsTable {
        table_name: "CLIENTS_SCOPES_PROTOCOLS_MAPPERS".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "client_scope_id".to_owned(),
            "mapper_id".to_owned()
        ],
        update_columns: vec![]
    };
    pub static ref CLIENT_SCOPE_TABLE_SELECT_CLIENT_SCOPE_ROLES: &'static str = r#"SELECT r.* FROM ROLES r INNER JOIN CLIENTS_SCOPES_ROLES csr
                ON csr.role_id = r.role_id WHERE csr.realm_id = $1 AND csr.client_scope_id = $2"#;
    pub static ref CLIENT_SCOPE_TABLE_DELETE_CLIENT_SCOPE_ROLES: &'static str = r#"DELETE FROM CLIENTS_SCOPES_ROLES csr WHERE csr.realm_id = $1 AND csr.client_scope_id = $2"#;
    pub static ref CLIENT_SCOPE_TABLE_SELECT_CLIENT_SCOPE_PROTOCOL_MAPPERS: &'static str = r#"SELECT * FROM PROTOCOLS_MAPPERS p INNER JOIN CLIENTS_SCOPES_PROTOCOLS_MAPPERS cscp  ON
                cscp.mapper_id = p.mapper_id  WHERE cscp.realm_id = $1 AND cscp.client_scope_id = $2"#;
    pub static ref CLIENT_SCOPE_TABLE_DELETE_CLIENT_SCOPE_PROTOCOL_MAPPERS: &'static str = r#"DELETE FROM CLIENTS_SCOPES_PROTOCOLS_MAPPERS cscp WHERE cscp.realm_id = $1 AND cscp.client_scope_id = $2"#;
    pub static ref CLIENTS_TABLE: RdsTable = RdsTable {
        table_name: "CLIENTS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "client_id".to_owned(),
            "realm_id".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "enabled".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned(),
        ],
        update_columns: vec![
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "enabled".to_owned(),
            "secret".to_owned(),
            "registration_token".to_owned(),
            "public_client".to_owned(),
            "full_scope_allowed".to_owned(),
            "protocol".to_owned(),
            "root_url".to_owned(),
            "web_origins".to_owned(),
            "redirect_uris".to_owned(),
            "consent_required".to_owned(),
            "authorization_code_flow_enabled".to_owned(),
            "implicit_flow_enabled".to_owned(),
            "direct_access_grants_enabled".to_owned(),
            "standard_flow_enabled".to_owned(),
            "is_surrogate_auth_required".to_owned(),
            "not_before".to_owned(),
            "bearer_only".to_owned(),
            "front_channel_logout".to_owned(),
            "configs".to_owned(),
            "client_authenticator_type".to_owned(),
            "service_account_enabled".to_owned(),
            "auth_flow_binding_overrides".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
    pub static ref CLIENTS_ROLES_TABLE: RdsTable = RdsTable {
        table_name: "CLIENTS_ROLES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "client_id".to_owned(),
            "role_id".to_owned()
        ],
        update_columns: vec![]
    };
    pub static ref CLIENTS_CLIENTS_SCOPES_TABLE: RdsTable = RdsTable {
        table_name: "CLIENTS_CLIENTS_SCOPES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "client_id".to_owned(),
            "client_scope_id".to_owned()
        ],
        update_columns: vec![]
    };
    pub static ref CLIENTS_PROTOCOLS_MAPPERS_TABLE: RdsTable = RdsTable {
        table_name: "CLIENTS_PROTOCOLS_MAPPERS".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "client_id".to_owned(),
            "mapper_id".to_owned()
        ],
        update_columns: vec![]
    };
    pub static ref CLIENT_TABLE_SELECT_CLIENT_BY_ROLE: &'static str = r#"SELECT c.* FROM CLIENTS INNER JOIN CLIENTS_ROLES cr ON cr.role_id = c.role_id  WHERE cr.realm_id = $1 AND cr.role_id = $2 LIMIT 1"#;
    pub static ref CLIENT_TABLE_SELECT_ROLES_BY_CLIENT_ID: &'static str = r#"SELECT r.* FROM ROLES INNER JOIN CLIENTS_ROLES cr ON cr.role_id = r.role_id  WHERE cr.realm_id = $1 AND cr.client_id = $2"#;
    pub static ref CLIENT_TABLE_SELECT_CLIENT_SCOPE_IDS_BY_CLIENT_ID: &'static str = r#"SELECT cs.client_scope_id FROM CLIENTS_SCOPES ccs INNER JOIN CLIENTS_CLIENTS_SCOPES ccs ON ccs.client_id = cs.client_id  WHERE ccs.realm_id = $1 AND ccs.client_id = $2"#;
    pub static ref CLIENT_TABLE_SELECT_PROTOCOL_MAPPERS_IDS_BY_CLIENT_ID: &'static str = r#"SELECT cpm.mapper_id FROM CLIENTS_PROTOCOLS_MAPPERS cpm WHERE cpm.realm_id = $1 AND cpm.client_id = $2"#;
}
