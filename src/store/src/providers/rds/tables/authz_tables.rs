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
    pub static ref CLIENT_ROLES_SELECT_BY_CLIENT_ID_QUERY: &'static str = r#"SELECT r.* FROM ROLES r INNER JOIN CLIENTS_ROLES cr ON (r.role_id = cr.role_id AND r.realm_id = cr.realm_id) WHERE cr.realm_id = $1 AND cr.client_id = $2"#;
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
    pub static ref SELECT_USER_GROUPS_COUNT_BY_USER_ID: String =
        "SELECT COUNT(g.group_id) FROM GROUPS g INNER JOIN ug USERS_GROUPS ON (ug.group_id = g.group_id AND  ug.realm_id = g.realm_id) WHERE ug.realm_id=$1 AND ug.user_id=$2".to_owned();

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

    pub static ref POLICIES_TABLE: RdsTable = RdsTable {
        table_name: "POLICIES".to_owned(),
        insert_columns: vec![
            "policy_id".to_owned(),
            "realm_id".to_owned(),
            "server_id".to_owned(),
            "name".to_owned(),
            "description".to_owned(),
            "policy_type".to_owned(),
            "decision_strategy".to_owned(),
            "policy_logic".to_owned(),
            "policy_owner".to_owned(),
            "configs".to_owned(),
            "attributes".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned(),
        ],
        update_columns: vec![
            "name".to_owned(),
            "description".to_owned(),
            "policy_type".to_owned(),
            "decision_strategy".to_owned(),
            "policy_logic".to_owned(),
            "policy_owner".to_owned(),
            "configs".to_owned(),
            "attributes".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned(),
        ]
    };

    pub static ref CLIENTS_POLICIES_TABLE: RdsTable = RdsTable {
        table_name: "CLIENTS_POLICIES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "server_id".to_owned(),
            "client_id".to_owned(),
            "policy_id".to_owned()
        ],
        update_columns: vec![]
    };

    pub static ref SELECT_CLIENTS_BY_POLICY_ID: String =
        "SELECT c.* FROM CLIENTS c INNER JOIN CLIENTS_POLICIES cp ON cp.client_id=c.client_id  WHERE cp.realm_id=$1 AND cp.server_id=$2 AND cp.policy_id=$3".to_owned();

    pub static ref USERS_POLICIES_TABLE: RdsTable = RdsTable {
        table_name: "USERS_POLICIES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "server_id".to_owned(),
            "user_id".to_owned(),
            "policy_id".to_owned()
        ],
        update_columns: vec![]
    };

    pub static ref SELECT_USERS_BY_POLICY_ID: String =
        "SELECT u.* FROM USERS u INNER JOIN USERS_POLICIES up ON up.user_id=u.user_id WHERE up.realm_id=$1 AND up.server_id=$2 AND up.policy_id=$3".to_owned();

    pub static ref ROLES_POLICIES_TABLE: RdsTable = RdsTable {
        table_name: "ROLES_POLICIES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "server_id".to_owned(),
            "role_id".to_owned(),
            "policy_id".to_owned()
        ],
        update_columns: vec![]
    };

    pub static ref SELECT_ROLES_BY_POLICY_ID: String =
        "SELECT r.* FROM ROLES r INNER JOIN ROLES_POLICIES rp ON rp.role_id=r.role_id WHERE rp.realm_id=$1 AND rp.server_id=$2 AND rp.policy_id=$3".to_owned();

    pub static ref GROUPS_POLICIES_TABLE: RdsTable = RdsTable {
        table_name: "GROUPS_POLICIES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "server_id".to_owned(),
            "group_id".to_owned(),
            "policy_id".to_owned(),
        ],
        update_columns: vec![]
    };

    pub static ref SELECT_GROUPS_BY_POLICY_ID: String =
        "SELECT g.* FROM GROUPS g INNER JOIN GROUPS_POLICIES gp ON gp.group_id=g.group_id WHERE gp.realm_id=$1 AND gp.server_id=$2 AND gp.policy_id=$3".to_owned();

    pub static ref POLICIES_POLICIES_TABLE: RdsTable = RdsTable {
        table_name: "POLICIES_POLICIES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "server_id".to_owned(),
            "policy_id".to_owned(),
            "associated_policy_id".to_owned()
        ],
        update_columns: vec![]
    };

    pub static ref SELECT_ASSOCIATED_POLICIES_BY_POLICY_ID: String =
        "SELECT p.* FROM POLICIES p INNER JOIN POLICIES_POLICIES pp ON pp.policy_id=p.policy_id WHERE pp.realm_id=$1 AND pp.server_id=$2 AND pp.policy_id=$3".to_owned();

    pub static ref RESOURCES_POLICIES_TABLE: RdsTable = RdsTable {
        table_name: "RESOURCES_POLICIES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "server_id".to_owned(),
            "resource_id".to_owned(),
            "policy_id".to_owned()
        ],
        update_columns: vec![]
    };

    pub static ref SELECT_RESOURCES_BY_POLICY_ID: String =
        "SELECT r.* FROM RESOURCES r INNER JOIN RESOURCES_POLICIES rp ON rp.policy_id=r.policy_id WHERE pp.realm_id=$1 AND rp.server_id=$2 AND rp.policy_id=$3".to_owned();

    pub static ref SCOPES_POLICIES_TABLE: RdsTable = RdsTable {
        table_name: "SCOPES_POLICIES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "server_id".to_owned(),
            "scope_id".to_owned(),
            "policy_id".to_owned()
        ],
        update_columns: vec![]
    };

    pub static ref SELECT_SCOPES_BY_POLICY_ID: String =
        "SELECT s.* FROM SCOPES s INNER JOIN SCOPES_POLICIES sp ON sp.policy_id=s.policy_id WHERE sp.realm_id=$1 AND sp.server_id=$2 AND sp.policy_id=$3".to_owned();

    pub static ref CLIENTS_SCOPES_POLICIES_TABLE: RdsTable = RdsTable {
        table_name: "CLIENTS_SCOPES_POLICIES".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "server_id".to_owned(),
            "client_scope_id".to_owned(),
            "policy_id".to_owned()
        ],
        update_columns: vec![]
    };

    pub static ref SELECT_CLIENTS_SCOPES_BY_POLICY_ID: String =
        "SELECT cs.* FROM CLIENTS_SCOPES cs INNER JOIN CLIENTS_SCOPES_POLICIES csp ON csp.policy_id=cs.policy_id WHERE csp.realm_id=$1 AND csp.server_id=$2 AND csp.policy_id=$3".to_owned();

}
