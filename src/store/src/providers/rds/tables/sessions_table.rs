use crate::providers::rds::tables::rds_table::RdsTable;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref ROOT_AUTH_SESSIONS_TABLE: RdsTable = RdsTable {
        table_name: "ROOT_AUTH_SESSIONS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "realm_id".to_owned(),
            "session_id".to_owned(),
            "timestamp".to_owned()
        ],
        update_columns: vec!["timestamp".to_owned()]
    };
    pub static ref AUTH_SESSIONS_TABLE: RdsTable = RdsTable {
        table_name: "AUTH_SESSIONS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "realm_id".to_owned(),
            "tab_id".to_owned(),
            "auth_user_id".to_owned(),
            "root_session_id".to_owned(),
            "client_id".to_owned(),
            "redirect_uri".to_owned(),
            "client_scopes".to_owned(),
            "timestamp".to_owned(),
            "action".to_owned(),
            "protocol".to_owned(),
            "execution_status".to_owned(),
            "client_notes".to_owned(),
            "auth_notes".to_owned(),
            "required_actions".to_owned(),
            "user_session_notes".to_owned(),
        ],
        update_columns: vec![
            "auth_user_id".to_owned(),
            "redirect_uri".to_owned(),
            "client_scopes".to_owned(),
            "timestamp".to_owned(),
            "action".to_owned(),
            "protocol".to_owned(),
            "execution_status".to_owned(),
            "client_notes".to_owned(),
            "auth_notes".to_owned(),
            "required_actions".to_owned(),
            "user_session_notes".to_owned(),
        ]
    };
    pub static ref SELECT_AUTH_SESSIONS_QUERY: &'static str = r#" SELECT aus.* FROM AUTH_SESSIONS aus INNER JOIN ROOT_AUTH_SESSIONS rs ON aus.root_session_id = rs.session_id WHERE aus.tenant = $1 AND aus.realm_id = $2 AND  rs.session_id = $3"#;
    pub static ref CLIENT_SESSIONS_TABLE: RdsTable = RdsTable {
        table_name: "CLIENT_SESSIONS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "realm_id".to_owned(),
            "session_id".to_owned(),
            "user_id".to_owned(),
            "user_session_id".to_owned(),
            "client_id".to_owned(),
            "auth_method".to_owned(),
            "redirect_uri".to_owned(),
            "action".to_owned(),
            "started_at".to_owned(),
            "expiration".to_owned(),
            "notes".to_owned(),
            "refresh_token".to_owned(),
            "refresh_token_use_count".to_owned(),
            "offline".to_owned(),
        ],
        update_columns: vec![
            "auth_method".to_owned(),
            "redirect_uri".to_owned(),
            "action".to_owned(),
            "started_at".to_owned(),
            "expiration".to_owned(),
            "notes".to_owned(),
            "refresh_token".to_owned(),
            "refresh_token_use_count".to_owned(),
            "offline".to_owned(),
        ]
    };
    pub static ref USER_SESSIONS_TABLE: RdsTable = RdsTable {
        table_name: "USER_SESSIONS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "realm_id".to_owned(),
            "session_id".to_owned(),
            "user_id".to_owned(),
            "login_username".to_owned(),
            "broker_session_id".to_owned(),
            "broker_user_id".to_owned(),
            "auth_method".to_owned(),
            "ip_address".to_owned(),
            "started_at".to_owned(),
            "expiration".to_owned(),
            "remember_me".to_owned(),
            "last_session_refresh".to_owned(),
            "offline".to_owned(),
            "notes".to_owned(),
            "state".to_owned(),
        ],
        update_columns: vec![
            "auth_method".to_owned(),
            "ip_address".to_owned(),
            "started_at".to_owned(),
            "expiration".to_owned(),
            "remember_me".to_owned(),
            "last_session_refresh".to_owned(),
            "offline".to_owned(),
            "notes".to_owned(),
            "state".to_owned(),
        ]
    };
    pub static ref SELECT_USER_SESSIONS_QUERY: &'static str = r#" SELECT us.* FROM USER_SESSIONS us INNER JOIN CLIENT_SESSIONS cs ON us.session_id = cs.user_session_id WHERE us.realm_id = $1 AND us.session_id = $2"#;
    pub static ref SELECT_USER_SESSIONS_PAGING_QUERY: &'static str = r#" SELECT us.* FROM USER_SESSIONS us INNER JOIN CLIENT_SESSIONS cs ON us.session_id = cs.user_session_id WHERE us.realm_id = $1 AND us.session_id = $2 AND cs.offline=$3 offset $4 limit $5 "#;
    pub static ref COUNT_USER_SESSION_QUERY: &'static str = r#" SELECT COUNT(us.session_id) FROM USER_SESSIONS us INNER JOIN CLIENT_SESSIONS cs ON us.session_id = cs.user_session_id WHERE us.realm_id = $1 AND cs.client_id = $2 AND cs.offline=$3"#;
}
