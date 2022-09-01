use lazy_static::lazy_static;

use crate::providers::rds::tables::rds_table::RdsTable;

lazy_static! {
    pub static ref REALM_TABLE: RdsTable = RdsTable {
        table_name: "REALMS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "realm_id".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "enabled".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned()
        ],
        update_columns: vec![
            "name".to_owned(),
            "display_name".to_owned(),
            "enabled".to_owned(),
            "registration_allowed".to_owned(),
            "verify_email".to_owned(),
            "reset_password_allowed".to_owned(),
            "login_with_email_allowed".to_owned(),
            "duplicated_email_allowed".to_owned(),
            "register_email_as_username".to_owned(),
            "ssl_enforcement".to_owned(),
            "password_policy".to_owned(),
            "edit_user_name_allowed".to_owned(),
            "revoke_refresh_token".to_owned(),
            "refresh_token_max_reuse".to_owned(),
            "access_token_lifespan".to_owned(),
            "access_code_lifespan".to_owned(),
            "access_code_lifespan_login".to_owned(),
            "access_code_lifespan_user_action".to_owned(),
            "action_tokens_lifespan".to_owned(),
            "not_before".to_owned(),
            "remember_me".to_owned(),
            "master_admin_client".to_owned(),
            "events_enabled".to_owned(),
            "admin_events_enabled".to_owned(),
            "attributes".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
    pub static ref REALM_TABLE_EXISTS_BY_CRITERIA_QUERY: &'static str = r#"SELECT COUNT(r.realm_id) FROM REALMS r WHERE upper(r.realm_id) = upper($1) OR upper(r.name) = upper($2) OR upper(r.display_name) = upper($3)"#;
}
