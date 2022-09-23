use lazy_static::lazy_static;

use crate::providers::rds::tables::rds_table::RdsTable;

lazy_static! {
    pub static ref USERS_CREDENTIALS_TABLE: RdsTable = RdsTable {
        table_name: "USERS_CREDENTIALS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "credential_id".to_owned(),
            "realm_id".to_owned(),
            "user_id".to_owned(),
            "credential_type".to_owned(),
            "user_label".to_owned(),
            "secret_data".to_owned(),
            "credential_data".to_owned(),
            "priority".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned()
        ],
        update_columns: vec![
            "credential_type".to_owned(),
            "user_label".to_owned(),
            "secret_data".to_owned(),
            "credential_data".to_owned(),
            "priority".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
    pub static ref UPDATE_PASSWORD_CREDENTIAL: &'static str = r#"UPDATE USERS_CREDENTIALS_TABLE SET credential_type=$1  WHERE REALM_ID=$2 AND user_id=$3 AND credential_type=$4"#;
    pub static ref INCREMENT_PASSWORD_CREDENTIAL_PRIORITY: &'static str = r#"UPDATE USERS_CREDENTIALS_TABLE SET priority=priority + 1  WHERE REALM_ID=$2 AND user_id=$3 AND priority > $4"#;
    pub static ref DECREMENT_CREDENTIAL_PRIORITY: &'static str = r#"UPDATE USERS_CREDENTIALS_TABLE SET priority=priority - 1  WHERE REALM_ID=$2 AND user_id=$3 AND priority > $4"#;
    pub static ref DELETE_USER_CREDENTIALS: &'static str =
        r#"DELETE FROM  USERS_CREDENTIALS_TABLE WHERE REALM_ID=$1 AND user_id=$2"#;
}
