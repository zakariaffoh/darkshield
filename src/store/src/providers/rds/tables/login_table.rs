use crate::providers::rds::tables::rds_table::RdsTable;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref LOGIN_FAILURES_TABLE: RdsTable = RdsTable {
        table_name: "USER_LOGIN_FAILURES".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "failure_id".to_owned(),
            "realm_id".to_owned(),
            "user_id".to_owned(),
            "failed_login_not_before".to_owned(),
            "num_failures".to_owned(),
            "last_failure".to_owned(),
            "last_ip_failure".to_owned(),
        ],
        update_columns: vec![]
    };
    pub static ref INCREMENT_LOGIN_FAILURE_QUERY: &'static str = r#" UPDATE USER_LOGIN_FAILURES SET failed_login_not_before = $1, num_failures = num_failures + 1, last_failure = $2, last_ip_failure = $3  WHERE tenant = $4 AND realm_id = $5 AND  user_id = $6"#;
}
