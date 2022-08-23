use lazy_static::lazy_static;

use crate::providers::rds::tables::rds_table::RdsTable;

lazy_static! {
    pub static ref USER_TABLE: RdsTable = RdsTable {
        table_name: "REALMS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "realm_id".to_owned(),
            "user_name".to_owned(),
            "enabled".to_owned(),
            "email".to_owned(),
            "email_verified".to_owned(),
            "required_actions".to_owned(),
            "not_before".to_owned(),
            "user_storage".to_owned(),
            "attributes".to_owned(),
            "is_service_account".to_owned(),
            "service_account_client_link".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned()
        ],
        update_columns: vec![
            "enabled".to_owned(),
            "email".to_owned(),
            "email_verified".to_owned(),
            "required_actions".to_owned(),
            "not_before".to_owned(),
            "user_storage".to_owned(),
            "attributes".to_owned(),
            "is_service_account".to_owned(),
            "service_account_client_link".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
    pub static ref SELECT_USER_BY_USER_NAME_EMAIL: &'static str =
        "SELECT * FROM USERS WHERE user_name=$1 OR email=$2";
}
