use crate::providers::rds::tables::rds_table::RdsTable;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref REVOKED_TOKENS_TABLE: RdsTable = RdsTable {
        table_name: "REVOKED_TOKENS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "realm_id".to_owned(),
            "token_id".to_owned(),
            "revokation_time".to_owned(),
            "lifespan_in_secs".to_owned(),
        ],
        update_columns: vec![]
    };
    pub static ref SINGLE_USE_TOKENS_TABLE: RdsTable = RdsTable {
        table_name: "SINGLE_USE_TOKENS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "realm_id".to_owned(),
            "token_id".to_owned(),
            "lifespan_in_secs".to_owned(),
        ],
        update_columns: vec![]
    };
}
