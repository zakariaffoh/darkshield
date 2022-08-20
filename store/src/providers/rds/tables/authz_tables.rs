use lazy_static::lazy_static;

use crate::providers::rds::tables::rds_table::RdsTable;

lazy_static! {
    pub static ref ROLE_TABLE: RdsTable = RdsTable {
        table_name: "ROLES".to_owned(),
        insert_columns: vec![
            "role_id".to_owned(),
            "realm_id".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "client_role".to_owned(),
            "description".to_owned()
        ],
        update_columns: vec![
            "name".to_owned(),
            "display_name".to_owned(),
            "client_role".to_owned(),
            "description".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
}
