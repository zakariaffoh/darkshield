use lazy_static::lazy_static;

use crate::providers::rds::tables::rds_table::RdsTable;

lazy_static! {
    pub static ref REALM_TABLE: RdsTable = RdsTable {
        table_name: "REALMS".to_owned(),
        insert_columns: vec![
            "realm_id".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "enabled".to_owned()
        ],
        update_columns: vec!["updated_by".to_owned(), "updated_at".to_owned()]
    };
}
