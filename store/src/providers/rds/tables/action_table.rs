use lazy_static::lazy_static;

use crate::providers::rds::tables::rds_table::RdsTable;

lazy_static! {
    pub static ref REQUIRED_ACTIONS_TABLE: RdsTable = RdsTable {
        table_name: "REQUIRED_ACTIONS".to_owned(),
        insert_columns: vec![
            "tenant".to_owned(),
            "realm_id".to_owned(),
            "provider_id".to_owned(),
            "action".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "default_action".to_owned(),
            "enabled".to_owned(),
            "on_time_action".to_owned(),
            "priority".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned()
        ],
        update_columns: vec![
            "provider_id".to_owned(),
            "action".to_owned(),
            "name".to_owned(),
            "display_name".to_owned(),
            "description".to_owned(),
            "default_action".to_owned(),
            "enabled".to_owned(),
            "on_time_action".to_owned(),
            "priority".to_owned(),
            "updated_by".to_owned(),
            "updated_at".to_owned()
        ]
    };
}
