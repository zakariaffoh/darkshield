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
            "description".to_owned(),
            "created_by".to_owned(),
            "created_at".to_owned(),
            "version".to_owned(),
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

    pub static ref IDENTITY_PROVIDER_TABLE: RdsTable = RdsTable {
        table_name: "IDENTITY_PROVIDER".to_owned(),
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
}
