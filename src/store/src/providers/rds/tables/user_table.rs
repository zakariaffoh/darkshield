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
    pub static ref SELECT_USER_BY_USER_NAME_EMAIL: String =
        "SELECT * FROM USERS WHERE realm_id: $1 AND (user_name=$2 OR email=$3)".to_owned();
    pub static ref SELECT_USER_GROUPS_BY_USER_ID: String =
        "SELECT g.* FROM GROUPS g INNER JOIN USERS_GROUPS ug ON (ug.group_id = g.group_id AND  ug.realm_id = g.realm_id) WHERE ug.realm_id: $1 AND ug.user_id=$2".to_owned();

    pub static ref SELECT_USER_GROUPS_COUNT_BY_USER_ID_PAGING: String =
        "SELECT COUNT(g.group_id) FROM GROUPS g INNER JOIN ug USERS_GROUPS ON (ug.group_id = g.group_id AND  ug.realm_id = g.realm_id) WHERE ug.realm_id: $1 AND ug.user_id=$2".to_owned();

    pub static ref SELECT_USER_GROUPS_BY_USER_ID_PAGING: String =
        "SELECT g.* FROM GROUPS g INNER JOIN USERS_GROUPS ug ON (ug.group_id = g.group_id AND  ug.realm_id = g.realm_id) WHERE ug.realm_id: $1 AND ug.user_id=$2 offset $3 limit $4".to_owned();

    pub static ref SELECT_USER_ROLES_BY_USER_ID: String =
        "SELECT r.* FROM ROLES r INNER JOIN USERS_ROLES ur ON (ur.role_id = r.role_id AND  ur.realm_id = r.realm_id) WHERE ur.realm_id= $1 AND ur.user_id=$2
        UNION ALL
        SELECT rr.* FROM ROLES rr INNER JOIN USERS_ROLES urr ON (urr.role_id = rr.role_id AND  urr.realm_id = rr.realm_id) 
        INNER JOIN GROUPS_ROLES gr ON (gr.role_id = rr.role_id AND  gr.realm_id = rr.realm_id)
        INNER JOIN USERS_GROUPS ugg ON (ugg.group_id = gr.group_id AND  ugg.realm_id = gr.realm_id) WHERE  ugg.realm_id= $1 AND ugg.user_id=$2
          ".to_owned();
}
