use super::role::Role;
use chrono::{DateTime, Utc};

#[derive(Debug)]
#[allow(dead_code)]
pub struct Group {
    group_id: String,
    realm_id: String,
    name: String,
    roles: Vec<Role>,
    display_name: String,
    created_by: String,
    created_at: DateTime<Utc>,
    updated_by: String,
    updated_at: DateTime<Utc>,
    version: i32,
}
