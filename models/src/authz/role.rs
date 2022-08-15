use chrono::{DateTime, Utc};

#[derive(Debug)]
#[allow(dead_code)]
pub struct Role {
    role_id: String,
    name: String,
    description: String,
    is_client_role: bool,
    display_name: String,
    created_by: String,
    created_at: DateTime<Utc>,
    updated_by: String,
    updated_at: DateTime<Utc>,
    version: i32,
}
