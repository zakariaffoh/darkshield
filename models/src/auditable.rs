use chrono::{DateTime, Utc};

#[derive(Debug)]
#[allow(dead_code)]
pub struct AuditableModel {
    tenant: String,
    created_by: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    updated_by: String,
    version: i32,
}
