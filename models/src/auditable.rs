use serde::Serialize;

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct AuditableModel {
    pub tenant: String,
    pub created_by: String,
    pub updated_by: String,
    pub created_at: f64,
    pub updated_at: f64,
    pub version: i32,
}

impl AuditableModel {
    pub fn from_creator(tenant: String, created_by: String, created_at: f64) -> Self {
        Self {
            tenant: tenant,
            created_by: created_by,
            updated_by: "".to_owned(),
            created_at: created_at,
            updated_at: 0.0,
            version: 1,
        }
    }
}
