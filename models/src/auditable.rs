#[derive(Debug)]
#[allow(dead_code)]
pub struct AuditableModel {
    pub tenant: String,
    pub created_by: String,
    pub updated_by: String,
    pub created_at: f64,
    pub updated_at: f64,
    pub version: i32,
}
