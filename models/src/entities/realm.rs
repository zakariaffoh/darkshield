use crate::auditable::AuditableModel;

#[derive(Debug)]
#[allow(dead_code)]
pub struct RealmModel {
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
    pub metadata: AuditableModel,
}
