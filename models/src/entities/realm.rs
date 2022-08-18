use crate::auditable::AuditableModel;

#[derive(Debug)]
#[allow(dead_code)]
pub struct RealmModel {
    realm_id: String,
    metadata: AuditableModel,
}
