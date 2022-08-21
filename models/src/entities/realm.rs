use serde::{Deserialize, Serialize};

use crate::auditable::AuditableModel;

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct RealmModel {
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
    pub metadata: AuditableModel,
}

#[derive(Serialize, Deserialize)]
pub struct RealmCreateModel {
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize)]
pub struct RealmUpdateModel {
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
}
