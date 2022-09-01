use serde::{Deserialize, Serialize};

use crate::auditable::AuditableModel;

#[derive(Debug, Serialize)]
pub struct RealmModel {
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
    pub metadata: Option<AuditableModel>,
}

#[derive(Serialize, Deserialize)]
pub struct RealmCreateModel {
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
}

impl Into<RealmModel> for RealmCreateModel {
    fn into(self) -> RealmModel {
        RealmModel {
            realm_id: self.realm_id,
            name: self.name,
            display_name: self.display_name,
            enabled: self.enabled,
            metadata: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RealmUpdateModel {
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
}

impl Into<RealmModel> for RealmUpdateModel {
    fn into(self) -> RealmModel {
        RealmModel {
            realm_id: self.realm_id,
            name: self.name,
            display_name: self.display_name,
            enabled: self.enabled,
            metadata: None,
        }
    }
}
