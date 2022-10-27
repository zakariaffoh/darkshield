use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditableModel {
    pub tenant: String,
    pub created_by: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_by: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
    pub version: i32,
}

impl Clone for AuditableModel {
    fn clone(&self) -> Self {
        Self {
            tenant: self.tenant.clone(),
            created_by: self.created_by.clone(),
            created_at: self.created_at.clone(),
            updated_by: self.updated_by.clone(),
            updated_at: self.updated_at.clone(),
            version: self.version.clone(),
        }
    }
}

impl AuditableModel {
    pub fn from_creator(tenant: String, created_by: String) -> Self {
        Self {
            tenant: tenant,
            created_by: Some(created_by),
            updated_by: None,
            created_at: Some(Utc::now()),
            updated_at: None,
            version: 1,
        }
    }

    pub fn from_updator(tenant: String, updated_by: String) -> Self {
        Self {
            tenant: tenant,
            created_by: None,
            updated_by: Some(updated_by),
            created_at: None,
            updated_at: Some(Utc::now()),
            version: 1,
        }
    }
}

impl Default for AuditableModel {
    fn default() -> Self {
        Self {
            tenant: Default::default(),
            created_by: Default::default(),
            created_at: Default::default(),
            updated_by: Default::default(),
            updated_at: Default::default(),
            version: Default::default(),
        }
    }
}
