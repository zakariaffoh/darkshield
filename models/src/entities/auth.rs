use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result};
use crate::auditable::AuditableModel;

#[derive(Debug, Serialize, Deserialize, ToSql, FromSql, PartialEq, Eq, Hash)]
pub enum RequiredActionEnum {
    ResetPassword,
    UpdatePassword,
    VerifyEmail,
    ConfigureTotp,
}

impl Display for RequiredActionEnum {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let printable = match *self {
            RequiredActionEnum::ResetPassword => "ResetPassword",
            RequiredActionEnum::UpdatePassword => "UpdatePassword",
            RequiredActionEnum::VerifyEmail => "VerifyEmail",
            RequiredActionEnum::ConfigureTotp => "ConfigureTotp",
        };
        write!(f, "{}", printable)
    }
}

#[derive(Serialize, Deserialize)]
pub struct RequiredActionModel {
    pub action_id: String,
    pub realm_id: String,
    pub provider_id: String,
    pub action: RequiredActionEnum,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
    pub default_action: Option<bool>,
    pub on_time_action: Option<bool>,
    pub priority: Option<u32>,
    pub metadata: Option<AuditableModel>,
}

#[derive(Serialize, Deserialize)]
pub struct RequiredActionCreateModel {
    pub realm_id: String,
    pub provider_id: String,
    pub action: RequiredActionEnum,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
    pub default_action: Option<bool>,
    pub on_time_action: Option<bool>,
    pub priority: Option<u32>,
}

impl Into<RequiredActionModel> for RequiredActionCreateModel {
    fn into(self) -> RequiredActionModel {
        RequiredActionModel {
            action_id: uuid::Uuid::new_v4().to_string(),
            realm_id: self.realm_id,
            provider_id: self.provider_id,
            action: self.action,
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            enabled: self.enabled,
            default_action: self.default_action,
            on_time_action: self.on_time_action,
            priority: self.priority,
            metadata: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RequiredActionUpdateModel {
    pub action_id: String,
    pub realm_id: String,
    pub provider_id: String,
    pub action: RequiredActionEnum,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
    pub default_action: Option<bool>,
    pub on_time_action: Option<bool>,
    pub priority: Option<u32>,
}

impl Into<RequiredActionModel> for RequiredActionUpdateModel {
    fn into(self) -> RequiredActionModel {
        RequiredActionModel {
            action_id: self.action_id,
            realm_id: self.realm_id,
            provider_id: self.provider_id,
            action: self.action,
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            enabled: self.enabled,
            default_action: self.default_action,
            on_time_action: self.on_time_action,
            priority: self.priority,
            metadata: None,
        }
    }
}
