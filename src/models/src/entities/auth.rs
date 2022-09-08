use crate::auditable::AuditableModel;
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::{Display, Formatter, Result},
};

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
pub struct RequiredActionMutationModel {
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

impl Into<RequiredActionModel> for RequiredActionMutationModel {
    fn into(self) -> RequiredActionModel {
        RequiredActionModel {
            action_id: String::new(),
            realm_id: String::new(),
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
pub struct AuthenticationFlowModel {
    pub flow_id: String,
    pub alias: String,
    pub realm_id: String,
    pub provider_id: String,
    pub description: String,
    pub top_level: Option<bool>,
    pub built_in: Option<bool>,
    pub metadata: Option<AuditableModel>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticationFlowMutationModel {
    pub alias: String,
    pub provider_id: String,
    pub description: String,
    pub top_level: Option<bool>,
    pub built_in: Option<bool>,
}

impl Into<AuthenticationFlowModel> for AuthenticationFlowMutationModel {
    fn into(self) -> AuthenticationFlowModel {
        AuthenticationFlowModel {
            flow_id: String::new(),
            realm_id: String::new(),
            alias: self.alias,
            provider_id: self.provider_id,
            description: self.description,
            top_level: self.top_level,
            built_in: self.built_in,
            metadata: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSql, FromSql, PartialEq, Eq, Hash)]
#[postgres(name = "authenticatorrequirementenum")]
pub enum AuthenticatorRequirementEnum {
    REQUIRED,
    CONDITIONAL,
    ALTERNATIVE,
    DISABLED,
}

impl Display for AuthenticatorRequirementEnum {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let printable = match *self {
            AuthenticatorRequirementEnum::REQUIRED => "REQUIRED",
            AuthenticatorRequirementEnum::CONDITIONAL => "CONDITIONAL",
            AuthenticatorRequirementEnum::ALTERNATIVE => "ALTERNATIVE",
            AuthenticatorRequirementEnum::DISABLED => "DISABLED",
        };
        write!(f, "{}", printable)
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticationExecutionModel {
    pub execution_id: String,
    pub realm_id: String,
    pub alias: String,
    pub flow_id: String,
    pub parent_flow_id: Option<String>,
    pub priority: i32,
    pub authenticator: String,
    pub authenticator_flow: Option<bool>,
    pub authenticator_config: Option<String>,
    pub requirement: AuthenticatorRequirementEnum,
    pub metadata: Option<AuditableModel>,
}

impl AuthenticationExecutionModel {
    pub fn is_required(&self) -> bool {
        self.requirement == AuthenticatorRequirementEnum::REQUIRED
    }
    pub fn is_conditional(&self) -> bool {
        return self.requirement == AuthenticatorRequirementEnum::CONDITIONAL;
    }

    pub fn is_alternative(&self) -> bool {
        return self.requirement == AuthenticatorRequirementEnum::ALTERNATIVE;
    }

    pub fn is_enabled(&self) -> bool {
        return self.requirement != AuthenticatorRequirementEnum::DISABLED;
    }

    pub fn is_disabled(&self) -> bool {
        return self.requirement == AuthenticatorRequirementEnum::DISABLED;
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticationExecutionMutationModel {
    pub alias: String,
    pub flow_id: String,
    pub parent_flow_id: Option<String>,
    pub priority: i32,
    pub authenticator: String,
    pub authenticator_flow: Option<bool>,
    pub authenticator_config: Option<String>,
    pub built_in: Option<bool>,
    pub requirement: AuthenticatorRequirementEnum,
}

impl Into<AuthenticationExecutionModel> for AuthenticationExecutionMutationModel {
    fn into(self) -> AuthenticationExecutionModel {
        AuthenticationExecutionModel {
            execution_id: String::new(),
            realm_id: String::new(),
            flow_id: self.flow_id,
            alias: self.alias,
            parent_flow_id: self.parent_flow_id,
            priority: self.priority,
            authenticator: self.authenticator,
            authenticator_flow: self.authenticator_flow,
            authenticator_config: self.authenticator_config,
            requirement: self.requirement,
            metadata: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticatorConfigModel {
    pub config_id: String,
    pub realm_id: String,
    pub alias: String,
    pub configs: Option<HashMap<String, Option<String>>>,
    pub metadata: Option<AuditableModel>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticatorConfigMutationModel {
    alias: String,
    configs: Option<HashMap<String, Option<String>>>,
}

impl Into<AuthenticatorConfigModel> for AuthenticatorConfigMutationModel {
    fn into(self) -> AuthenticatorConfigModel {
        AuthenticatorConfigModel {
            config_id: String::new(),
            realm_id: String::new(),
            alias: self.alias,
            configs: self.configs,
            metadata: None,
        }
    }
}
