use crate::auditable::AuditableModel;
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};

use super::attributes::AttributesMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct Permission {}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoleModel {
    pub role_id: String,
    pub realm_id: String,
    pub name: String,
    pub description: String,
    pub is_client_role: bool,
    pub display_name: String,
    pub metadata: Option<AuditableModel>,
}

#[derive(Debug, Deserialize)]
pub struct RoleMutationModel {
    pub name: String,
    pub description: String,
    pub is_client_role: bool,
    pub display_name: String,
}

impl Into<RoleModel> for RoleMutationModel {
    fn into(self) -> RoleModel {
        RoleModel {
            role_id: String::new(),
            realm_id: String::new(),
            name: self.name,
            description: self.description,
            is_client_role: self.is_client_role,
            display_name: self.display_name,
            metadata: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupModel {
    pub group_id: String,
    pub realm_id: String,
    pub name: String,
    pub roles: Option<Vec<RoleModel>>,
    pub display_name: String,
    pub description: String,
    pub is_default: bool,
    pub metadata: Option<AuditableModel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupMutationModel {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub is_default: bool,
}

impl Into<GroupModel> for GroupMutationModel {
    fn into(self) -> GroupModel {
        GroupModel {
            group_id: uuid::Uuid::new_v4().to_string(),
            realm_id: String::new(),
            name: self.name,
            description: self.description,
            roles: None,
            display_name: self.display_name,
            is_default: self.is_default,
            metadata: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupPagingResult {
    pub page_size: i64,
    pub page_index: i64,
    pub total_count: i64,
    pub groups: Vec<GroupModel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityProviderModel {
    pub internal_id: String,
    pub provider_id: String,
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
    pub trust_email: Option<bool>,
    pub configs: Option<AttributesMap>,
    pub metadata: Option<AuditableModel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityProviderMutationModel {
    pub provider_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
    pub trust_email: Option<bool>,
    pub configs: Option<AttributesMap>,
}

impl Into<IdentityProviderModel> for IdentityProviderMutationModel {
    fn into(self) -> IdentityProviderModel {
        IdentityProviderModel {
            realm_id: String::new(),
            internal_id: String::new(),
            provider_id: self.provider_id,
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            enabled: self.enabled,
            trust_email: self.trust_email,
            configs: self.configs,
            metadata: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSql, FromSql, PartialEq, Eq, Hash)]
#[postgres(name = "policyenforcementmodeenum")]
pub enum PolicyEnforcementModeEnum {
    Enforcing,
    Permissive,
    Disabled,
}

#[derive(Debug, Serialize, Deserialize, ToSql, FromSql, PartialEq, Eq, Hash)]
#[postgres(name = "decisionstrategyenum")]
pub enum DecisionStrategyEnum {
    Affirmative,
    Unanimous,
    Consensus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceServerModel {
    pub server_id: String,
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enforcement_mode: PolicyEnforcementModeEnum,
    pub decision_strategy: DecisionStrategyEnum,
    pub remote_resource_management: Option<bool>,
    pub user_managed_access_enabled: Option<bool>,
    pub configs: Option<AttributesMap>,
    pub metadata: Option<AuditableModel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceServerMutationModel {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enforcement_mode: PolicyEnforcementModeEnum,
    pub decision_strategy: DecisionStrategyEnum,
    pub remote_resource_management: Option<bool>,
    pub user_managed_access_enabled: Option<bool>,
    pub configs: Option<AttributesMap>,
}

impl Into<ResourceServerModel> for ResourceServerMutationModel {
    fn into(self) -> ResourceServerModel {
        ResourceServerModel {
            server_id: String::new(),
            realm_id: String::new(),
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            enforcement_mode: self.enforcement_mode,
            decision_strategy: self.decision_strategy,
            remote_resource_management: self.remote_resource_management,
            user_managed_access_enabled: self.user_managed_access_enabled,
            configs: self.configs,
            metadata: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceModel {
    pub resource_id: String,
    pub server_id: String,
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub resource_uris: Vec<String>,
    pub resource_type: String,
    pub resource_owner: String,
    pub user_managed_access_enabled: Option<bool>,
    pub configs: Option<AttributesMap>,
    pub metadata: Option<AuditableModel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceMutationModel {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub resource_uris: Vec<String>,
    pub resource_type: String,
    pub resource_owner: String,
    pub user_managed_access_enabled: Option<bool>,
    pub configs: Option<AttributesMap>,
}

impl Into<ResourceModel> for ResourceMutationModel {
    fn into(self) -> ResourceModel {
        ResourceModel {
            resource_id: String::new(),
            server_id: String::new(),
            realm_id: String::new(),
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            resource_uris: self.resource_uris,
            resource_type: self.resource_type,
            resource_owner: self.resource_owner,
            user_managed_access_enabled: self.user_managed_access_enabled,
            configs: self.configs,
            metadata: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScopeModel {
    pub scope_id: String,
    pub server_id: String,
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub metadata: Option<AuditableModel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScopeMutationModel {
    pub name: String,
    pub display_name: String,
    pub description: String,
}

impl Into<ScopeModel> for ScopeMutationModel {
    fn into(self) -> ScopeModel {
        ScopeModel {
            scope_id: String::new(),
            server_id: String::new(),
            realm_id: String::new(),
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            metadata: None,
        }
    }
}
