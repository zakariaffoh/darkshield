use std::collections::{BTreeMap, HashMap};

use crate::auditable::AuditableModel;
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};

use super::{attributes::AttributesMap, client::ClientScopeModel, user::UserModel};

#[derive(Debug, Serialize, Deserialize)]
pub struct Permission {
    resource_id: Option<String>,
    resource_name: Option<String>,
    scopes: Option<Vec<String>>,
    claims: Option<HashMap<String, Vec<String>>>,
}

impl Permission {
    fn resource_id(&self) -> &Option<String> {
        &self.resource_id
    }

    fn set_resource_id(&mut self, resource_id: Option<String>) {
        self.resource_id = resource_id
    }
}

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

#[derive(Debug, Serialize, Deserialize, ToSql, FromSql, PartialEq, Eq, Hash)]
#[postgres(name = "policytypeenum")]
pub enum PolicyTypeEnum {
    RegexPolicy,
    RolePolicy,
    GroupPolicy,
    TimePolicy,
    UserPolicy,
    PyPolicy,
    ClientPolicy,
    ClientScopePolicy,
    AggregatedPolicy,
    ScopePermission,
    ResourcePermission,
}

#[derive(Debug, Serialize, Deserialize, ToSql, FromSql, PartialEq, Eq, Hash)]
#[postgres(name = "decisionlogicenum")]
pub enum DecisionLogicEnum {
    Affirmative,
    Unanimous,
    Consensus,
}

#[derive(Serialize, Deserialize)]
pub struct PolicyModel {
    policy_type: PolicyTypeEnum,
    policy_id: String,
    server_id: String,
    realm_id: String,
    name: String,
    description: String,
    decision: DecisionStrategyEnum,
    logic: DecisionLogicEnum,
    policy_owner: String,
    configs: Option<BTreeMap<String, String>>,
    policies: Option<Vec<PolicyModel>>,
    resources: Option<Vec<ResourceModel>>,
    scopes: Option<Vec<ScopeModel>>,
    roles: Option<Vec<RoleModel>>,
    groups: Option<GroupPolicyConfig>,
    regex: Option<RegexConfig>,
    time: Option<TimePolicyConfig>,
    users: Option<Vec<UserModel>>,
    script: Option<String>,
    client_scopes: Option<Vec<ClientScopeModel>>,
    resource_type: Option<String>,
}

impl PartialEq for PolicyModel {
    fn eq(&self, other: &Self) -> bool {
        self.policy_type == other.policy_type
            && self.policy_id == other.policy_id
            && self.server_id == other.server_id
            && self.realm_id == other.realm_id
            && self.name == other.name
            && self.description == other.description
            && self.policy_type == other.policy_type
            && self.decision == other.decision
            && self.logic == other.logic
            && self.policy_owner == other.policy_owner
    }
}

#[derive(Serialize, Deserialize)]
pub struct RegexConfig {
    target_claim: String,
    target_regex: String,
}

#[derive(Serialize, Deserialize)]
pub struct TimePolicyConfig {
    not_before_time: Option<u64>,
    not_on_or_after_time: Option<u64>,
    year: Option<u64>,
    year_end: Option<u64>,
    month: Option<u64>,
    month_end: Option<u64>,
    day_of_month: Option<u64>,
    day_of_month_end: Option<u64>,
    hour: Option<u64>,
    hour_end: Option<u64>,
    minute: Option<u64>,
    minute_end: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupPolicyConfig {
    group_claim: Option<String>,
    groups: Option<Vec<GroupModel>>,
}
