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
    pub policy_type: PolicyTypeEnum,
    pub policy_id: String,
    pub server_id: String,
    pub realm_id: String,
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategyEnum,
    pub logic: DecisionLogicEnum,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    pub policies: Option<Vec<PolicyModel>>,
    pub resources: Option<Vec<ResourceModel>>,
    pub scopes: Option<Vec<ScopeModel>>,
    pub roles: Option<Vec<RoleModel>>,
    pub groups: Option<GroupPolicyConfig>,
    pub regex: Option<RegexConfig>,
    pub time: Option<TimePolicyConfig>,
    pub users: Option<Vec<UserModel>>,
    pub script: Option<String>,
    pub client_scopes: Option<Vec<ClientScopeModel>>,
    pub resource_type: Option<String>,
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
    pub target_claim: String,
    pub target_regex: String,
}

#[derive(Serialize, Deserialize)]
pub struct TimePolicyConfig {
    pub not_before_time: Option<u64>,
    pub not_on_or_after_time: Option<u64>,
    pub year: Option<u64>,
    pub year_end: Option<u64>,
    pub month: Option<u64>,
    pub month_end: Option<u64>,
    pub day_of_month: Option<u64>,
    pub day_of_month_end: Option<u64>,
    pub hour: Option<u64>,
    pub hour_end: Option<u64>,
    pub minute: Option<u64>,
    pub minute_end: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupPolicyConfig {
    pub group_claim: Option<String>,
    pub groups: Option<Vec<GroupModel>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupPolicyRepresentation {
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategyEnum,
    pub logic: DecisionLogicEnum,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    pub policies: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub group_claim: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RolePolicyRepresentation {
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategyEnum,
    pub logic: DecisionLogicEnum,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    pub policies: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserPolicyRepresentation {
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategyEnum,
    pub logic: DecisionLogicEnum,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    pub policies: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub users: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PyPolicyRepresentation {
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategyEnum,
    pub logic: DecisionLogicEnum,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    pub policies: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub script: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TimePolicyRepresentation {
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategyEnum,
    pub logic: DecisionLogicEnum,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    pub policies: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub not_before_time: Option<u64>,
    pub not_on_or_after_time: Option<u64>,
    pub year: Option<u64>,
    pub year_end: Option<u64>,
    pub month: Option<u64>,
    pub month_end: Option<u64>,
    pub day_of_month: Option<u64>,
    pub day_of_month_end: Option<u64>,
    pub hour: Option<u64>,
    pub hour_end: Option<u64>,
    pub minute: Option<u64>,
    pub minute_end: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegexPolicyRepresentation {
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategyEnum,
    pub logic: DecisionLogicEnum,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    pub policies: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub target_claim: String,
    pub target_regex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AggregatedPoliciesRepresentation {
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategyEnum,
    pub logic: DecisionLogicEnum,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    pub policies: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientPolicyRepresentation {
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategyEnum,
    pub logic: DecisionLogicEnum,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    pub policies: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub clients: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientScopePolicyRepresentation {
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategyEnum,
    pub logic: DecisionLogicEnum,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    pub policies: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub client_scopes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScopePermissionPolicyRepresentation {
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategyEnum,
    pub logic: DecisionLogicEnum,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    pub policies: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub resource_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourcePermissionPolicyRepresentation {
    pub name: String,
    pub description: String,
    pub decision: DecisionStrategyEnum,
    pub logic: DecisionLogicEnum,
    pub policy_owner: String,
    pub configs: Option<BTreeMap<String, String>>,
    pub policies: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub resource_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PolicyRepresentation {
    #[serde(rename = "group_policy")]
    GroupPolicy(GroupPolicyRepresentation),
    #[serde(rename = "role_policy")]
    RolePolicy(RolePolicyRepresentation),
    #[serde(rename = "user_policy")]
    UserPolicy(UserPolicyRepresentation),
    #[serde(rename = "py_policy")]
    PyPolicy(PyPolicyRepresentation),
    #[serde(rename = "time_policy")]
    TimePolicy(TimePolicyRepresentation),
    #[serde(rename = "regex_policy")]
    RegexPolicy(RegexPolicyRepresentation),
    #[serde(rename = "aggregated_policy")]
    AggregatedPolicy(AggregatedPoliciesRepresentation),
    #[serde(rename = "client_policy")]
    ClientPolicy(ClientPolicyRepresentation),
    #[serde(rename = "client_scope_policy")]
    ClientScopePolicy(ClientScopePolicyRepresentation),
    #[serde(rename = "scope_permission_policy")]
    ScopePermissionPolicy(ScopePermissionPolicyRepresentation),
    #[serde(rename = "resource_permission_policy")]
    ResourcePermissionPolicy(ResourcePermissionPolicyRepresentation),
}
