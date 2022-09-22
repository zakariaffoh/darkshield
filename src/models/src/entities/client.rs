use super::attributes::AttributesMap;
use super::authz::RoleModel;
use crate::auditable::AuditableModel;
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, ToSql, FromSql, PartialEq)]
#[postgres(name = "protocolenum")]
pub enum ProtocolEnum {
    #[serde(alias = "openid-connect")]
    #[postgres(name = "openid-connect")]
    OpendId,

    #[serde(alias = "docker")]
    #[postgres(name = "docker")]
    Docker,
}

impl FromStr for ProtocolEnum {
    type Err = String;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "openid-connect" => Ok(ProtocolEnum::OpendId),
            _ => Err(format!("unsupported enum type: {0}", input)),
        }
    }
}
impl ToString for ProtocolEnum {
    fn to_string(&self) -> String {
        match &self {
            ProtocolEnum::OpendId => "openid-connect".to_owned(),
            _ => String::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientModel {
    pub client_id: String,
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
    pub consent_required: Option<bool>,
    pub root_url: Option<String>,
    pub web_origins: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub registration_token: Option<String>,
    pub secret: Option<String>,

    pub protocol: Option<ProtocolEnum>,
    pub public_client: Option<bool>,
    pub client_authenticator_type: Option<String>,
    pub full_scope_allowed: Option<bool>,
    pub authorization_code_flow_enabled: Option<bool>,
    pub implicit_flow_enabled: Option<bool>,
    pub direct_access_grants_enabled: Option<bool>,
    pub standard_flow_enabled: Option<bool>,
    pub bearer_only: Option<bool>,
    pub front_channel_logout: Option<bool>,
    pub is_surrogate_auth_required: Option<bool>,
    pub not_before: Option<i32>,
    pub configs: Option<AttributesMap>,
    pub service_account_enabled: Option<bool>,
    pub auth_flow_binding_overrides: Option<AttributesMap>,
    pub metadata: Option<AuditableModel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientCreateModel {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,
}

impl Into<ClientModel> for ClientCreateModel {
    fn into(self) -> ClientModel {
        ClientModel {
            client_id: String::new(),
            realm_id: String::new(),
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            enabled: self.enabled,
            consent_required: None,
            root_url: None,
            web_origins: None,
            redirect_uris: None,
            registration_token: None,
            secret: None,
            protocol: None,
            public_client: None,
            client_authenticator_type: None,
            full_scope_allowed: None,
            authorization_code_flow_enabled: None,
            implicit_flow_enabled: None,
            direct_access_grants_enabled: None,
            standard_flow_enabled: None,
            bearer_only: None,
            front_channel_logout: None,
            is_surrogate_auth_required: None,
            not_before: None,
            configs: None,
            service_account_enabled: None,
            auth_flow_binding_overrides: None,
            metadata: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientUpdateModel {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub enabled: Option<bool>,

    pub consent_required: Option<bool>,
    pub root_url: Option<String>,
    pub web_origins: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub registration_token: Option<String>,
    pub secret: Option<String>,

    pub protocol: Option<ProtocolEnum>,
    pub public_client: Option<bool>,
    pub client_authenticator_type: Option<String>,
    pub full_scope_allowed: Option<bool>,
    pub authorization_code_flow_enabled: Option<bool>,
    pub implicit_flow_enabled: Option<bool>,
    pub direct_access_grants_enabled: Option<bool>,
    pub standard_flow_enabled: Option<bool>,
    pub bearer_only: Option<bool>,
    pub front_channel_logout: Option<bool>,
    pub is_surrogate_auth_required: Option<bool>,
    pub not_before: Option<i32>,
    pub configs: Option<AttributesMap>,
    pub service_account_enabled: Option<bool>,
    pub auth_flow_binding_overrides: Option<AttributesMap>,
    pub metadata: Option<AuditableModel>,
}

impl Into<ClientModel> for ClientUpdateModel {
    fn into(self) -> ClientModel {
        ClientModel {
            client_id: String::new(),
            realm_id: String::new(),
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            enabled: self.enabled,
            consent_required: self.consent_required,
            root_url: self.root_url,
            web_origins: self.web_origins,
            redirect_uris: self.redirect_uris,
            registration_token: self.registration_token,
            secret: self.secret,

            protocol: self.protocol,
            public_client: self.public_client,
            client_authenticator_type: self.client_authenticator_type,
            full_scope_allowed: self.full_scope_allowed,
            authorization_code_flow_enabled: self.authorization_code_flow_enabled,
            implicit_flow_enabled: self.implicit_flow_enabled,
            direct_access_grants_enabled: self.direct_access_grants_enabled,
            standard_flow_enabled: self.standard_flow_enabled,
            bearer_only: self.bearer_only,
            front_channel_logout: self.front_channel_logout,
            is_surrogate_auth_required: self.is_surrogate_auth_required,
            not_before: self.not_before,
            configs: self.configs,
            service_account_enabled: self.service_account_enabled,
            auth_flow_binding_overrides: self.auth_flow_binding_overrides,
            metadata: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientScopeModel {
    pub client_scope_id: String,
    pub realm_id: String,
    pub name: String,
    pub description: String,
    pub protocol: ProtocolEnum,
    pub roles: Option<Vec<RoleModel>>,
    pub protocol_mappers: Option<Vec<ProtocolMapperModel>>,
    pub default_scope: Option<bool>,
    pub configs: Option<HashMap<String, Option<String>>>,
    pub metadata: Option<AuditableModel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientScopeMutationModel {
    pub name: String,
    pub description: String,
    pub protocol: ProtocolEnum,
    pub default_scope: Option<bool>,
    pub configs: Option<HashMap<String, Option<String>>>,
}

impl Into<ClientScopeModel> for ClientScopeMutationModel {
    fn into(self) -> ClientScopeModel {
        ClientScopeModel {
            client_scope_id: String::new(),
            realm_id: String::new(),
            name: self.name,
            description: self.description,
            protocol: self.protocol,
            roles: None,
            protocol_mappers: None,
            default_scope: self.default_scope,
            configs: self.configs,
            metadata: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtocolMapperModel {
    pub mapper_id: String,
    pub realm_id: String,
    pub name: String,
    pub protocol: ProtocolEnum,
    pub mapper_type: String,
    pub configs: Option<AttributesMap>,
    pub metadata: Option<AuditableModel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtocolMapperMutationModel {
    pub name: String,
    pub protocol: ProtocolEnum,
    pub mapper_type: String,
    pub configs: Option<AttributesMap>,
}

impl Into<ProtocolMapperModel> for ProtocolMapperMutationModel {
    fn into(self) -> ProtocolMapperModel {
        ProtocolMapperModel {
            mapper_id: String::new(),
            realm_id: String::new(),
            name: self.name,
            protocol: self.protocol,
            mapper_type: self.mapper_type,
            configs: self.configs,
            metadata: None,
        }
    }
}
