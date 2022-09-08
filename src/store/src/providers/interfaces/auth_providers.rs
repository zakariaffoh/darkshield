use std::collections::HashMap;

use async_trait::async_trait;
use models::entities::auth::{
    AuthenticationExecutionModel, AuthenticationFlowModel, AuthenticatorConfigModel,
    RequiredActionEnum, RequiredActionModel,
};
use shaku::Interface;

#[async_trait]
pub trait IRequiredActionProvider: Interface {
    async fn register_required_action(&self, action: &RequiredActionModel) -> Result<(), String>;

    async fn update_required_action(&self, action: &RequiredActionModel) -> Result<(), String>;

    async fn update_required_action_priority(
        &self,
        realm_id: &str,
        priority_map: &HashMap<String, String>,
    ) -> Result<bool, String>;

    async fn remove_required_action(&self, realm_id: &str, action_id: &str)
        -> Result<bool, String>;

    async fn load_required_action_by_action_id(
        &self,
        realm_id: &str,
        action_id: &str,
    ) -> Result<Option<RequiredActionModel>, String>;

    async fn load_required_actions_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<RequiredActionModel>, String>;

    async fn load_required_actions_by_action_list(
        &self,
        realm_id: &str,
        actions: &Vec<RequiredActionEnum>,
    ) -> Result<Vec<RequiredActionModel>, String>;

    async fn load_required_action_by_action(
        &self,
        realm_id: &str,
        action: &RequiredActionEnum,
    ) -> Result<Option<RequiredActionModel>, String>;

    async fn required_action_exists_by_action(
        &self,
        realm_id: &str,
        action: &RequiredActionEnum,
    ) -> Result<bool, String>;
}

#[async_trait]
pub trait IAuthenticationFlowProvider: Interface {
    async fn create_authentication_flow(
        &self,
        flow: &AuthenticationFlowModel,
    ) -> Result<(), String>;

    async fn update_authentication_flow(
        &self,
        flow: &AuthenticationFlowModel,
    ) -> Result<(), String>;

    async fn load_authentication_flow_by_flow_id(
        &self,
        realm_id: &str,
        flow_id: &str,
    ) -> Result<Option<AuthenticationFlowModel>, String>;

    async fn load_authentication_flow_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<AuthenticationFlowModel>, String>;

    async fn remove_authentication_flow(
        &self,
        realm_id: &str,
        flow_id: &str,
    ) -> Result<bool, String>;

    async fn exists_flow_by_alias(&self, realm_id: &str, alias: &str) -> Result<bool, String>;
}

#[async_trait]
pub trait IAuthenticationExecutionProvider: Interface {
    async fn create_authentication_execution(
        &self,
        execution: &AuthenticationExecutionModel,
    ) -> Result<(), String>;
    async fn update_authentication_execution(
        &self,
        execution: &AuthenticationExecutionModel,
    ) -> Result<(), String>;
    async fn load_authentication_execution_by_execution_id(
        &self,
        realm_id: &str,
        execution_id: &str,
    ) -> Result<Option<AuthenticationExecutionModel>, String>;
    async fn load_authentication_execution_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<AuthenticationExecutionModel>, String>;
    async fn remove_authentication_execution(
        &self,
        realm_id: &str,
        execution_id: &str,
    ) -> Result<bool, String>;

    async fn exists_execution_by_alias(&self, realm_id: &str, alias: &str) -> Result<bool, String>;
}

#[async_trait]
pub trait IAuthenticatorConfigProvider: Interface {
    async fn create_authenticator_config(
        &self,
        config: &AuthenticatorConfigModel,
    ) -> Result<(), String>;
    async fn update_authenticator_config(
        &self,
        config: &AuthenticatorConfigModel,
    ) -> Result<(), String>;
    async fn load_authenticator_config_by_config_id(
        &self,
        realm_id: &str,
        config_id: &str,
    ) -> Result<Option<AuthenticatorConfigModel>, String>;
    async fn load_authenticator_configs_by_realm(
        &self,
        realm_id: &str,
    ) -> Result<Vec<AuthenticatorConfigModel>, String>;
    async fn remove_authenticator_config(
        &self,
        realm_id: &str,
        config_id: &str,
    ) -> Result<bool, String>;

    async fn exists_config_by_alias(&self, realm_id: &str, alias: &str) -> Result<bool, String>;
}
