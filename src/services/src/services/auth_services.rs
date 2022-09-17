use async_trait::async_trait;
use commons::ApiResult;
use log;
use models::auditable::AuditableModel;
use models::entities::auth::AuthenticationExecutionModel;
use models::entities::auth::AuthenticationFlowModel;
use models::entities::auth::AuthenticatorConfigModel;
use models::entities::auth::{RequiredActionEnum, RequiredActionModel};
use shaku::Component;
use shaku::Interface;
use std::sync::Arc;
use store::providers::interfaces::auth_providers::IAuthenticationExecutionProvider;
use store::providers::interfaces::auth_providers::IAuthenticationFlowProvider;
use store::providers::interfaces::auth_providers::IAuthenticatorConfigProvider;
use store::providers::interfaces::auth_providers::IRequiredActionProvider;
use uuid;

#[async_trait]
pub trait IRequiredActionService: Interface {
    async fn register_required_action(&self, action: &RequiredActionModel) -> Result<(), String>;

    async fn update_required_action(&self, action: &RequiredActionModel) -> Result<(), String>;

    async fn update_required_action_priority(
        &self,
        realm_id: &str,
        action: &RequiredActionEnum,
        priority: i32,
    ) -> Result<(), String>;

    async fn load_required_action(
        &self,
        realm_id: &str,
        action_id: &str,
    ) -> Result<Option<RequiredActionModel>, String>;

    async fn load_required_action_by_realm_id(
        &self,
        realm_id: &str,
    ) -> Result<Vec<RequiredActionModel>, String>;

    async fn remove_required_action(&self, realm_id: &str, action_id: &str)
        -> Result<bool, String>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRequiredActionService)]
pub struct RequiredActionService {
    #[shaku(inject)]
    required_action_provider: Arc<dyn IRequiredActionProvider>,
}

#[async_trait]
impl IRequiredActionService for RequiredActionService {
    async fn register_required_action(&self, action: &RequiredActionModel) -> Result<(), String> {
        self.required_action_provider
            .register_required_action(&action)
            .await
    }

    async fn update_required_action(&self, action: &RequiredActionModel) -> Result<(), String> {
        self.required_action_provider
            .update_required_action(&action)
            .await
    }

    async fn update_required_action_priority(
        &self,
        _realm_id: &str,
        _action: &RequiredActionEnum,
        _priority: i32,
    ) -> Result<(), String> {
        /*let realm_actions = self.load_required_action_by_realm_id(&realm_id).await;
        let mut actions = match realm_actions {
            ApiResult::Data(res) => res,
            ApiResult::Error(_) => Vec::new()
        };
        let current_actions: Vec<RequiredActionModel> = actions.iter().filter(|ac| ac.action == *action).collect();

        if current_actions.len() != 1{

        }
        let current_action = current_actions[0];
        actions.sort_by_key(|ac1| ac1.priority.unwrap());
        let mut action_by_priority = HashMap::new();

        for action in actions.iter(){
            if action.priority.unwrap() <= 1{
                action_by_priority.insert(action.action, action.priority.unwrap() - 1);
            }
            else if action.action == current_action.action {
                action_by_priority.insert(action.action, action.priority.unwrap() + 1);
            }
            else {
                action_by_priority.insert(action.action, action.priority.unwrap());
            }
        }*/
        Ok(())
    }

    async fn load_required_action(
        &self,
        realm_id: &str,
        action_id: &str,
    ) -> Result<Option<RequiredActionModel>, String> {
        self.required_action_provider
            .load_required_action_by_action_id(&realm_id, &action_id)
            .await
    }

    async fn load_required_action_by_realm_id(
        &self,
        realm_id: &str,
    ) -> Result<Vec<RequiredActionModel>, String> {
        self.required_action_provider
            .load_required_actions_by_realm(&realm_id)
            .await
    }

    async fn remove_required_action(
        &self,
        realm_id: &str,
        action_id: &str,
    ) -> Result<bool, String> {
        self.required_action_provider
            .remove_required_action(&realm_id, &action_id)
            .await
    }
}

#[async_trait]
pub trait IAuthenticationFlowService: Interface {
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
    async fn load_authentication_flow_by_realm_id(
        &self,
        realm_id: &str,
    ) -> Result<Vec<AuthenticationFlowModel>, String>;
    async fn exists_flow_by_alias(&self, realm_id: &str, alias: &str) -> Result<bool, String>;

    async fn remove_authentication_flow(
        &self,
        realm_id: &str,
        flow_id: &str,
    ) -> Result<bool, String>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IAuthenticationFlowService)]
pub struct AuthenticationFlowService {
    #[shaku(inject)]
    authentication_flow_provider: Arc<dyn IAuthenticationFlowProvider>,
}

#[async_trait]
impl IAuthenticationFlowService for AuthenticationFlowService {
    async fn create_authentication_flow(
        &self,
        flow: &AuthenticationFlowModel,
    ) -> Result<(), String> {
        self.authentication_flow_provider
            .create_authentication_flow(&flow)
            .await
    }

    async fn update_authentication_flow(
        &self,
        flow: &AuthenticationFlowModel,
    ) -> Result<(), String> {
        self.authentication_flow_provider
            .update_authentication_flow(&flow)
            .await
    }

    async fn load_authentication_flow_by_flow_id(
        &self,
        realm_id: &str,
        flow_id: &str,
    ) -> Result<Option<AuthenticationFlowModel>, String> {
        self.authentication_flow_provider
            .load_authentication_flow_by_flow_id(&realm_id, &flow_id)
            .await
    }

    async fn load_authentication_flow_by_realm_id(
        &self,
        realm_id: &str,
    ) -> Result<Vec<AuthenticationFlowModel>, String> {
        self.authentication_flow_provider
            .load_authentication_flow_by_realm(&realm_id)
            .await
    }

    async fn exists_flow_by_alias(&self, realm_id: &str, alias: &str) -> Result<bool, String> {
        self.authentication_flow_provider
            .exists_flow_by_alias(&realm_id, &alias)
            .await
    }

    async fn remove_authentication_flow(
        &self,
        realm_id: &str,
        flow_id: &str,
    ) -> Result<bool, String> {
        self.authentication_flow_provider
            .remove_authentication_flow(&realm_id, &flow_id)
            .await
    }
}

#[async_trait]
pub trait IAuthenticationExecutionService: Interface {
    async fn create_authentication_execution(
        &self,
        execution: &AuthenticationExecutionModel,
    ) -> Result<(), String>;
    async fn update_authentication_execution(
        &self,
        execution: &AuthenticationExecutionModel,
    ) -> Result<(), String>;
    async fn load_authentication_execution(
        &self,
        realm_id: &str,
        execution_id: &str,
    ) -> Result<Option<AuthenticationExecutionModel>, String>;
    async fn load_authentication_execution_by_realm_id(
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

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IAuthenticationExecutionService)]
pub struct AuthenticationExecutionService {
    #[shaku(inject)]
    authentication_execution_provider: Arc<dyn IAuthenticationExecutionProvider>,
}

#[async_trait]
impl IAuthenticationExecutionService for AuthenticationExecutionService {
    async fn create_authentication_execution(
        &self,
        execution: &AuthenticationExecutionModel,
    ) -> Result<(), String> {
        self.authentication_execution_provider
            .create_authentication_execution(&execution)
            .await
    }

    async fn update_authentication_execution(
        &self,
        execution: &AuthenticationExecutionModel,
    ) -> Result<(), String> {
        self.authentication_execution_provider
            .update_authentication_execution(&execution)
            .await
    }

    async fn load_authentication_execution(
        &self,
        realm_id: &str,
        execution_id: &str,
    ) -> Result<Option<AuthenticationExecutionModel>, String> {
        self.authentication_execution_provider
            .load_authentication_execution_by_execution_id(&realm_id, &execution_id)
            .await
    }

    async fn load_authentication_execution_by_realm_id(
        &self,
        realm_id: &str,
    ) -> Result<Vec<AuthenticationExecutionModel>, String> {
        self.authentication_execution_provider
            .load_authentication_execution_by_realm(&realm_id)
            .await
    }

    async fn remove_authentication_execution(
        &self,
        realm_id: &str,
        execution_id: &str,
    ) -> Result<bool, String> {
        self.authentication_execution_provider
            .remove_authentication_execution(&realm_id, &execution_id)
            .await
    }

    async fn exists_execution_by_alias(&self, realm_id: &str, alias: &str) -> Result<bool, String> {
        self.authentication_execution_provider
            .exists_execution_by_alias(&realm_id, &alias)
            .await
    }
}

#[async_trait]
pub trait IAuthenticatorConfigService: Interface {
    async fn create_authenticator_config(
        &self,
        config: &AuthenticatorConfigModel,
    ) -> Result<(), String>;

    async fn update_authenticator_config(
        &self,
        config: &AuthenticatorConfigModel,
    ) -> Result<(), String>;

    async fn load_authenticator_config(
        &self,
        realm_id: &str,
        config_id: &str,
    ) -> Result<Option<AuthenticatorConfigModel>, String>;

    async fn load_authenticator_config_by_realm_id(
        &self,
        realm_id: &str,
    ) -> Result<Vec<AuthenticatorConfigModel>, String>;

    async fn exists_config_by_alias(&self, realm_id: &str, alias: &str) -> Result<bool, String>;

    async fn remove_authenticator_config(
        &self,
        realm_id: &str,
        config_id: &str,
    ) -> Result<bool, String>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IAuthenticatorConfigService)]
pub struct AuthenticatorConfigService {
    #[shaku(inject)]
    authenticator_config_provider: Arc<dyn IAuthenticatorConfigProvider>,
}

#[async_trait]
impl IAuthenticatorConfigService for AuthenticatorConfigService {
    async fn create_authenticator_config(
        &self,
        config: &AuthenticatorConfigModel,
    ) -> Result<(), String> {
        self.authenticator_config_provider
            .create_authenticator_config(&config)
            .await
    }

    async fn update_authenticator_config(
        &self,
        config: &AuthenticatorConfigModel,
    ) -> Result<(), String> {
        self.authenticator_config_provider
            .update_authenticator_config(&config)
            .await
    }

    async fn load_authenticator_config(
        &self,
        realm_id: &str,
        config_id: &str,
    ) -> Result<Option<AuthenticatorConfigModel>, String> {
        self.authenticator_config_provider
            .load_authenticator_config_by_config_id(&realm_id, &config_id)
            .await
    }

    async fn load_authenticator_config_by_realm_id(
        &self,
        realm_id: &str,
    ) -> Result<Vec<AuthenticatorConfigModel>, String> {
        self.authenticator_config_provider
            .load_authenticator_configs_by_realm(&realm_id)
            .await
    }

    async fn exists_config_by_alias(&self, realm_id: &str, alias: &str) -> Result<bool, String> {
        self.authenticator_config_provider
            .exists_config_by_alias(&realm_id, &alias)
            .await
    }

    async fn remove_authenticator_config(
        &self,
        realm_id: &str,
        config_id: &str,
    ) -> Result<bool, String> {
        self.authenticator_config_provider
            .remove_authenticator_config(&realm_id, &config_id)
            .await
    }
}
