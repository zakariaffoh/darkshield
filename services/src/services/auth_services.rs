use log;
use models::entities::auth::AuthenticationExecutionModel;
use models::entities::auth::AuthenticatorConfigModel;
use store::providers::interfaces::auth_providers::IAuthenticationExecutionProvider;
use store::providers::interfaces::auth_providers::IAuthenticatorConfigProvider;
use std::sync::Arc;
use shaku::Component;
use shaku::Interface;
use async_trait::async_trait;
use commons::api_result::ApiResult;
use models::auditable::AuditableModel;
use models::entities::auth::AuthenticationFlowModel;
use models::entities::auth::{RequiredActionModel, RequiredActionEnum};
use store::providers::interfaces::auth_providers::IRequiredActionProvider;
use store::providers::interfaces::auth_providers::IAuthenticationFlowProvider;


#[async_trait]
pub trait IRequiredActionService: Interface {
    async fn register_required_action(&self, action: RequiredActionModel) -> ApiResult<RequiredActionModel>;
    async fn update_required_action(&self, action: RequiredActionModel) -> ApiResult<()>;
    async fn update_required_action_priority(&self, realm_id: &str, action: &RequiredActionEnum, priority: i32) -> ApiResult<()>;
    async fn load_required_action(&self, realm_id: &str, action_id:&str) -> ApiResult<Option<RequiredActionModel>>;
    async fn load_required_action_by_realm_id(&self, realm_id: &str) -> ApiResult<Vec<RequiredActionModel>>;
    async fn remove_required_action(&self, realm_id: &str, action_id: &str) -> ApiResult<()>;
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
    async fn register_required_action(&self, action: RequiredActionModel) -> ApiResult<RequiredActionModel> {
        let existing_action = self.required_action_provider.load_required_action_by_action(&action.realm_id, &action.action).await;
        if let Ok(response) = existing_action {
            if response.is_some() {
                log::error!("required action: {} already exists in realm: {}", &action.action, &action.realm_id);
                return ApiResult::from_error(409, "500", "required action already exists");
            }
        }
        let mut action = action;
        action.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_action = self.required_action_provider.register_required_action(&action).await;
        match created_action {
            Ok(_) => ApiResult::Data(action),
            Err(_) => ApiResult::from_error(500, "500", "failed to required action"),
        }
    }
    
    async fn update_required_action(&self, action: RequiredActionModel) -> ApiResult<()>{
        let existing_action = self.required_action_provider.load_required_action_by_action_id(&action.realm_id, &action.action_id).await;
        if let Ok(response) = existing_action {
            if response.is_none() {
                log::error!("required action: {} not found in realm: {}", &action.name, &action.realm_id);
                return ApiResult::from_error(404, "404", "action not found");
            }
        }
        let mut action = action;
        action.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_action = self.required_action_provider.update_required_action(&action).await;
        match updated_action {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to update role"),
        }
    }
    
    async fn update_required_action_priority(&self, _realm_id: &str, _action: &RequiredActionEnum, _priority: i32) -> ApiResult<()>{
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
        ApiResult::Data(())
    }

    async fn load_required_action(&self, realm_id: &str, action_id:&str) -> ApiResult<Option<RequiredActionModel>>{
        let loaded_action = self.required_action_provider.load_required_action_by_action_id(&realm_id, &action_id).await;
        match loaded_action {
            Ok(action) => ApiResult::from_data(action),
            Err(err) => ApiResult::from_error(500, "500", &err)
        }  
    }

    async fn load_required_action_by_realm_id(&self, realm_id: &str) -> ApiResult<Vec<RequiredActionModel>>{
        let loaded_actions = self.required_action_provider.load_required_actions_by_realm(&realm_id).await;
        match loaded_actions {
            Ok(actions) => {
                log::info!("[{}] required actions loaded for realm: {}", actions.len(), &realm_id);
                ApiResult::from_data(actions)
            }
            Err(err) => {
                log::error!("Failed to load required actions from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    async fn remove_required_action(&self, realm_id: &str, action_id: &str) -> ApiResult<()>{
        let existing_action = self.required_action_provider.load_required_action_by_action_id(&realm_id, &action_id).await;
        if let Ok(response) = existing_action {
            if response.is_none() {
                log::error!("required action: {} not found in realm: {}", &action_id, &realm_id);
                return ApiResult::from_error(404, "404", "required action not found");
            }
        }
        let result = self.required_action_provider.remove_required_action(&realm_id, &action_id).await;
        match result {
            Ok(res) => {
                if res {
                    ApiResult::Data(())
                }
                else {
                    ApiResult::from_error(500, "500", "failed to delete required action")
                }
            },
            Err(_) => ApiResult::from_error(500, "500", "server internal error"),
        }
    }
}


#[async_trait]
pub trait IAuthenticationFlowService: Interface {
    async fn create_authentication_flow(&self, flow: AuthenticationFlowModel) -> ApiResult<AuthenticationFlowModel>;
    async fn update_authentication_flow(&self, flow: AuthenticationFlowModel) -> ApiResult<()>;
    async fn load_authentication_flow_by_flow_id(&self, realm_id: &str, flow_id:&str) -> ApiResult<Option<AuthenticationFlowModel>>;
    async fn load_authentication_flow_by_realm_id(&self, realm_id: &str) -> ApiResult<Vec<AuthenticationFlowModel>>;
    async fn remove_authentication_flow(&self, realm_id: &str, flow_id: &str) -> ApiResult<()>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IAuthenticationFlowService)]
pub struct AuthenticationFlowService {
    #[shaku(inject)]
    authentication_flow_provider: Arc<dyn IAuthenticationFlowProvider>,
}

#[async_trait]
impl IAuthenticationFlowService for AuthenticationFlowService{
    async fn create_authentication_flow(&self, flow: AuthenticationFlowModel) -> ApiResult<AuthenticationFlowModel>{
        let existing_flow = self.authentication_flow_provider.exists_flow_by_alias(&flow.realm_id, &flow.alias).await;
        if let Ok(response) = existing_flow {
            if response {
                log::error!("authentication flow: {} already exists in realm: {}", &flow.alias, &flow.realm_id);
                return ApiResult::from_error(409, "500", "authentication flow already exists");
            }
        }
        let mut flow = flow;
        flow.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_flow = self.authentication_flow_provider.create_authentication_flow(&flow).await;
        match created_flow {
            Ok(_) => ApiResult::Data(flow),
            Err(_) => ApiResult::from_error(500, "500", "failed to create authentication flow"),
        }
    }

    async fn update_authentication_flow(&self, flow: AuthenticationFlowModel) -> ApiResult<()>{
        let existing_flow = self.authentication_flow_provider.load_authentication_flow_by_flow_id(&flow.realm_id, &flow.flow_id).await;
        if let Ok(response) = existing_flow {
            if response.is_none() {
                log::error!("authentication flow: {} not found in realm: {}", &flow.alias, &flow.realm_id);
                return ApiResult::from_error(404, "404", "authentication flow not found");
            }
        }
        let mut flow = flow;
        flow.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_flow = self.authentication_flow_provider.update_authentication_flow(&flow).await;
        match updated_flow {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to update authentication flow"),
        }
    }

    async fn load_authentication_flow_by_flow_id(&self, realm_id: &str, flow_id:&str) -> ApiResult<Option<AuthenticationFlowModel>>{
        let loaded_flow = self.authentication_flow_provider.load_authentication_flow_by_flow_id(&realm_id, &flow_id).await;
        match loaded_flow {
            Ok(flow) => ApiResult::from_data(flow),
            Err(err) => ApiResult::from_error(500, "500", &err)
        } 
    }

    async fn load_authentication_flow_by_realm_id(&self, realm_id: &str) -> ApiResult<Vec<AuthenticationFlowModel>>{
        let loaded_flows = self.authentication_flow_provider.load_authentication_flow_by_realm(&realm_id).await;
        match loaded_flows {
            Ok(flows) => {
                log::info!("[{}] authentication flows loaded for realm: {}", flows.len(), &realm_id);
                ApiResult::from_data(flows)
            }
            Err(err) => {
                log::error!("Failed to authentication flow from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    async fn remove_authentication_flow(&self, realm_id: &str, flow_id: &str) -> ApiResult<()>{
        let existing_flow = self.authentication_flow_provider.load_authentication_flow_by_flow_id(&realm_id, &flow_id).await;
        if let Ok(response) = existing_flow {
            if response.is_none() {
                log::error!("authentication flow: {} not found in realm: {}", &flow_id, &realm_id);
                return ApiResult::from_error(404, "404", "authentication flow not found");
            }
        }
        let result = self.authentication_flow_provider.remove_authentication_flow(&realm_id, &flow_id).await;
        match result {
            Ok(res) => {
                if res {
                    ApiResult::Data(())
                }
                else {
                    ApiResult::from_error(500, "500", "failed to delete authentication flow")
                }
            },
            Err(_) => ApiResult::from_error(500, "500", "server internal error"),
        }
    }
}

#[async_trait]
pub trait IAuthenticationExecutionService: Interface {
    async fn create_authentication_execution(&self, execution: AuthenticationExecutionModel) -> ApiResult<AuthenticationExecutionModel>;
    async fn update_authentication_execution(&self, execution: AuthenticationExecutionModel) -> ApiResult<()>;
    async fn load_authentication_execution(&self, realm_id: &str, execution_id:&str) -> ApiResult<Option<AuthenticationExecutionModel>>;
    async fn load_authentication_execution_by_realm_id(&self, realm_id: &str) -> ApiResult<Vec<AuthenticationExecutionModel>>;
    async fn remove_authentication_execution(&self, realm_id: &str, execution_id: &str) -> ApiResult<()>;
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
    async fn create_authentication_execution(&self, execution: AuthenticationExecutionModel) -> ApiResult<AuthenticationExecutionModel>{
        let existing_execution = self.authentication_execution_provider.exists_execution_by_alias(&execution.realm_id, &execution.alias).await;
        if let Ok(response) = existing_execution {
            if response {
                log::error!("authentication execution: {} already exists in realm: {}", &execution.alias, &execution.realm_id);
                return ApiResult::from_error(409, "500", "authentication execution already exists");
            }
        }
        let mut execution = execution;
        execution.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_execution = self.authentication_execution_provider.create_authentication_execution(&execution).await;
        match created_execution {
            Ok(_) => ApiResult::Data(execution),
            Err(_) => ApiResult::from_error(500, "500", "failed to create authentication execution"),
        }
    }

    async fn update_authentication_execution(&self, execution: AuthenticationExecutionModel) -> ApiResult<()>{
        let existing_execution = self.authentication_execution_provider.load_authentication_execution_by_execution_id(&execution.realm_id, &execution.execution_id).await;
        if let Ok(response) = existing_execution {
            if response.is_none() {
                log::error!("authentication execution: {} not found in realm: {}", &execution.alias, &execution.realm_id);
                return ApiResult::from_error(404, "404", "authentication execution not found");
            }
        }
        let mut execution = execution;
        execution.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_execution = self.authentication_execution_provider.update_authentication_execution(&execution).await;
        match updated_execution {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to update authentication execution"),
        }
    }

    async fn load_authentication_execution(&self, realm_id: &str, execution_id:&str) -> ApiResult<Option<AuthenticationExecutionModel>>{
        let loaded_execution = self.authentication_execution_provider.load_authentication_execution_by_execution_id(&realm_id, &execution_id).await;
        match loaded_execution {
            Ok(execution) => ApiResult::from_data(execution),
            Err(err) => ApiResult::from_error(500, "500", &err)
        } 
    }

    async fn load_authentication_execution_by_realm_id(&self, realm_id: &str) -> ApiResult<Vec<AuthenticationExecutionModel>>{
        let loaded_executions = self.authentication_execution_provider.load_authentication_execution_by_realm(&realm_id, ).await;
        match loaded_executions {
            Ok(flows) => {
                log::info!("[{}] authentication executions loaded for realm: {}", flows.len(), &realm_id);
                ApiResult::from_data(flows)
            }
            Err(err) => {
                log::error!("Failed to authentication executions from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    async fn remove_authentication_execution(&self, realm_id: &str, execution_id: &str) -> ApiResult<()>{
        let existing_execution = self.authentication_execution_provider.load_authentication_execution_by_execution_id(&realm_id, &execution_id).await;
        if let Ok(response) = existing_execution {
            if response.is_none() {
                log::error!("authentication execution: {} not found in realm: {}", &execution_id, &realm_id);
                return ApiResult::from_error(404, "404", "authentication execution not found");
            }
        }
        let result = self.authentication_execution_provider.remove_authentication_execution(&realm_id, &execution_id).await;
        match result {
            Ok(res) => {
                if res {
                    ApiResult::Data(())
                }
                else {
                    ApiResult::from_error(500, "500", "failed to delete authentication execution")
                }
            },
            Err(_) => ApiResult::from_error(500, "500", "server internal error"),
        }
    }
}


#[async_trait]
pub trait IAuthenticatorConfigService: Interface {
    async fn create_authenticator_config(&self, config: AuthenticatorConfigModel) -> ApiResult<AuthenticatorConfigModel>;
    async fn update_authenticator_config(&self, config: AuthenticatorConfigModel) -> ApiResult<()>;
    async fn load_authenticator_config(&self, realm_id: &str, config_id:&str) -> ApiResult<Option<AuthenticatorConfigModel>>;
    async fn load_authenticator_config_by_realm_id(&self, realm_id: &str) -> ApiResult<Vec<AuthenticatorConfigModel>>;
    async fn remove_authenticator_config(&self, realm_id: &str, config_id: &str) -> ApiResult<()>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IAuthenticatorConfigService)]
pub struct AuthenticatorConfigService {
    #[shaku(inject)]
    authenticator_config_provider: Arc<dyn IAuthenticatorConfigProvider>,
}

#[async_trait]
impl IAuthenticatorConfigService for AuthenticatorConfigService{
    async fn create_authenticator_config(&self, config: AuthenticatorConfigModel) -> ApiResult<AuthenticatorConfigModel>{
        let existing_config = self.authenticator_config_provider.exists_config_by_alias(&config.realm_id, &config.alias).await;
        if let Ok(response) = existing_config {
            if response {
                log::error!("authentication config: {} already exists in realm: {}", &config.alias, &config.realm_id);
                return ApiResult::from_error(409, "500", "authentication config already exists");
            }
        }
        let mut config = config;
        config.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_config = self.authenticator_config_provider.create_authenticator_config(&config).await;
        match created_config {
            Ok(_) => ApiResult::Data(config),
            Err(_) => ApiResult::from_error(500, "500", "failed to create authentication config"),
        }
    }

    async fn update_authenticator_config(&self, config: AuthenticatorConfigModel) -> ApiResult<()>{
        let existing_config = self.authenticator_config_provider.load_authenticator_config_by_config_id(&config.realm_id, &config.config_id).await;
        if let Ok(response) = existing_config {
            if response.is_none() {
                log::error!("authentication config: {} not found in realm: {}", &config.alias, &config.realm_id);
                return ApiResult::from_error(404, "404", "authentication config not found");
            }
        }
        let mut config = config;
        config.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_config = self.authenticator_config_provider.update_authenticator_config(&config).await;
        match updated_config {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to update authentication config"),
        }
    }

    async fn load_authenticator_config(&self, realm_id: &str, config_id:&str) -> ApiResult<Option<AuthenticatorConfigModel>>{
        let loaded_execution = self.authenticator_config_provider.load_authenticator_config_by_config_id(&realm_id, &config_id).await;
        match loaded_execution {
            Ok(execution) => ApiResult::from_data(execution),
            Err(err) => ApiResult::from_error(500, "500", &err)
        } 
    }
    
    async fn load_authenticator_config_by_realm_id(&self, realm_id: &str) -> ApiResult<Vec<AuthenticatorConfigModel>>{
        let loaded_configs = self.authenticator_config_provider.load_authenticator_configs_by_realm(&realm_id).await;
        match loaded_configs {
            Ok(flows) => {
                log::info!("[{}] authentication config loaded for realm: {}", flows.len(), &realm_id);
                ApiResult::from_data(flows)
            }
            Err(err) => {
                log::error!("Failed to load authentication config from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }
    
    async fn remove_authenticator_config(&self, realm_id: &str, config_id: &str) -> ApiResult<()>{
        let existing_config = self.authenticator_config_provider.load_authenticator_config_by_config_id(&realm_id, &config_id).await;
        if let Ok(response) = existing_config {
            if response.is_none() {
                log::error!("authentication config: {} not found in realm: {}", &config_id, &realm_id);
                return ApiResult::from_error(404, "404", "authentication config not found");
            }
        }
        let result = self.authenticator_config_provider.remove_authenticator_config(&realm_id, &config_id).await;
        match result {
            Ok(res) => {
                if res {
                    ApiResult::Data(())
                }
                else {
                    ApiResult::from_error(500, "500", "failed to delete authentication config")
                }
            },
            Err(_) => ApiResult::from_error(500, "500", "server internal error"),
        }
    }
}