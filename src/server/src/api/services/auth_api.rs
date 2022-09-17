use crate::context::DarkShieldContext;
use commons::ApiResult;
use log;
use uuid;

use models::{
    auditable::AuditableModel,
    entities::auth::{
        AuthenticationExecutionModel, AuthenticationFlowModel, AuthenticatorConfigModel,
        RequiredActionEnum, RequiredActionModel,
    },
};
use services::services::auth_services::{
    IAuthenticationExecutionService, IAuthenticationFlowService, IAuthenticatorConfigService,
    IRequiredActionService,
};
use shaku::HasComponent;
pub struct AuthenticationModelApi;

impl AuthenticationModelApi {
    pub async fn create_authentication_execution(
        context: &DarkShieldContext,
        execution: AuthenticationExecutionModel,
    ) -> ApiResult<AuthenticationExecutionModel> {
        let authentication_execution_service: &dyn IAuthenticationExecutionService =
            context.services().resolve_ref();

        let existing_execution = authentication_execution_service
            .exists_execution_by_alias(&execution.realm_id, &execution.alias)
            .await;
        if let Ok(response) = existing_execution {
            if response {
                log::error!(
                    "authentication execution: {} already exists in realm: {}",
                    &execution.alias,
                    &execution.realm_id
                );
                return ApiResult::from_error(
                    409,
                    "500",
                    "authentication execution already exists",
                );
            }
        }
        let mut execution = execution;
        execution.execution_id = uuid::Uuid::new_v4().to_string();
        execution.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_execution = authentication_execution_service
            .create_authentication_execution(&execution)
            .await;
        match created_execution {
            Ok(_) => ApiResult::Data(execution),
            _ => ApiResult::from_error(500, "500", "failed to create authentication execution"),
        }
    }

    pub async fn update_authentication_execution(
        context: &DarkShieldContext,
        execution: AuthenticationExecutionModel,
    ) -> ApiResult<()> {
        let authentication_execution_service: &dyn IAuthenticationExecutionService =
            context.services().resolve_ref();

        let existing_execution = authentication_execution_service
            .load_authentication_execution(&execution.realm_id, &execution.execution_id)
            .await;
        if let Ok(response) = existing_execution {
            if response.is_none() {
                log::error!(
                    "authentication execution: {} not found in realm: {}",
                    &execution.alias,
                    &execution.realm_id
                );
                return ApiResult::from_error(404, "404", "authentication execution not found");
            }
        }
        let mut execution = execution;
        execution.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_execution = authentication_execution_service
            .update_authentication_execution(&execution)
            .await;
        match updated_execution {
            Ok(_) => ApiResult::no_content(),
            _ => ApiResult::from_error(500, "500", "failed to update authentication execution"),
        }
    }

    pub async fn load_authentication_execution(
        context: &DarkShieldContext,
        realm_id: &str,
        execution_id: &str,
    ) -> ApiResult<AuthenticationExecutionModel> {
        let authentication_execution_service: &dyn IAuthenticationExecutionService =
            context.services().resolve_ref();

        let loaded_execution = authentication_execution_service
            .load_authentication_execution(&realm_id, &execution_id)
            .await;
        match loaded_execution {
            Ok(execution) => ApiResult::<AuthenticationExecutionModel>::from_option(execution),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_authentication_execution_by_realm_id(
        context: &DarkShieldContext,
        realm_id: &str,
    ) -> ApiResult<Vec<AuthenticationExecutionModel>> {
        let authentication_execution_service: &dyn IAuthenticationExecutionService =
            context.services().resolve_ref();

        let loaded_executions = authentication_execution_service
            .load_authentication_execution_by_realm_id(&realm_id)
            .await;
        match loaded_executions {
            Ok(flows) => {
                log::info!(
                    "[{}] authentication executions loaded for realm: {}",
                    flows.len(),
                    &realm_id
                );
                if flows.is_empty() {
                    return ApiResult::no_content();
                } else {
                    ApiResult::from_data(flows)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to authentication executions from realm: {}",
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn remove_authentication_execution(
        context: &DarkShieldContext,
        realm_id: &str,
        execution_id: &str,
    ) -> ApiResult<()> {
        let authentication_execution_service: &dyn IAuthenticationExecutionService =
            context.services().resolve_ref();

        let existing_execution = authentication_execution_service
            .load_authentication_execution(&realm_id, &execution_id)
            .await;
        if let Ok(response) = existing_execution {
            if response.is_none() {
                log::error!(
                    "authentication execution: {} not found in realm: {}",
                    &execution_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "authentication execution not found");
            }
        }
        let result = authentication_execution_service
            .remove_authentication_execution(&realm_id, &execution_id)
            .await;
        match result {
            Ok(res) => {
                if res {
                    ApiResult::Data(())
                } else {
                    ApiResult::from_error(500, "500", "failed to delete authentication execution")
                }
            }
            _ => ApiResult::from_error(500, "500", "server internal error"),
        }
    }

    pub async fn create_authentication_flow(
        context: &DarkShieldContext,
        flow: AuthenticationFlowModel,
    ) -> ApiResult<AuthenticationFlowModel> {
        let authentication_flow_service: &dyn IAuthenticationFlowService =
            context.services().resolve_ref();

        let existing_flow = authentication_flow_service
            .exists_flow_by_alias(&flow.realm_id, &flow.alias)
            .await;
        if let Ok(response) = existing_flow {
            if response {
                log::error!(
                    "authentication flow: {} already exists in realm: {}",
                    &flow.alias,
                    &flow.realm_id
                );
                return ApiResult::from_error(409, "500", "authentication flow already exists");
            }
        }
        let mut flow = flow;
        flow.flow_id = uuid::Uuid::new_v4().to_string();
        flow.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_flow = authentication_flow_service
            .create_authentication_flow(&flow)
            .await;
        match created_flow {
            Ok(_) => ApiResult::Data(flow),
            Err(_) => ApiResult::from_error(500, "500", "failed to create authentication flow"),
        }
    }

    pub async fn update_authentication_flow(
        context: &DarkShieldContext,
        flow: AuthenticationFlowModel,
    ) -> ApiResult<()> {
        let authentication_flow_service: &dyn IAuthenticationFlowService =
            context.services().resolve_ref();

        let existing_flow = authentication_flow_service
            .load_authentication_flow_by_flow_id(&flow.realm_id, &flow.flow_id)
            .await;
        if let Ok(response) = existing_flow {
            if response.is_none() {
                log::error!(
                    "authentication flow: {} not found in realm: {}",
                    &flow.alias,
                    &flow.realm_id
                );
                return ApiResult::from_error(404, "404", "authentication flow not found");
            }
        }
        let mut flow_model = flow;
        flow_model.flow_id = uuid::Uuid::new_v4().to_string();
        flow_model.metadata =
            AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_flow = authentication_flow_service
            .update_authentication_flow(&flow_model)
            .await;
        match updated_flow {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to update authentication flow"),
        }
    }

    pub async fn load_authentication_flow_by_flow_id(
        context: &DarkShieldContext,
        realm_id: &str,
        flow_id: &str,
    ) -> ApiResult<AuthenticationFlowModel> {
        let authentication_flow_service: &dyn IAuthenticationFlowService =
            context.services().resolve_ref();

        let loaded_flow = authentication_flow_service
            .load_authentication_flow_by_flow_id(&realm_id, &flow_id)
            .await;
        match loaded_flow {
            Ok(flow) => ApiResult::<AuthenticationFlowModel>::from_option(flow),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_authentication_flow_by_realm_id(
        context: &DarkShieldContext,
        realm_id: &str,
    ) -> ApiResult<Vec<AuthenticationFlowModel>> {
        let authentication_flow_service: &dyn IAuthenticationFlowService =
            context.services().resolve_ref();

        let loaded_flows = authentication_flow_service
            .load_authentication_flow_by_realm_id(&realm_id)
            .await;
        match loaded_flows {
            Ok(flows) => {
                log::info!(
                    "[{}] authentication flows loaded for realm: {}",
                    flows.len(),
                    &realm_id
                );
                if flows.is_empty() {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_data(flows)
                }
            }
            Err(err) => {
                log::error!("Failed to authentication flow from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn remove_authentication_flow(
        context: &DarkShieldContext,
        realm_id: &str,
        flow_id: &str,
    ) -> ApiResult {
        let authentication_flow_service: &dyn IAuthenticationFlowService =
            context.services().resolve_ref();

        let existing_flow = authentication_flow_service
            .load_authentication_flow_by_flow_id(&realm_id, &flow_id)
            .await;
        if let Ok(response) = existing_flow {
            if response.is_none() {
                log::error!(
                    "authentication flow: {} not found in realm: {}",
                    &flow_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "authentication flow not found");
            }
        }
        let result = authentication_flow_service
            .remove_authentication_flow(&realm_id, &flow_id)
            .await;
        match result {
            Ok(res) => {
                if res {
                    ApiResult::no_content()
                } else {
                    ApiResult::from_error(500, "500", "failed to delete authentication flow")
                }
            }
            _ => ApiResult::from_error(500, "500", "server internal error"),
        }
    }

    pub async fn create_authenticator_config(
        context: &DarkShieldContext,
        config: AuthenticatorConfigModel,
    ) -> ApiResult<AuthenticatorConfigModel> {
        let authenticator_config_service: &dyn IAuthenticatorConfigService =
            context.services().resolve_ref();

        let existing_config = authenticator_config_service
            .exists_config_by_alias(&config.realm_id, &config.alias)
            .await;
        if let Ok(response) = existing_config {
            if response {
                log::error!(
                    "authentication config: {} already exists in realm: {}",
                    &config.alias,
                    &config.realm_id
                );
                return ApiResult::from_error(409, "500", "authentication config already exists");
            }
        }
        let mut config = config;
        config.config_id = uuid::Uuid::new_v4().to_string();
        config.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_config = authenticator_config_service
            .create_authenticator_config(&config)
            .await;
        match created_config {
            Ok(_) => ApiResult::Data(config),
            Err(_) => ApiResult::from_error(500, "500", "failed to create authentication config"),
        }
    }

    pub async fn update_authenticator_config(
        context: &DarkShieldContext,
        config: AuthenticatorConfigModel,
    ) -> ApiResult<()> {
        let authenticator_config_service: &dyn IAuthenticatorConfigService =
            context.services().resolve_ref();

        let existing_config = authenticator_config_service
            .load_authenticator_config(&config.realm_id, &config.config_id)
            .await;
        if let Ok(response) = existing_config {
            if response.is_none() {
                log::error!(
                    "authentication config: {} not found in realm: {}",
                    &config.alias,
                    &config.realm_id
                );
                return ApiResult::from_error(404, "404", "authentication config not found");
            }
        }
        let mut config = config;
        config.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_config = authenticator_config_service
            .update_authenticator_config(&config)
            .await;
        match updated_config {
            Ok(_) => ApiResult::no_content(),
            Err(_) => ApiResult::from_error(500, "500", "failed to update authentication config"),
        }
    }

    pub async fn load_authenticator_config(
        context: &DarkShieldContext,
        realm_id: &str,
        config_id: &str,
    ) -> ApiResult<Option<AuthenticatorConfigModel>> {
        let authenticator_config_service: &dyn IAuthenticatorConfigService =
            context.services().resolve_ref();

        let loaded_execution = authenticator_config_service
            .load_authenticator_config(&realm_id, &config_id)
            .await;
        match loaded_execution {
            Ok(execution) => ApiResult::from_data(execution),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_authenticator_config_by_realm_id(
        context: &DarkShieldContext,
        realm_id: &str,
    ) -> ApiResult<Vec<AuthenticatorConfigModel>> {
        let authenticator_config_service: &dyn IAuthenticatorConfigService =
            context.services().resolve_ref();

        let loaded_configs = authenticator_config_service
            .load_authenticator_config_by_realm_id(&realm_id)
            .await;
        match loaded_configs {
            Ok(configs) => {
                log::info!(
                    "[{}] authentication configs loaded for realm: {}",
                    configs.len(),
                    &realm_id
                );
                if configs.is_empty() {
                    return ApiResult::no_content();
                } else {
                    ApiResult::from_data(configs)
                }
            }
            Err(err) => {
                log::error!(
                    "Failed to load authentication config from realm: {}",
                    &realm_id
                );
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn remove_authenticator_config(
        context: &DarkShieldContext,
        realm_id: &str,
        config_id: &str,
    ) -> ApiResult<()> {
        let authenticator_config_service: &dyn IAuthenticatorConfigService =
            context.services().resolve_ref();

        let existing_config = authenticator_config_service
            .load_authenticator_config(&realm_id, &config_id)
            .await;
        if let Ok(response) = existing_config {
            if response.is_none() {
                log::error!(
                    "authentication config: {} not found in realm: {}",
                    &config_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "authentication config not found");
            }
        }
        let result = authenticator_config_service
            .remove_authenticator_config(&realm_id, &config_id)
            .await;
        match result {
            Ok(res) => {
                if res {
                    ApiResult::Data(())
                } else {
                    ApiResult::from_error(500, "500", "failed to delete authentication config")
                }
            }
            Err(_) => ApiResult::from_error(500, "500", "server internal error"),
        }
    }

    pub async fn register_required_action(
        context: &DarkShieldContext,
        action: RequiredActionModel,
    ) -> ApiResult<RequiredActionModel> {
        let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();

        let existing_action = required_action_service
            .load_required_action(&action.realm_id, &action.action_id)
            .await;
        if let Ok(response) = existing_action {
            if response.is_some() {
                log::error!(
                    "required action: {} already exists in realm: {}",
                    &action.action,
                    &action.realm_id
                );
                return ApiResult::from_error(409, "500", "required action already exists");
            }
        }
        let mut action = action;
        action.action_id = uuid::Uuid::new_v4().to_string();
        action.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_action = required_action_service
            .register_required_action(&action)
            .await;
        match created_action {
            Ok(_) => ApiResult::Data(action),
            Err(_) => ApiResult::from_error(500, "500", "failed to required action"),
        }
    }

    pub async fn update_required_action(
        context: &DarkShieldContext,
        action: RequiredActionModel,
    ) -> ApiResult<()> {
        let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();

        let existing_action = required_action_service
            .load_required_action(&action.realm_id, &action.action_id)
            .await;
        if let Ok(response) = existing_action {
            if response.is_none() {
                log::error!(
                    "required action: {} not found in realm: {}",
                    &action.name,
                    &action.realm_id
                );
                return ApiResult::from_error(404, "404", "action not found");
            }
        }
        let mut action = action;
        action.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_action = required_action_service
            .update_required_action(&action)
            .await;
        match updated_action {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to update role"),
        }
    }

    pub async fn update_required_action_priority(
        context: &DarkShieldContext,
        _realm_id: &str,
        _action: &RequiredActionEnum,
        _priority: i32,
    ) -> ApiResult<()> {
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

    pub async fn load_required_action_by_id(
        context: &DarkShieldContext,
        realm_id: &str,
        action_id: &str,
    ) -> ApiResult<Option<RequiredActionModel>> {
        let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();

        let loaded_action = required_action_service
            .load_required_action(&realm_id, &action_id)
            .await;
        match loaded_action {
            Ok(action) => ApiResult::from_data(action),
            Err(err) => ApiResult::from_error(500, "500", &err),
        }
    }

    pub async fn load_required_action_by_realm_id(
        context: &DarkShieldContext,
        realm_id: &str,
    ) -> ApiResult<Vec<RequiredActionModel>> {
        let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();
        let loaded_actions = required_action_service
            .load_required_action_by_realm_id(&realm_id)
            .await;

        match loaded_actions {
            Ok(actions) => {
                log::info!(
                    "[{}] required actions loaded for realm: {}",
                    actions.len(),
                    &realm_id
                );
                ApiResult::from_data(actions)
            }
            Err(err) => {
                log::error!("Failed to load required actions from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    pub async fn remove_required_action(
        context: &DarkShieldContext,
        realm_id: &str,
        action_id: &str,
    ) -> ApiResult<()> {
        let required_action_service: &dyn IRequiredActionService = context.services().resolve_ref();

        let existing_action = required_action_service
            .load_required_action(&realm_id, &action_id)
            .await;
        if let Ok(response) = existing_action {
            if response.is_none() {
                log::error!(
                    "required action: {} not found in realm: {}",
                    &action_id,
                    &realm_id
                );
                return ApiResult::from_error(404, "404", "required action not found");
            }
        }
        let result = required_action_service
            .remove_required_action(&realm_id, &action_id)
            .await;
        match result {
            Ok(res) => {
                if res {
                    ApiResult::Data(())
                } else {
                    ApiResult::from_error(500, "500", "failed to delete required action")
                }
            }
            _ => ApiResult::from_error(500, "500", "server internal error"),
        }
    }
}
