use async_trait::async_trait;
use log;
use commons::api_result::ApiResult;
use models::auditable::AuditableModel;
use models::entities::auth::{RequiredActionModel, RequiredActionEnum};
use shaku::Component;
use shaku::Interface;
use store::providers::interfaces::auth_providers::IRequiredActionProvider;
use std::collections::HashMap;
use std::sync::Arc;


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

