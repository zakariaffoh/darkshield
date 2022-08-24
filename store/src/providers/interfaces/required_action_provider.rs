use std::collections::HashMap;

use async_trait::async_trait;
use models::entities::required_action::{RequiredActionEnum, RequiredActionModel};
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
