use std::sync::Arc;
use log;
use uuid;
use shaku::Component;
use shaku::Interface;
use async_trait::async_trait;
use models::entities::authz::*;
use commons::api_result::ApiResult;
use models::auditable::AuditableModel;
use store::providers::interfaces::authz_provider::IGroupProvider;
use store::providers::interfaces::authz_provider::IIdentityProvider;
use store::providers::interfaces::authz_provider::IRoleProvider;

#[async_trait]
pub trait IRoleService: Interface {
    async fn create_role(&self, realm: RoleModel) -> ApiResult<RoleModel>;
    async fn update_role(&self, realm: RoleModel) -> ApiResult<()>;
    async fn delete_role(&self, realm_id: &str, role_id:&str) -> ApiResult<bool>;
    async fn load_role_by_id(&self, realm_id: &str, role_id:&str) -> ApiResult<Option<RoleModel>>;
    async fn load_roles_by_realm(&self, realm_id: &str) -> ApiResult<Vec<RoleModel>>;
    async fn count_roles_by_realm(&self, realm_id: &str) -> ApiResult<u32>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IRoleService)]
pub struct RoleService {
    #[shaku(inject)]
    role_provider: Arc<dyn IRoleProvider>,
}

#[async_trait]
impl IRoleService for RoleService {

    async fn create_role(&self, role: RoleModel) -> ApiResult<RoleModel> {
        let existing_role = self.role_provider.load_role_by_name(&role.realm_id, &role.name).await;
        if let Ok(response) = existing_role {
            if response.is_some() {
                log::error!("role: {} already exists in realm: {}", &role.name, &role.realm_id);
                return ApiResult::from_error(409, "500", "role already exists");
            }
        }
        let mut role = role;
        role.role_id = uuid::Uuid::new_v4().to_string();
        role.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_role = self.role_provider.create_role(&role).await;
        match created_role {
            Ok(_) => ApiResult::Data(role),
            Err(_) => ApiResult::from_error(500, "500", "failed to create role"),
        }
    }

    async fn update_role(&self, role: RoleModel) -> ApiResult<()> {
        let existing_role = self.role_provider.load_role_by_id(&role.realm_id, &role.role_id).await;
        if let Ok(response) = existing_role {
            if response.is_none() {
                log::error!("role: {} not found in realm: {}", &role.name, &role.realm_id);
                return ApiResult::from_error(404, "404", "role not found");
            }
        }
        let mut role = role;
        role.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_role = self.role_provider.update_role(&role).await;
        match updated_role {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to update role"),
        }
    }

    async fn delete_role(&self, realm_id: &str, role_id:&str) -> ApiResult<bool> {
        let existing_role = self.role_provider.load_role_by_id(&realm_id, &role_id).await;
        if let Ok(response) = existing_role {
            if response.is_none() {
                log::error!("role: {} not found in realm: {}", &role_id, &realm_id);
                return ApiResult::from_error(404, "404", "role not found");
            }
        }
        let updated_role = self.role_provider.delete_role(&realm_id, &role_id).await;
        match updated_role {
            Ok(_) => ApiResult::Data(true),
            Err(_) => ApiResult::from_error(500, "500", "failed to update role"),
        }
    }

    async fn load_role_by_id(&self, realm_id: &str, role_id:&str) -> ApiResult<Option<RoleModel>>{
        let loaded_role = self.role_provider.load_role_by_id(&realm_id, &role_id).await;
        match loaded_role {
            Ok(role) => ApiResult::from_data(role),
            Err(err) => ApiResult::from_error(500, "500", &err)
        }
    }

    async fn load_roles_by_realm(&self, realm_id: &str) -> ApiResult<Vec<RoleModel>>{
        let loaded_roles = self.role_provider.load_roles_by_realm(&realm_id).await;
        match loaded_roles {
            Ok(roles) => {
                log::info!("[{}] roles loaded for realm: {}", roles.len(), &realm_id);
                ApiResult::from_data(roles)
            }
            Err(err) => {
                log::error!("Failed to load roles from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    async fn count_roles_by_realm(&self, realm_id: &str) -> ApiResult<u32>{
        let response = self.role_provider.count_roles(&realm_id).await;
        match response {
            Ok(count) => ApiResult::from_data(count),
            Err(err) => ApiResult::from_error(500, "500", &err)
        }
    }
}


#[async_trait]
pub trait IGroupService: Interface {
    async fn create_group(&self, group: GroupModel) -> ApiResult<GroupModel>;
    async fn udpate_group(&self, group: GroupModel) -> ApiResult<()>;
    async fn delete_group(&self, realm_id: &str, group_id: &str) -> ApiResult<()>;
    async fn load_group_by_id(&self, realm_id: &str, group_id: &str) -> ApiResult<Option<GroupModel>>;
    async fn load_groups_by_realm(&self, realm_id: &str) -> ApiResult<Vec<GroupModel>>;
    async fn count_groups(&self, realm_id: &str) -> ApiResult<u32>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IGroupService)]
pub struct GroupService {
    #[shaku(inject)]
    group_provider: Arc<dyn IGroupProvider>,
    role_provider: Arc<dyn IRoleProvider>,
}

#[async_trait]
impl IGroupService for GroupService {

    async fn create_group(&self, group: GroupModel) -> ApiResult<GroupModel> {
        let existing_group = self.group_provider.load_group_by_name(&group.realm_id, &group.name).await;
        if let Ok(response) = existing_group {
            if response.is_some() {
                log::error!("group: {} already exists in realm: {}", &group.name, &group.realm_id);
                return ApiResult::from_error(409, "500", "role already exists");
            }
        }
        let mut group = group;
        group.group_id = uuid::Uuid::new_v4().to_string();
        group.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_group = self.group_provider.create_group(&group).await;
        match created_group {
            Ok(_) => ApiResult::Data(group),
            Err(_) => ApiResult::from_error(500, "500", "failed to create group"),
        }
    }

    async fn udpate_group(&self, group: GroupModel) -> ApiResult<()> {
        let existing_group = self.group_provider.load_group_by_id(&group.realm_id, &group.group_id).await;
        if let Ok(response) = existing_group {
            if response.is_some() {
                log::error!("group: {} already exists in realm: {}", &group.name, &group.realm_id);
                return ApiResult::from_error(409, "500", "role already exists");
            }
        }
        let mut group = group;
        group.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_group = self.group_provider.create_group(&group).await;
        match updated_group {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to update group"),
        }
    }

    async fn delete_group(&self, realm_id: &str, group_id: &str) -> ApiResult<()>{
        let existing_group = self.group_provider.load_group_by_id(&realm_id, &group_id).await;
        if let Ok(response) = existing_group {
            if response.is_none() {
                log::error!("group: {} not found in realm: {}", &group_id, &realm_id);
                return ApiResult::from_error(404, "404", "role not found");
            }
        }
        let result = self.group_provider.delete_group(&realm_id, &group_id).await;
        match result {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to update role"),
        }
    }

    async fn load_group_by_id(&self, realm_id: &str, group_id: &str) -> ApiResult<Option<GroupModel>> {
        let loaded_group = self.group_provider.load_group_by_id(&realm_id, &group_id).await;
        match loaded_group {
            Ok(group) => ApiResult::from_data(group),
            Err(err) => ApiResult::from_error(500, "500", &err)
        }
    }

    async fn load_groups_by_realm(&self, realm_id: &str) -> ApiResult<Vec<GroupModel>>{
        let loaded_groups = self.group_provider.load_groups_by_realm(&realm_id).await;
        match loaded_groups {
            Ok(groups) => {
                log::info!("[{}] groups loaded for realm: {}", groups.len(), &realm_id);
                ApiResult::from_data(groups)
            }
            Err(err) => {
                log::error!("Failed to load group from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    async fn count_groups(&self, realm_id: &str) -> ApiResult<u32>{
        let response = self.group_provider.count_groups(&realm_id).await;
        match response {
            Ok(count) => ApiResult::from_data(count),
            Err(err) => ApiResult::from_error(500, "500", &err)
        }
    }
}


#[async_trait]
pub trait IIdentityProviderService: Interface {
    async fn create_identity_provider(&self, idp: IdentityProviderModel) -> ApiResult<IdentityProviderModel>;
    async fn udpate_identity_provider(&self, idp: IdentityProviderModel) -> ApiResult<()>;
    async fn load_identity_provider(&self, realm_id: &str, internal_id: &str) -> ApiResult<Option<IdentityProviderModel>>;
    async fn load_identity_providers_by_realm(&self, realm_id: &str) -> ApiResult<Vec<IdentityProviderModel>>;
    async fn delete_identity_provider(&self, realm_id: &str, internal_id: &str) -> ApiResult<()>;
    async fn exists_by_alias(&self, realm_id: &str, alias: &str) -> ApiResult<bool>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IIdentityProviderService)]
pub struct IdentityProviderService {
    #[shaku(inject)]
    identity_provider: Arc<dyn IIdentityProvider>,
}

#[async_trait]
impl IIdentityProviderService for IdentityProviderService {

    async fn create_identity_provider(&self, idp: IdentityProviderModel) -> ApiResult<IdentityProviderModel>{
        let existing_idp = self.identity_provider.load_identity_provider_by_internal_id(&idp.realm_id, &idp.internal_id).await;
        if let Ok(response) = existing_idp {
            if response.is_some() {
                log::error!("identity privider: {} already exists in realm: {}", &idp.name, &idp.realm_id);
                return ApiResult::from_error(409, "500", "identity privider already exists");
            }
        }
        let mut idp = idp;
        idp.internal_id = uuid::Uuid::new_v4().to_string();
        idp.metadata = AuditableModel::from_creator("tenant".to_owned(), "zaffoh".to_owned());
        let created_idp = self.identity_provider.create_identity_provider(&idp).await;
        match created_idp {
            Ok(_) => ApiResult::Data(idp),
            Err(_) => ApiResult::from_error(500, "500", "failed to create identity privider"),
        }
    }

    async fn udpate_identity_provider(&self, idp: IdentityProviderModel) -> ApiResult<()>{
        let existing_idp = self.identity_provider.load_identity_provider_by_internal_id(&idp.realm_id, &idp.internal_id).await;
        if let Ok(response) = existing_idp {
            if response.is_none() {
                log::error!("identity provider: {} already exists in realm: {}", &idp.internal_id, &idp.realm_id);
                return ApiResult::from_error(409, "500", "identity provider already exists");
            }
            let existing_idp = response.unwrap();
            if existing_idp.name != idp.name {
                let has_alias = self.identity_provider.exists_by_alias(&idp.realm_id, &idp.internal_id).await;
                if let Ok(res) = has_alias{
                    if res {
                        log::error!("identity provider with name: {} already exists in realm: {}", &idp.name, &idp.realm_id);
                        return ApiResult::from_error(409, "500", &format!("identity provider already for alias {0}", &idp.name));
                    }
                }
            }
        }
        let mut idp = idp;
        idp.metadata = AuditableModel::from_updator("tenant".to_owned(), "zaffoh".to_owned());
        let updated_idp = self.identity_provider.udpate_identity_provider(&idp).await;
        match updated_idp {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to update identity provider"),
        }
    }

    async fn load_identity_provider(&self, realm_id: &str, internal_id: &str) -> ApiResult<Option<IdentityProviderModel>>{
        let loaded_idp = self.identity_provider.load_identity_provider_by_internal_id(&realm_id, &internal_id).await;
        match loaded_idp {
            Ok(idp) => ApiResult::from_data(idp),
            Err(err) => ApiResult::from_error(500, "500", &err)
        }
    }

    async fn load_identity_providers_by_realm(&self, realm_id: &str) -> ApiResult<Vec<IdentityProviderModel>>{
        let loaded_idps = self.identity_provider.load_identity_provider_by_realm(&realm_id).await;
        match loaded_idps {
            Ok(idps) => {
                log::info!("[{}] identity providers loaded for realm: {}", idps.len(), &realm_id);
                ApiResult::from_data(idps)
            }
            Err(err) => {
                log::error!("Failed to load identity providers from realm: {}", &realm_id);
                ApiResult::from_error(500, "500", &err)
            }
        }
    }

    async fn delete_identity_provider(&self, realm_id: &str, internal_id: &str) -> ApiResult<()>{
        let existing_idp = self.identity_provider.load_identity_provider_by_internal_id(&realm_id, &internal_id).await;
        if let Ok(response) = existing_idp {
            if response.is_none() {
                log::error!("identity provider: {} not found in realm: {}", &internal_id, &realm_id);
                return ApiResult::from_error(404, "404", "identity provider not found");
            }
        }
        let updated_idp = self.identity_provider.remove_identity_provider(&realm_id, &internal_id).await;
        match updated_idp {
            Ok(_) => ApiResult::Data(()),
            Err(_) => ApiResult::from_error(500, "500", "failed to update identity provider"),
        }
    }

    async fn exists_by_alias(&self, realm_id: &str, alias: &str) -> ApiResult<bool>{
        let existing_idp = self.identity_provider.exists_by_alias(&realm_id, &alias).await;
        match existing_idp {
            Ok(res) => ApiResult::Data(res),
            Err(_) => ApiResult::from_error(500, "500", "failed check identity provider"),
        }
    }
}
