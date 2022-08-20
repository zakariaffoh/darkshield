use crate::auditable::AuditableModel;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Permission {}

#[derive(Debug)]
#[allow(dead_code)]
pub struct RoleModel {
    pub role_id: String,
    pub realm_id: String,
    pub name: String,
    pub description: String,
    pub is_client_role: bool,
    pub display_name: String,
    pub metadata: AuditableModel,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct GroupModel {
    pub group_id: String,
    pub realm_id: String,
    pub name: String,
    pub roles: Option<Vec<RoleModel>>,
    pub display_name: String,
    pub description: String,
    pub is_default: bool,
    pub metadata: AuditableModel,
}
