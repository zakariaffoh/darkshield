use crate::auditable::AuditableModel;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Permission {}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Role {
    role_id: String,
    name: String,
    description: String,
    is_client_role: bool,
    display_name: String,
    metadata: AuditableModel,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Group {
    group_id: String,
    realm_id: String,
    name: String,
    roles: Vec<Role>,
    display_name: String,
    metadata: AuditableModel,
}
