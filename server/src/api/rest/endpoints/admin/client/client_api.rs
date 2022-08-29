use log;
use shaku::HasComponent;
use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};

use crate::context::context::DarkShieldContext;
use models::entities::client::{
    ClientCreateModel, 
    ClientModel, 
    ClientUpdateModel,
    ClientScopeMutationModel, 
    ClientScopeModel, 
    ProtocolMapperModel,
    ProtocolMapperMutationModel,

};
use services::services::client::{
    IClientService, 
    IClientScopeService, 
    IProtocolMapperService
};

#[post("/admin/realms/{realm_id}/clients_scopes/create")]
pub async fn create_client_scope(
    realm_id: web::Path<String>,
    scope: web::Json<ClientScopeMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {

    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    let mut client_scope_model: ClientScopeModel = role.0.into();
    client_scope_model.realm_id = realm_id.to_string();
    log::info!("Creating client scope: {} for realm: {}", &client_scope_model.name, realm_id.as_str());
    client_scope_service.create_client_scope(client_scope_model).await
}


#[put("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}/update")]
pub async fn update_client_scope(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    scope: web::Json<ClientScopeMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    let mut client_scope_model: RoleModel = role.0.into();
    client_scope_model.realm_id = realm_id.to_string();
    client_scope_model.client_scope_id = client_scope_id.to_string();
    log::info!("updating client scope {}, realm: {}", client_scope_id.as_str(), realm_id.as_str());
    client_scope_service.update_client_scope(client_scope_model).await
}

#[get("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}")]
pub async fn load_client_scope_by_id(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    log::info!("Loading role: {}, for realm: {}", client_scope_id.as_str(), realm_id.as_str());
    client_scope_service.load_client_scope_by_id(realm_id.as_str(), client_scope_id.as_str()).await
}

#[delete("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}")]
pub async fn delete_client_scope_by_id(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    log::info!("Deleting client scope: {}, for realm: {}", client_scope_id.as_str(), realm_id.as_str());
    client_scope_service.delete_client_scope_by_id(realm_id.as_str(), client_scope_id.as_str()).await
}


#[put("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}/protocol_mapper/{mapper_id}")]
pub async fn add_client_scope_protocol_mapper(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    mapper_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    log::info!("Adding client scope: {}, protocol mapper: {} for realm: {}", client_scope_id.as_str(), mapper.as_str(), realm_id.as_str());
    client_scope_service.add_client_scope_protocol_mapper(realm_id.as_str(), client_scope_id.as_str(),  mapper.as_str()).await
}


#[delete("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}/protocol_mapper/{mapper_id}")]
pub async fn delete_client_scope_protocol_mapper(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    mapper_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    log::info!("Deleting client scope: {}, protocol mapper: {} for realm: {}", client_scope_id.as_str(), mapper.as_str(), realm_id.as_str());
    client_scope_service.delete_client_scope_protocol_mapper(realm_id.as_str(), client_scope_id.as_str(),  mapper.as_str()).await
}

#[put("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}/roles/{role_id}")]
pub async fn add_client_scope_role_mapping(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    role_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    log::info!("Adding client scope: {}, role: {} for realm: {}", client_scope_id.as_str(), role_id.as_str(), realm_id.as_str());
    client_scope_service.add_client_scope_protocol_mapper(realm_id.as_str(), client_scope_id.as_str(),  mapper.as_str()).await
}


#[delete("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}/roles/{role_id}")]
pub async fn delete_client_scope_role_mapping(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    mapper_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    log::info!("Deleting client scope: {}, role: {} for realm: {}", client_scope_id.as_str(), role_id.as_str(), realm_id.as_str());
    client_scope_service.delete_client_scope_role_mapping(realm_id.as_str(), client_scope_id.as_str(),  mapper.as_str()).await
}


#[post("/admin/realms/{realm_id}/protocol_mapper/create")]
pub async fn create_protocol_mapper(
    realm_id: web::Path<String>,
    mapper: web::Json<ProtocolMapperMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {

    let protocol_mapper_service: &dyn IProtocolMqpperService = context.services().resolve_ref();
    let mut mapper_model: ClientScopeModel = role.0.into();
    mapper_model.realm_id = realm_id.to_string();
    log::info!("Creating protocol mapper: {} for realm: {}", &mapper.mapper, realm_id.as_str());
    protocol_mapper_service.create_protocol_mapper(client_scope_model).await
}


#[put("/admin/realms/{realm_id}/protocol_mapper/{mapper_id}")]
pub async fn update_protocol_mapper(
    realm_id: web::Path<String>,
    mapper_id: web::Path<String>,
    mapper: web::Json<ProtocolMapperMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let protocol_mapper_service: &dyn IProtocolMqpperService = context.services().resolve_ref();
    let mut mapper: RoleModel = role.0.into();
    mapper.realm_id = realm_id.to_string();
    mapper.mapper_id = mapper_id.to_string();
    log::info!("updating protocol mapper: {}, realm: {}", mapper_id.as_str(), realm_id.as_str());
    protocol_mapper_service.update_protocol_mapper(mapper).await
}

#[get("/admin/realms/{realm_id}/protocol_mapper/{mapper_id}")]
pub async fn load_protocol_mapper_by_id(
    realm_id: web::Path<String>,
    mapper_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let protocol_mapper_service: &dyn IProtocolMqpperService = context.services().resolve_ref();
    log::info!("Loading role: {}, for realm: {}", mapper_id.as_str(), realm_id.as_str());
    protocol_mapper_service.load_protocol_mapper_by_id(realm_id.as_str(), mapper_id.as_str()).await
}

#[get("/admin/realms/{realm_id}/protocol_mappers/protocol/{protocol}")]
pub async fn load_protocol_mappers_by_protocol(
    realm_id: web::Path<String>,
    protocol: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let protocol_mapper_service: &dyn IProtocolMqpperService = context.services().resolve_ref();
    log::info!("Loading protocol mapper: {}, by protocol: {} for realm: {}", mapper_id.as_str(), protocol.as_str());
    protocol_mapper_service.load_protocol_mappers_by_protocol(realm_id.as_str(), protocol.as_str()).await
}

#[get("/admin/realms/{realm_id}/protocol_mappers/client/{client_id}")]
pub async fn load_protocol_mappers_by_client_id(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let protocol_mapper_service: &dyn IProtocolMqpperService = context.services().resolve_ref();
    log::info!("Loading protocol mapper for client id: {}, for realm: {}", client_id.as_str(), realm_id.as_str());
    protocol_mapper_service.load_protocol_mappers_by_client_id(realm_id.as_str(), client_id.as_str()).await
}