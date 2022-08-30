use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};
use log;
use shaku::HasComponent;

use crate::context::context::DarkShieldContext;
use models::entities::client::{
    ClientCreateModel, ClientModel, ClientScopeModel, ClientScopeMutationModel, ClientUpdateModel,
    ProtocolMapperModel, ProtocolMapperMutationModel,
};
use services::services::client_services::{
    IClientScopeService, IClientService, IProtocolMapperService,
};

#[post("/admin/realms/{realm_id}/clients_scopes/create")]
pub async fn create_client_scope(
    realm_id: web::Path<String>,
    scope: web::Json<ClientScopeMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    let mut client_scope_model: ClientScopeModel = scope.0.into();
    client_scope_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating client scope: {} for realm: {}",
        &client_scope_model.name,
        realm_id.as_str()
    );
    client_scope_service
        .create_client_scope(client_scope_model)
        .await
}

#[put("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}/update")]
pub async fn update_client_scope(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    scope: web::Json<ClientScopeMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    let mut client_scope_model: ClientScopeModel = scope.0.into();
    client_scope_model.realm_id = realm_id.to_string();
    client_scope_model.client_scope_id = client_scope_id.to_string();
    log::info!(
        "updating client scope {}, realm: {}",
        client_scope_id.as_str(),
        realm_id.as_str()
    );
    client_scope_service
        .update_client_scope(client_scope_model)
        .await
}

#[get("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}")]
pub async fn load_client_scope_by_id(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    log::info!(
        "Loading client scope: {}, for realm: {}",
        client_scope_id.as_str(),
        realm_id.as_str()
    );
    client_scope_service
        .load_client_scope_by_scope_id(realm_id.as_str(), client_scope_id.as_str())
        .await
}

#[delete("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}")]
pub async fn delete_client_scope_by_id(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    log::info!(
        "Deleting client scope: {}, for realm: {}",
        client_scope_id.as_str(),
        realm_id.as_str()
    );
    client_scope_service
        .delete_client_scope(realm_id.as_str(), client_scope_id.as_str())
        .await
}

#[put("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}/protocol_mapper/{mapper_id}")]
pub async fn add_client_scope_protocol_mapper(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    mapper_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    log::info!(
        "Adding client scope: {}, protocol mapper: {} for realm: {}",
        client_scope_id.as_str(),
        mapper_id.as_str(),
        realm_id.as_str()
    );
    client_scope_service
        .add_client_scope_protocol_mapper(
            realm_id.as_str(),
            client_scope_id.as_str(),
            mapper_id.as_str(),
        )
        .await
}

#[delete("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}/protocol_mapper/{mapper_id}")]
pub async fn delete_client_scope_protocol_mapper(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    mapper_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    log::info!(
        "Deleting client scope: {}, protocol mapper: {} for realm: {}",
        client_scope_id.as_str(),
        mapper_id.as_str(),
        realm_id.as_str()
    );
    client_scope_service
        .remove_client_scope_protocol_mapper(
            realm_id.as_str(),
            client_scope_id.as_str(),
            mapper_id.as_str(),
        )
        .await
}

#[put("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}/roles/{role_id}")]
pub async fn add_client_scope_role_mapping(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    role_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    log::info!(
        "Adding client scope: {}, role: {} for realm: {}",
        client_scope_id.as_str(),
        role_id.as_str(),
        realm_id.as_str()
    );
    client_scope_service
        .add_client_scope_role_mapping(
            realm_id.as_str(),
            client_scope_id.as_str(),
            role_id.as_str(),
        )
        .await
}

#[delete("/admin/realms/{realm_id}/clients_scopes/{client_scope_id}/roles/{role_id}")]
pub async fn delete_client_scope_role_mapping(
    realm_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    role_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    log::info!(
        "Deleting client scope: {}, role: {} for realm: {}",
        client_scope_id.as_str(),
        role_id.as_str(),
        realm_id.as_str()
    );
    client_scope_service
        .remove_client_scope_role_mapping(
            realm_id.as_str(),
            client_scope_id.as_str(),
            role_id.as_str(),
        )
        .await
}

#[post("/admin/realms/{realm_id}/protocol_mapper/create")]
pub async fn create_protocol_mapper(
    realm_id: web::Path<String>,
    mapper: web::Json<ProtocolMapperMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let protocol_mapper_service: &dyn IProtocolMapperService = context.services().resolve_ref();
    let mut mapper_model: ProtocolMapperModel = mapper.0.into();
    mapper_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating protocol mapper: {} for realm: {}",
        &mapper_model.name,
        realm_id.as_str()
    );
    protocol_mapper_service
        .create_protocol_mapper(mapper_model)
        .await
}

#[put("/admin/realms/{realm_id}/protocol_mapper/{mapper_id}")]
pub async fn update_protocol_mapper(
    realm_id: web::Path<String>,
    mapper_id: web::Path<String>,
    mapper: web::Json<ProtocolMapperMutationModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let protocol_mapper_service: &dyn IProtocolMapperService = context.services().resolve_ref();
    let mut mapper_model: ProtocolMapperModel = mapper.0.into();
    mapper_model.realm_id = realm_id.to_string();
    mapper_model.mapper_id = mapper_id.to_string();
    log::info!(
        "updating protocol mapper: {}, realm: {}",
        mapper_id.as_str(),
        realm_id.as_str()
    );
    protocol_mapper_service
        .update_protocol_mapper(mapper_model)
        .await
}

#[get("/admin/realms/{realm_id}/protocol_mapper/{mapper_id}")]
pub async fn load_protocol_mapper_by_id(
    realm_id: web::Path<String>,
    mapper_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let protocol_mapper_service: &dyn IProtocolMapperService = context.services().resolve_ref();
    log::info!(
        "Loading protocol mapper: {}, for realm: {}",
        mapper_id.as_str(),
        realm_id.as_str()
    );
    protocol_mapper_service
        .load_protocol_mapper_by_mapper_id(realm_id.as_str(), mapper_id.as_str())
        .await
}

#[get("/admin/realms/{realm_id}/protocol_mappers/protocol/{protocol}")]
pub async fn load_protocol_mappers_by_protocol(
    realm_id: web::Path<String>,
    protocol: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let protocol_mapper_service: &dyn IProtocolMapperService = context.services().resolve_ref();
    log::info!(
        "Loading protocol mapper by protocol: {} for realm: {}",
        protocol.as_str(),
        realm_id.as_str()
    );
    protocol_mapper_service
        .load_protocol_mapper_by_protocol(realm_id.as_str(), protocol.as_str())
        .await
}

#[get("/admin/realms/{realm_id}/protocol_mappers/client/{client_id}")]
pub async fn load_protocol_mappers_by_client_id(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let protocol_mapper_service: &dyn IProtocolMapperService = context.services().resolve_ref();
    log::info!(
        "Loading protocol mapper for client id: {}, for realm: {}",
        client_id.as_str(),
        realm_id.as_str()
    );
    protocol_mapper_service
        .load_protocol_mappers_by_client_id(realm_id.as_str(), client_id.as_str())
        .await
}

#[post("/admin/realms/{realm_id}/client/create")]
pub async fn create_client(
    realm_id: web::Path<String>,
    client: web::Json<ClientCreateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    let mut client_model: ClientModel = client.0.into();
    client_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating client: {} for realm: {}",
        &client_model.client_id,
        realm_id.as_str()
    );
    client_service.create_client(client_model).await
}

#[put("/admin/realms/{realm_id}/client/{client_id}")]
pub async fn update_client(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    client: web::Json<ClientUpdateModel>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    let mut client_model: ClientModel = client.0.into();
    client_model.realm_id = realm_id.to_string();
    client_model.client_id = client_id.to_string();
    log::info!(
        "Updating client: {} for realm: {}",
        &client_model.client_id,
        realm_id.as_str()
    );
    client_service.update_client(client_model).await
}

#[get("/admin/realms/{realm_id}/client/{client_id}")]
pub async fn load_client_by_id(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    log::info!(
        "loading client: {} for realm: {}",
        client_id.as_str(),
        realm_id.as_str()
    );
    client_service
        .load_client_by_id(realm_id.as_str(), realm_id.as_str())
        .await
}

#[delete("/admin/realms/{realm_id}/client/{client_id}")]
pub async fn delete_client_by_id(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    log::info!(
        "Delete client: {} for realm: {}",
        client_id.as_str(),
        realm_id.as_str()
    );
    client_service
        .delete_client(realm_id.as_str(), realm_id.as_str())
        .await
}

#[post("/admin/realms/{realm_id}/client/{client_id}/roles_mapping")]
pub async fn add_client_roles_mapping(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    roles_ids: web::Json<Vec<String>>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    log::info!(
        "Add client: {} roles: [{}]  mapping for realm: {}",
        roles_ids.0.join(","),
        client_id.as_str(),
        realm_id.as_str(),
    );
    client_service
        .add_client_roles_mapping(realm_id.as_str(), realm_id.as_str(), roles_ids.0)
        .await
}

#[put("/admin/realms/{realm_id}/client/{client_id}/roles_mapping")]
pub async fn remove_client_roles_mapping(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    roles_ids: web::Json<Vec<String>>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    log::info!(
        "Removing client: {} roles: [{}]  mapping for realm: {}",
        roles_ids.0.join(","),
        client_id.as_str(),
        realm_id.as_str(),
    );
    client_service
        .remove_client_roles_mapping(realm_id.as_str(), realm_id.as_str(), roles_ids.0)
        .await
}

#[get("/admin/realms/{realm_id}/client/{client_id}/roles_mapping")]
pub async fn load_client_roles_mapping(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    log::info!(
        "Loading client: {} roles mapping for realm: {}",
        client_id.as_str(),
        realm_id.as_str(),
    );
    client_service
        .load_client_roles_mapping(realm_id.as_str(), realm_id.as_str())
        .await
}

#[post("/admin/realms/{realm_id}/client/{client_id}/client_scope/{client_scope_id}")]
pub async fn add_client_scope_mapping(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    log::info!(
        "Adding client: {} scope: {} mapping  for realm: {}",
        client_id.as_str(),
        client_scope_id.as_str(),
        realm_id.as_str(),
    );
    client_service
        .add_client_scope_mapping(
            realm_id.as_str(),
            client_id.as_str(),
            client_scope_id.as_str(),
        )
        .await
}

#[put("/admin/realms/{realm_id}/client/{client_id}/client_scope/{client_scope_id}")]
pub async fn remove_client_protocol_mapping(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    client_scope_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    log::info!(
        "Removing client: {} scope: {} mapping  for realm: {}",
        client_id.as_str(),
        client_scope_id.as_str(),
        realm_id.as_str(),
    );
    client_service
        .remove_client_scope_mapping(
            realm_id.as_str(),
            client_id.as_str(),
            client_scope_id.as_str(),
        )
        .await
}

#[get("/admin/realms/{realm_id}/client/{client_id}/client_scopes/all")]
pub async fn load_client_scopes_by_client_id(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    log::info!(
        "Loading client: {} scopes mapping for realm: {}",
        client_id.as_str(),
        realm_id.as_str(),
    );
    client_service
        .load_client_scopes_by_client_id(realm_id.as_str(), client_id.as_str())
        .await
}

#[post("/admin/realms/{realm_id}/client/{client_id}/protocol_mapper/{mapper_id}")]
pub async fn add_client_protocol_mapper(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    mapper_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    log::info!(
        "Add client: {} protocol mapper: {} mapping for realm: {}",
        client_id.as_str(),
        mapper_id.as_str(),
        realm_id.as_str(),
    );
    client_service
        .add_client_protocol_mapping(realm_id.as_str(), client_id.as_str(), mapper_id.as_str())
        .await
}

#[put("/admin/realms/{realm_id}/client/{client_id}/protocol_mapper/{mapper_id}")]
pub async fn remove_client_protocol_mapper_mapper(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    mapper_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    log::info!(
        "Removing client: {} protocol mapper: {} mapping  for realm: {}",
        client_id.as_str(),
        mapper_id.as_str(),
        realm_id.as_str(),
    );
    client_service
        .remove_client_protocol_mapping(realm_id.as_str(), client_id.as_str(), mapper_id.as_str())
        .await
}

#[get("/admin/realms/{realm_id}/client/{client_id}/protocol_mappers/all")]
pub async fn load_client_protocol_mappers(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    log::info!(
        "Loading client: {} protocol mappers  for realm: {}",
        client_id.as_str(),
        realm_id.as_str(),
    );
    client_service
        .load_client_protocols_by_client_id(realm_id.as_str(), realm_id.as_str())
        .await
}

#[get("/admin/realms/{realm_id}/client/{client_id}/service_account")]
pub async fn load_client_associated_service_account(
    realm_id: web::Path<String>,
    client_id: web::Path<String>,
    context: web::Data<DarkShieldContext>,
) -> impl Responder {
    let client_service: &dyn IClientService = context.services().resolve_ref();
    log::info!(
        "Loading client: {} associated service acount for realm: {}",
        client_id.as_str(),
        realm_id.as_str(),
    );
    client_service
        .load_associated_service_acount_by_client_id(realm_id.as_str(), realm_id.as_str())
        .await
}
