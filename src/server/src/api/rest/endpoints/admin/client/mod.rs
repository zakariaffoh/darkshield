use actix_web::{
    delete, get, post, put,
    web::{self},
    Responder,
};
use log;
use shaku::HasComponent;

use crate::api::services::client_api::ClientApi;
use services::session::session::DarkshieldSession;

use models::entities::client::{
    ClientCreateModel, ClientModel, ClientScopeModel, ClientScopeMutationModel, ClientUpdateModel,
    ProtocolMapperModel, ProtocolMapperMutationModel,
};
use services::services::client_services::IClientScopeService;

#[post("/realm/{realm_id}/client/{client_id}")]
pub async fn create_client(
    params: web::Path<(String, String)>,
    client: web::Json<ClientCreateModel>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let mut client_model: ClientModel = client.0.into();
    let (realm_id, client_id) = params.into_inner();
    client_model.realm_id = realm_id;
    client_model.client_id = client_id;
    log::info!(
        "Creating client: {} for realm: {}",
        &client_model.client_id,
        &client_model.realm_id,
    );
    ClientApi::create_client(&context, client_model).await
}

#[put("/realm/{realm_id}/client/{client_id}")]
pub async fn update_client(
    params: web::Path<(String, String)>,
    client: web::Json<ClientUpdateModel>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id) = params.into_inner();
    let mut client_model: ClientModel = client.0.into();
    client_model.realm_id = realm_id.to_string();
    client_model.client_id = client_id.to_string();
    log::info!(
        "Updating client: {} for realm: {}",
        &client_model.client_id,
        realm_id.as_str()
    );
    ClientApi::update_client(&context, client_model).await
}

#[get("/realm/{realm_id}/client/{client_id}")]
pub async fn load_client_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id) = params.into_inner();
    log::info!(
        "loading client: {} for realm: {}",
        client_id.as_str(),
        realm_id.as_str()
    );
    ClientApi::load_client_by_id(&context, &realm_id, &client_id).await
}

#[delete("/realm/{realm_id}/client/{client_id}")]
pub async fn delete_client_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id) = params.into_inner();
    log::info!(
        "Delete client: {} for realm: {}",
        client_id.as_str(),
        realm_id.as_str()
    );
    ClientApi::delete_client(&context, &realm_id, &client_id).await
}

#[put("/realm/{realm_id}/client/{client_id}/role/{role_id}")]
pub async fn client_add_client_roles_mapping(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id, role_id) = params.into_inner();
    log::info!(
        "Add client: {} role: {}  mapping for realm: {}",
        &role_id,
        &client_id,
        &realm_id,
    );
    ClientApi::add_client_role_mapping(&context, &realm_id, &client_id, &role_id).await
}

#[delete("/realm/{realm_id}/client/{client_id}/role/{role_id}")]
pub async fn client_remove_client_roles_mapping(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id, role_id) = params.into_inner();
    log::info!(
        "Removing client: {} role: {}  mapping for realm: {}",
        role_id.as_str(),
        client_id.as_str(),
        realm_id.as_str(),
    );
    ClientApi::remove_client_role_mapping(&context, &realm_id, &client_id, &role_id).await
}

#[get("/realm/{realm_id}/client/{client_id}/roles_mapping")]
pub async fn client_load_client_roles_mapping(
    params: web::Path<(String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id) = params.into_inner();
    log::info!(
        "Loading client: {} roles mapping for realm: {}",
        client_id.as_str(),
        realm_id.as_str(),
    );
    ClientApi::load_client_roles_mapping(&context, &realm_id, &client_id).await
}

#[put("/realm/{realm_id}/client/{client_id}/client_scope/{client_scope_id}")]
pub async fn client_add_client_scope_mapping(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id, client_scope_id) = params.into_inner();
    log::info!(
        "Adding client: {} scope: {} mapping  for realm: {}",
        client_id.as_str(),
        client_scope_id.as_str(),
        realm_id.as_str(),
    );
    ClientApi::add_client_scope_mapping(&context, &realm_id, &client_id, &client_scope_id).await
}

#[delete("/realm/{realm_id}/client/{client_id}/client_scope/{client_scope_id}")]
pub async fn client_remove_client_scope_mapping(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id, client_scope_id) = params.into_inner();
    log::info!(
        "Removing client: {} scope: {} mapping  for realm: {}",
        client_id.as_str(),
        client_scope_id.as_str(),
        realm_id.as_str(),
    );
    ClientApi::remove_client_scope_mapping(&context, &realm_id, &client_id, &client_scope_id).await
}

#[get("/realm/{realm_id}/client/{client_id}/client_scopes/all")]
pub async fn client_load_client_scopes_by_client_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id) = params.into_inner();
    log::info!(
        "Loading client: {} scopes mapping for realm: {}",
        client_id.as_str(),
        realm_id.as_str(),
    );
    ClientApi::load_client_scopes_by_client_id(&context, &realm_id, &client_id).await
}

#[put("/realm/{realm_id}/client/{client_id}/protocol_mapper/{mapper_id}")]
pub async fn client_add_client_protocol_mapper(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id, mapper_id) = params.into_inner();
    log::info!(
        "Add client: {} protocol mapper: {} mapping for realm: {}",
        client_id.as_str(),
        mapper_id.as_str(),
        realm_id.as_str(),
    );
    ClientApi::add_client_protocol_mapping(&context, &realm_id, &client_id, &mapper_id).await
}

#[delete("/realm/{realm_id}/client/{client_id}/protocol_mapper/{mapper_id}")]
pub async fn client_remove_client_protocol_mapper(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id, mapper_id) = params.into_inner();
    log::info!(
        "Removing client: {} protocol mapper: {} mapping  for realm: {}",
        &client_id,
        &mapper_id,
        &realm_id,
    );
    ClientApi::remove_client_protocol_mapping(&context, &realm_id, &client_id, &mapper_id).await
}

#[get("/realm/{realm_id}/client/{client_id}/protocol_mappers/all")]
pub async fn client_load_client_protocol_mappers(
    params: web::Path<(String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id) = params.into_inner();
    log::info!(
        "Loading client: {} protocol mappers  for realm: {}",
        client_id.as_str(),
        realm_id.as_str(),
    );
    ClientApi::load_protocol_mappers_by_client_id(&context, &realm_id, &client_id).await
}

#[get("/realm/{realm_id}/client/{client_id}/service_account")]
pub async fn client_load_associated_service_account(
    params: web::Path<(String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id) = params.into_inner();
    log::info!(
        "Loading client: {} associated service acount for realm: {}",
        client_id.as_str(),
        realm_id.as_str(),
    );
    ClientApi::load_associated_service_acount_by_client_id(&context, &realm_id, &client_id).await
}

#[post("/realm/{realm_id}/client_scope/create")]
pub async fn create_client_scope(
    realm_id: web::Path<String>,
    scope: web::Json<ClientScopeMutationModel>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let mut client_scope_model: ClientScopeModel = scope.0.into();
    client_scope_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating client scope: {} for realm: {}",
        &client_scope_model.name,
        realm_id.as_str()
    );
    ClientApi::create_client_scope(&context, client_scope_model).await
}

#[put("/realm/{realm_id}/client_scope/{client_scope_id}")]
pub async fn update_client_scope(
    params: web::Path<(String, String)>,
    scope: web::Json<ClientScopeMutationModel>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_scope_id) = params.into_inner();
    let mut client_scope_model: ClientScopeModel = scope.0.into();
    client_scope_model.realm_id = realm_id.to_string();
    client_scope_model.client_scope_id = client_scope_id.to_string();
    log::info!(
        "updating client scope {}, realm: {}",
        client_scope_id,
        realm_id
    );
    ClientApi::update_client_scope(&context, client_scope_model).await
}

#[get("/realm/{realm_id}/client_scope/{client_scope_id}")]
pub async fn client_scope_load_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_scope_id) = params.into_inner();
    log::info!(
        "Loading client scope: {}, for realm: {}",
        client_scope_id.as_str(),
        realm_id.as_str()
    );
    ClientApi::load_client_scope_by_scope_id(&context, &realm_id, &client_scope_id).await
}

#[delete("/realm/{realm_id}/client_scope/{client_scope_id}")]
pub async fn client_scope_delete_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_scope_id) = params.into_inner();
    log::info!(
        "Deleting client scope: {}, for realm: {}",
        client_scope_id.as_str(),
        realm_id.as_str()
    );
    ClientApi::delete_client_scope(&context, &realm_id, &client_scope_id).await
}

#[put("/realm/{realm_id}/client_scope/{client_scope_id}/protocol_mapper/{mapper_id}")]
pub async fn client_scope_add_protocol_mapper(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_scope_id, mapper_id) = params.into_inner();
    log::info!(
        "Adding client scope: {}, protocol mapper: {} for realm: {}",
        client_scope_id.as_str(),
        mapper_id.as_str(),
        realm_id.as_str()
    );

    ClientApi::add_client_scope_protocol_mapper(&context, &realm_id, &client_scope_id, &mapper_id)
        .await
}

#[delete("/realm/{realm_id}/client_scope/{client_scope_id}/protocol_mapper/{mapper_id}")]
pub async fn client_scope_remove_protocol_mapper(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let client_scope_service: &dyn IClientScopeService = context.services().resolve_ref();
    let (realm_id, client_scope_id, mapper_id) = params.into_inner();

    log::info!(
        "Deleting client scope: {}, protocol mapper: {} for realm: {}",
        client_scope_id.as_str(),
        mapper_id.as_str(),
        realm_id.as_str()
    );
    ClientApi::remove_client_scope_protocol_mapper(
        &context,
        &realm_id,
        &client_scope_id,
        &mapper_id,
    )
    .await
}

#[put("/realm/{realm_id}/client_scope/{client_scope_id}/role/{role_id}")]
pub async fn client_scope_add_role_mapping(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_scope_id, role_id) = params.into_inner();

    log::info!(
        "Adding client scope: {}, role: {} for realm: {}",
        client_scope_id.as_str(),
        role_id.as_str(),
        realm_id.as_str()
    );

    ClientApi::add_client_scope_role_mapping(
        &context,
        &realm_id,
        &client_scope_id,
        &role_id.as_str(),
    )
    .await
}

#[delete("/realm/{realm_id}/client_scope/{client_scope_id}/role/{role_id}")]
pub async fn client_scope_remove_role_mapping(
    params: web::Path<(String, String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_scope_id, role_id) = params.into_inner();
    log::info!(
        "Deleting client scope: {}, role: {} for realm: {}",
        client_scope_id.as_str(),
        role_id.as_str(),
        realm_id.as_str()
    );

    ClientApi::remove_client_scope_role_mapping(
        &context,
        &realm_id,
        &client_scope_id,
        &role_id.as_str(),
    )
    .await
}

#[post("/realm/{realm_id}/protocol_mapper/create")]
pub async fn create_protocol_mapper(
    realm_id: web::Path<String>,
    mapper: web::Json<ProtocolMapperMutationModel>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let mut mapper_model: ProtocolMapperModel = mapper.0.into();
    mapper_model.realm_id = realm_id.to_string();
    log::info!(
        "Creating protocol mapper: {} for realm: {}",
        &mapper_model.name,
        realm_id.as_str()
    );
    ClientApi::create_protocol_mapper(&context, mapper_model).await
}

#[put("/realm/{realm_id}/protocol_mapper/{mapper_id}")]
pub async fn update_protocol_mapper(
    params: web::Path<(String, String)>,
    mapper: web::Json<ProtocolMapperMutationModel>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, mapper_id) = params.into_inner();
    let mut mapper_model: ProtocolMapperModel = mapper.0.into();
    mapper_model.realm_id = realm_id.to_string();
    mapper_model.mapper_id = mapper_id.to_string();
    log::info!(
        "updating protocol mapper: {}, realm: {}",
        mapper_id.as_str(),
        realm_id.as_str()
    );
    ClientApi::update_protocol_mapper(&context, mapper_model).await
}

#[get("/realm/{realm_id}/protocol_mapper/{mapper_id}")]
pub async fn protocol_mapper_load_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, mapper_id) = params.into_inner();

    log::info!(
        "Loading protocol mapper: {}, for realm: {}",
        mapper_id.as_str(),
        realm_id.as_str()
    );
    ClientApi::load_protocol_mapper_by_mapper_id(&context, &realm_id, &mapper_id).await
}

#[delete("/realm/{realm_id}/protocol_mapper/{mapper_id}")]
pub async fn protocol_mappers_delete_by_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, mapper_id) = params.into_inner();
    log::info!(
        "Deleting protocol mapper by mapper_id: {} for realm: {}",
        mapper_id.as_str(),
        realm_id.as_str()
    );

    ClientApi::delete_protocol_mapper(&context, &realm_id, &mapper_id).await
}

#[get("/realm/{realm_id}/protocol_mappers/protocol/{protocol}")]
pub async fn protocol_mappers_load_by_protocol(
    params: web::Path<(String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, protocol) = params.into_inner();
    log::info!(
        "Loading protocol mapper by protocol: {} for realm: {}",
        protocol.as_str(),
        realm_id.as_str()
    );
    ClientApi::load_protocol_mapper_by_protocol(&context, &realm_id, &protocol).await
}

#[get("/realm/{realm_id}/protocol_mapper/client/{client_id}")]
pub async fn protocol_mappers_load_by_client_id(
    params: web::Path<(String, String)>,
    context: web::Data<DarkshieldSession>,
) -> impl Responder {
    let (realm_id, client_id) = params.into_inner();
    log::info!(
        "Loading protocol mapper for client id: {}, for realm: {}",
        client_id.as_str(),
        realm_id.as_str()
    );
    ClientApi::load_protocol_mappers_by_client_id(&context, &realm_id, &client_id).await
}
