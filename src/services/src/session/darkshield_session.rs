use crate::{catalog::DarkshieldServices, services::client_services::IClientScopeService};
use actix_web::http::Uri;
use futures::lock::Mutex;
use shaku::{module, Component, HasComponent, Interface};
use std::sync::Arc;

pub struct DarkshieldContext {
    uri: Uri,
}

impl DarkshieldContext {
    pub fn uri(&self) -> Uri {
        self.uri.clone()
    }
}

pub struct DarkshieldSession {
    context: Arc<Mutex<DarkshieldContext>>,
    services: Arc<DarkshieldServices>,
}

impl DarkshieldSession {
    pub fn context(&self) -> &Arc<Mutex<DarkshieldContext>> {
        &self.context
    }
    pub fn services(&self) -> &Arc<DarkshieldServices> {
        &self.services
    }

    pub fn client_scope_service(&self) -> &dyn IClientScopeService {
        let client_scope_service: &dyn IClientScopeService = self.services.resolve_ref();
        client_scope_service
    }
}
