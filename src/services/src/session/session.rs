use futures::lock::{Mutex, MutexGuard};
use models::entities::user::UserModel;
#[allow(unused)]
use shaku::{module, Component, HasComponent, Interface};
use std::sync::Arc;

use crate::{factory::DarkshieldServicesFactory, services::client_services::IClientScopeService};

use super::context::DarkshieldContext;

pub struct DarkshieldSession {
    context: Arc<DarkshieldContext>,
    services: Arc<DarkshieldServicesFactory>,
}

impl DarkshieldSession {
    pub fn new(services: Arc<DarkshieldServicesFactory>, context: Arc<DarkshieldContext>) -> Self {
        Self {
            context: Arc::clone(&context),
            services: Arc::clone(&services),
        }
    }

    pub fn context(&self) -> &Arc<DarkshieldContext> {
        &self.context
    }
    pub fn services(&self) -> &Arc<DarkshieldServicesFactory> {
        &self.services
    }
    pub fn client_scope_service(&self) -> &dyn IClientScopeService {
        let client_scope_service: &dyn IClientScopeService = self.services.resolve_ref();
        return client_scope_service;
    }
}
