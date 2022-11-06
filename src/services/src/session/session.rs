#[allow(unused)]
use shaku::{module, Component, HasComponent, Interface};
use std::sync::Arc;

use crate::factory::IDarkShieldServices;

use super::context::DarkshieldContext;

pub struct DarkshieldSession {
    context: Arc<DarkshieldContext>,
    services: Arc<dyn IDarkShieldServices>,
}

impl Clone for DarkshieldSession {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            services: self.services.clone(),
        }
    }
}

impl DarkshieldSession {
    pub fn new(services: Arc<dyn IDarkShieldServices>, context: Arc<DarkshieldContext>) -> Self {
        Self {
            context: Arc::clone(&context),
            services: Arc::clone(&services),
        }
    }

    pub fn context(&self) -> &Arc<DarkshieldContext> {
        &self.context
    }
    pub fn services(&self) -> &Arc<dyn IDarkShieldServices> {
        &self.services
    }
}
