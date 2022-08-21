use services::catalog::catalog::DarkshieldServices;

#[allow(dead_code)]
pub struct DarkShieldContext {
    services: DarkshieldServices,
}

impl DarkShieldContext {
    pub fn new(services: DarkshieldServices) -> Self {
        Self { services: services }
    }

    pub fn services(&self) -> &DarkshieldServices {
        &self.services
    }
}
