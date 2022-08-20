use services::{catalog::catalog::ServicesCatalog, services::relam_service::RealmService};
use store::providers::rds::client::postgres_client::DataBaseManager;

use crate::services::rds::database::rds_data_base;

#[allow(dead_code)]
pub struct DarkShieldContext {
    database: DataBaseManager,
    services: ServicesCatalog,
}

#[allow(dead_code)]
impl DarkShieldContext {
    pub fn new() -> Self {
        Self {
            database: rds_data_base(),
            services: ServicesCatalog::new(),
        }
    }

    pub fn database(&self) -> &DataBaseManager {
        &self.database
    }

    pub fn services(&self) -> &ServicesCatalog {
        &self.services
    }
}

pub fn build_darkshield_context() -> DarkShieldContext {
    let mut services = ServicesCatalog::new();
    services.register(
        std::any::type_name::<RealmService>().to_owned(),
        Box::new(RealmService::new()),
    );
    DarkShieldContext::new()
}
