use crate::services::realm_service::RealmService;
use shaku::{module, Component, HasComponent, Interface};

use store::providers::rds::{
    client::postgres_client::DataBaseManager,
    loaders::{
        rds_authz_providers::{RdsGroupProvider, RdsRoleProvider},
        rds_realm_provider::RdsRealmProvider,
    },
};

module! {
     pub DarkshieldServices {
        components = [DataBaseManager, RdsRealmProvider, RdsGroupProvider, RdsRoleProvider, RealmService],
        providers = [],
    }
}

#[cfg(test)]
mod tests {
    use crate::services::realm_service::IRealmService;

    use super::*;
    use store::providers::rds::client::postgres_client::DataBaseManagerParameters;

    #[test]
    fn test_build_services() {
        let module = DarkshieldServices::builder()
            .with_component_parameters::<DataBaseManager>(DataBaseManagerParameters {
                connection_pool: None,
            })
            .build();
    }
}
