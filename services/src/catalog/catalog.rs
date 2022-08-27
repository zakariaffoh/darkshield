use crate::services::{realm_service::RealmService, authz_services::{RoleService, GroupService}, auth_services::RequiredActionService};
#[allow(unused_extern_crates)]
use shaku::{module, Component, HasComponent, Interface};

use store::providers::rds::{
    client::postgres_client::DataBaseManager,
    loaders::{
        rds_authz_providers::{RdsGroupProvider, RdsRoleProvider},
        rds_realm_provider::RdsRealmProvider,
        rds_auth_providers::RdsRequiredActionProvider,
    },
};

module! {
     pub DarkshieldServices {
        components = [
            DataBaseManager, 
            RdsRealmProvider,
            RdsGroupProvider, 
            RdsRoleProvider, 
            RdsRequiredActionProvider,
            RealmService,
            RoleService, 
            GroupService,
            RequiredActionService,
        ],
        providers = [],
    }
}

#[cfg(test)]
mod tests {

}
