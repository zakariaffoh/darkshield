pub mod core;
pub mod interfaces;
pub mod rds;

/*use shaku::{module, ModuleInterface};

use rds::loaders::{
    rds_authz_providers::{RdsGroupProvider, RdsRoleProvider},
    rds_realm_provider::RdsRealmProvider,
};

use self::rds::client::postgres_client::DataBaseManager;

module! {
     pub RdsModules {
        components = [RdsRealmProvider, RdsGroupProvider, RdsRoleProvider, DataBaseManager],
        providers = []
    }
}*/
