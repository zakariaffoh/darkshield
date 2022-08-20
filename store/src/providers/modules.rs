use shaku::module;

use super::rds::loaders::{
    rds_authz_providers::{RdsGroupProvider, RdsRoleProvider},
    rds_realm_provider::RdsRealmProvider,
};

module! {
     pub RdsModules {
        components = [RdsRealmProvider, RdsGroupProvider, RdsRoleProvider],
        providers = []
    }
}
