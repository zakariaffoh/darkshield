use crate::services::{realm_service::RealmService, authz_services::*, auth_services::*};
use crate::services::authz_services::*;
use crate::services::auth_services::*;

#[allow(unused_extern_crates)]
use shaku::{module, Component, HasComponent, Interface};

use store::providers::rds::{
    client::postgres_client::DataBaseManager,
    loaders::{
        rds_authz_providers::*,
        rds_realm_provider::RdsRealmProvider,
        rds_auth_providers::*,
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
            RdsIdentityProvider,
            RdsAuthenticationExecutionProvider,
            RdsAuthenticationFlowProvider,
            RdsAuthenticatorConfigProvider,
            RealmService,
            RoleService, 
            GroupService,
            RequiredActionService,
            IdentityProviderService,
            AuthenticationExecutionService,
            AuthenticationFlowService,
            AuthenticatorConfigService,
        ],
        providers = [],
    }
}

