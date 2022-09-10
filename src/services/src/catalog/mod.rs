use crate::services::{
    auth_services::{
        AuthenticationExecutionService, AuthenticationFlowService, AuthenticatorConfigService,
        RequiredActionService,
    },
    authz_services::{
        GroupService, IdentityProviderService, ResourceServerService, ResourceService, RoleService,
        ScopeService,
    },
    client_services::{ClientScopeService, ClientService, ProtocolMapperService},
    realm_service::RealmService,
    user_service::UserService,
};

use shaku::{module, Component, HasComponent, Interface};

use store::providers::rds::{
    client::postgres_client::DataBaseManager,
    loaders::{
        rds_auth_providers::*,
        rds_authz_providers::{
            RdsGroupProvider, RdsIdentityProvider, RdsResourceProvider, RdsResourceServerProvider,
            RdsRoleProvider, RdsScopeProvider,
        },
        rds_client_provider::{
            RdsClientProvider, RdsClientScopeProvider, RdsProtocolMapperProvider,
        },
        rds_realm_provider::RdsRealmProvider,
        rds_user_provider::RdsUserProvider,
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
            RdsClientScopeProvider,
            RdsProtocolMapperProvider,
            RdsClientProvider,
            RdsScopeProvider,
            RdsResourceServerProvider,
            RdsResourceProvider,
            RdsUserProvider,
            RealmService,
            RoleService,
            GroupService,
            RequiredActionService,
            IdentityProviderService,
            AuthenticationExecutionService,
            AuthenticationFlowService,
            AuthenticatorConfigService,
            ClientScopeService,
            ProtocolMapperService,
            ClientService,
            ResourceServerService,
            ScopeService,
            ResourceService,
            UserService,
        ],
        providers = [],
    }
}
