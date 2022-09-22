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
    credentials_services::UserCredentialService,
    health_check::HealthCheckService,
    realm_service::RealmService,
    tokens_services::{RevokedTokenStoreService, SingleUseTokenService},
    user_services::{UserActionService, UserConsentService, UserImpersonationService, UserService},
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
        rds_health_check::RdsHealthCheckProvider,
        rds_login_failure::RdsUserLoginFailureProvider,
        rds_realm_provider::RdsRealmProvider,
        rds_session_providers::{
            RdsAuthenticationSessionProvider, RdsRootAuthenticationSessionProvider,
            RdsUserSessionProvider,
        },
        rds_tokens_providers::{RdsRevokedTokenStoreProvider, RdsSingleUseTokenProvider},
        rds_user_provider::RdsUserProvider,
    },
};

module! {
     pub DarkshieldServices {
        components = [
            DataBaseManager,
            RdsHealthCheckProvider,
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
            RdsUserLoginFailureProvider,
            RdsSingleUseTokenProvider,
            RdsRevokedTokenStoreProvider,
            RdsAuthenticationSessionProvider,
            RdsRootAuthenticationSessionProvider,
            RdsUserSessionProvider,
            HealthCheckService,
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
            SingleUseTokenService,
            RevokedTokenStoreService,
            UserConsentService,
            UserActionService,
            UserService,
            UserImpersonationService,
            UserCredentialService
        ],
        providers = [],
    }
}
