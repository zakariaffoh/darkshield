use std::sync::Arc;

use crate::services::{
    auth_services::{
        AuthenticationExecutionService, AuthenticationFlowService, AuthenticatorConfigService,
        IAuthenticationExecutionService, IAuthenticationFlowService, IAuthenticatorConfigService,
        IRequiredActionService, RequiredActionService,
    },
    authz_services::{
        GroupService, IGroupService, IIdentityProviderService, IPolicyService,
        IResourceServerService, IResourceService, IRoleService, IScopeService,
        IdentityProviderService, PolicyService, ResourceServerService, ResourceService,
        RoleService, ScopeService,
    },
    client_services::{
        ClientScopeService, ClientService, IClientScopeService, IClientService,
        IProtocolMapperService, ProtocolMapperService,
    },
    credentials_services::{IUserCredentialService, UserCredentialService, UserCredentialStore},
    health_check::{HealthCheckService, IHealthCheckService},
    realm_service::{IRealmService, RealmService},
    tokens_services::{RevokedTokenStoreService, SingleUseTokenService},
    user_services::{
        IUserService, UserActionService, UserConsentService, UserImpersonationService, UserService,
    },
};

#[allow(unused)]
use shaku::{module, Component, HasComponent, Interface};

use store::providers::rds::{
    client::postgres_client::DataBaseManager,
    loaders::{
        rds_auth_providers::*,
        rds_authz_providers::{
            RdsGroupProvider, RdsIdentityProvider, RdsPolicyProvider, RdsResourceProvider,
            RdsResourceServerProvider, RdsRoleProvider, RdsScopeProvider,
        },
        rds_client_provider::{
            RdsClientProvider, RdsClientScopeProvider, RdsProtocolMapperProvider,
        },
        rds_credential_provider::RdsCredentialProvider,
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
     pub DarkshieldServicesCatalog {
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
            RdsCredentialProvider,
            RdsPolicyProvider,
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
            UserCredentialService,
            UserCredentialStore,
            PolicyService,
        ],
        providers = [],
    }
}

pub trait IDarkShieldServices {
    fn role_service(&self) -> Arc<dyn IRoleService>;
    fn group_service(&self) -> Arc<dyn IGroupService>;
    fn realm_service(&self) -> Arc<dyn IRealmService>;
    fn client_scope_service(&self) -> Arc<dyn IClientScopeService>;
    fn health_check_service(&self) -> Arc<dyn IHealthCheckService>;
    fn authentication_execution_service(&self) -> Arc<dyn IAuthenticationExecutionService>;
    fn authentication_flow_service(&self) -> Arc<dyn IAuthenticationFlowService>;
    fn authenticator_config_service(&self) -> Arc<dyn IAuthenticatorConfigService>;
    fn required_action_service(&self) -> Arc<dyn IRequiredActionService>;
    fn identity_provider_service(&self) -> Arc<dyn IIdentityProviderService>;
    fn resource_server_service(&self) -> Arc<dyn IResourceServerService>;
    fn resource_service(&self) -> Arc<dyn IResourceService>;
    fn scope_service(&self) -> Arc<dyn IScopeService>;
    fn policy_service(&self) -> Arc<dyn IPolicyService>;
    fn client_service(&self) -> Arc<dyn IClientService>;
    fn user_service(&self) -> Arc<dyn IUserService>;
    fn user_credential_service(&self) -> Arc<dyn IUserCredentialService>;
    fn protocol_mapper_service(&self) -> Arc<dyn IProtocolMapperService>;
}

pub struct DarkshieldServicesFactory {
    services: DarkshieldServicesCatalog,
}

impl DarkshieldServicesFactory {
    pub fn new(services: DarkshieldServicesCatalog) -> Self {
        Self { services: services }
    }
}

impl IDarkShieldServices for DarkshieldServicesFactory {
    fn group_service(&self) -> Arc<dyn IGroupService> {
        let role_service: Arc<dyn IGroupService> = self.services.resolve();
        return role_service;
    }

    fn realm_service(&self) -> Arc<dyn IRealmService> {
        let realm_service: Arc<dyn IRealmService> = self.services.resolve();
        return realm_service;
    }

    fn role_service(&self) -> Arc<dyn IRoleService> {
        let role_service: Arc<dyn IRoleService> = self.services.resolve();
        return role_service;
    }

    fn client_scope_service(&self) -> Arc<dyn IClientScopeService> {
        let client_scope_service: Arc<dyn IClientScopeService> = self.services.resolve();
        return client_scope_service;
    }

    fn health_check_service(&self) -> Arc<dyn IHealthCheckService> {
        let health_check: Arc<dyn IHealthCheckService> = self.services.resolve();
        health_check
    }
    fn authentication_execution_service(&self) -> Arc<dyn IAuthenticationExecutionService> {
        let authentication_execution_service: Arc<dyn IAuthenticationExecutionService> =
            self.services.resolve();
        authentication_execution_service
    }
    fn authentication_flow_service(&self) -> Arc<dyn IAuthenticationFlowService> {
        let authentication_flow_service: Arc<dyn IAuthenticationFlowService> =
            self.services.resolve();
        authentication_flow_service
    }
    fn authenticator_config_service(&self) -> Arc<dyn IAuthenticatorConfigService> {
        let authenticator_config_service: Arc<dyn IAuthenticatorConfigService> =
            self.services.resolve();
        authenticator_config_service
    }

    fn required_action_service(&self) -> Arc<dyn IRequiredActionService> {
        let required_action_service: Arc<dyn IRequiredActionService> = self.services.resolve();
        required_action_service
    }

    fn identity_provider_service(&self) -> Arc<dyn IIdentityProviderService> {
        let identity_provider_service: Arc<dyn IIdentityProviderService> = self.services.resolve();
        identity_provider_service
    }

    fn resource_server_service(&self) -> Arc<dyn IResourceServerService> {
        let resource_server_server: Arc<dyn IResourceServerService> = self.services.resolve();
        resource_server_server
    }
    fn resource_service(&self) -> Arc<dyn IResourceService> {
        let resource_service: Arc<dyn IResourceService> = self.services.resolve();
        resource_service
    }
    fn scope_service(&self) -> Arc<dyn IScopeService> {
        let scope_service: Arc<dyn IScopeService> = self.services.resolve();
        scope_service
    }
    fn policy_service(&self) -> Arc<dyn IPolicyService> {
        let policy_service: Arc<dyn IPolicyService> = self.services.resolve();
        policy_service
    }
    fn client_service(&self) -> Arc<dyn IClientService> {
        let client_service: Arc<dyn IClientService> = self.services.resolve();
        client_service
    }
    fn user_service(&self) -> Arc<dyn IUserService> {
        let user_service: Arc<dyn IUserService> = self.services.resolve();
        user_service
    }
    fn user_credential_service(&self) -> Arc<dyn IUserCredentialService> {
        let user_credential_service: Arc<dyn IUserCredentialService> = self.services.resolve();
        user_credential_service
    }
    fn protocol_mapper_service(&self) -> Arc<dyn IProtocolMapperService> {
        let protocol_mapper_service: Arc<dyn IProtocolMapperService> = self.services.resolve();
        protocol_mapper_service
    }
}
