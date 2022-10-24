use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OidcConfiguration {
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    introspection_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    jwks_uri: Option<String>,
    registration_endpoint: Option<String>,
    grant_types_supported: Option<Vec<String>>,
    id_token_signing_alg_values_supported: Option<Vec<String>>,
    id_token_encryption_alg_values_supported: Option<Vec<String>>,
    id_token_encryption_enc_values_supported: Option<Vec<String>>,
    user_info_signing_alg_values_supported: Option<Vec<String>>,
    request_object_signing_alg_values_supported: Option<Vec<String>>,
    request_object_encryption_alg_values_supported: Option<Vec<String>>,
    request_object_encryption_enc_values_supported: Option<Vec<String>>,
    response_types_supported: Option<Vec<String>>,
    response_modes_supported: Option<Vec<String>>,
    subject_types_supported: Option<Vec<String>>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    claims_supported: Option<Vec<String>>,
    claims_parameter_supported: Option<bool>,
    claim_types_supported: Option<Vec<String>>,
    authorization_signing_alg_values_supported: Option<Vec<String>>,
    authorization_encryption_alg_values_supported: Option<Vec<String>>,
    authorization_encryption_enc_values_supported: Option<Vec<String>>,
    scopes_supported: Option<Vec<String>>,
    request_uri_parameter_supported: Option<bool>,
    request_parameter_supported: Option<bool>,
    require_request_uri_registration: Option<bool>,
    revocation_endpoint: Option<String>,
    pushed_authorization_request_endpoint: Option<String>,
    require_pushed_authorization_requests: Option<bool>,
    revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    code_challenge_methods_supported: Option<bool>,
}

impl OidcConfiguration {
    pub fn new() -> Self {
        Self {
            issuer: Default::default(),
            authorization_endpoint: Default::default(),
            token_endpoint: Default::default(),
            introspection_endpoint: Default::default(),
            userinfo_endpoint: Default::default(),
            end_session_endpoint: Default::default(),
            jwks_uri: Default::default(),
            registration_endpoint: Default::default(),
            grant_types_supported: Default::default(),
            id_token_signing_alg_values_supported: Default::default(),
            id_token_encryption_alg_values_supported: Default::default(),
            id_token_encryption_enc_values_supported: Default::default(),
            user_info_signing_alg_values_supported: Default::default(),
            request_object_signing_alg_values_supported: Default::default(),
            request_object_encryption_alg_values_supported: Default::default(),
            request_object_encryption_enc_values_supported: Default::default(),
            response_types_supported: Default::default(),
            response_modes_supported: Default::default(),
            subject_types_supported: Default::default(),
            token_endpoint_auth_methods_supported: Default::default(),
            token_endpoint_auth_signing_alg_values_supported: Default::default(),
            introspection_endpoint_auth_methods_supported: Default::default(),
            introspection_endpoint_auth_signing_alg_values_supported: Default::default(),
            claims_supported: Default::default(),
            claims_parameter_supported: Default::default(),
            claim_types_supported: Default::default(),
            authorization_signing_alg_values_supported: Default::default(),
            authorization_encryption_alg_values_supported: Default::default(),
            authorization_encryption_enc_values_supported: Default::default(),
            scopes_supported: Default::default(),
            request_uri_parameter_supported: Default::default(),
            request_parameter_supported: Default::default(),
            require_request_uri_registration: Default::default(),
            revocation_endpoint: Default::default(),
            revocation_endpoint_auth_signing_alg_values_supported: Default::default(),
            revocation_endpoint_auth_methods_supported: Default::default(),
            code_challenge_methods_supported: Default::default(),
            pushed_authorization_request_endpoint: Default::default(),
            require_pushed_authorization_requests: Default::default(),
        }
    }

    pub fn issuer(&self) -> &Option<String> {
        &self.issuer
    }

    pub fn set_issuer(&mut self, issuer: impl Into<String>) {
        self.issuer = Some(issuer.into());
    }

    pub fn authorization_endpoint(&self) -> &Option<String> {
        &self.authorization_endpoint
    }

    pub fn set_authorization_endpoint(&mut self, authorization_endpoint: impl Into<String>) {
        self.authorization_endpoint = Some(authorization_endpoint.into());
    }

    pub fn token_endpoint(&self) -> &Option<String> {
        &self.token_endpoint
    }

    pub fn set_token_endpoint(&mut self, token_endpoint: impl Into<String>) {
        self.token_endpoint = Some(token_endpoint.into());
    }

    pub fn introspection_endpoint(&self) -> &Option<String> {
        &self.introspection_endpoint
    }

    pub fn set_introspection_endpoint(&mut self, introspection_endpoint: impl Into<String>) {
        self.introspection_endpoint = Some(introspection_endpoint.into());
    }

    pub fn userinfo_endpoint(&self) -> &Option<String> {
        &self.userinfo_endpoint
    }

    pub fn set_userinfo_endpoint(&mut self, userinfo_endpoint: impl Into<String>) {
        self.userinfo_endpoint = Some(userinfo_endpoint.into());
    }

    pub fn end_session_endpoint(&self) -> &Option<String> {
        &self.end_session_endpoint
    }

    pub fn set_end_session_endpoint(&mut self, end_session_endpoint: impl Into<String>) {
        self.end_session_endpoint = Some(end_session_endpoint.into());
    }

    pub fn jwks_uri(&self) -> &Option<String> {
        &self.jwks_uri
    }

    pub fn set_jwks_uri(&mut self, jwks_uri: impl Into<String>) {
        self.jwks_uri = Some(jwks_uri.into());
    }

    pub fn grant_types_supported(&self) -> &Option<Vec<String>> {
        &self.grant_types_supported
    }

    pub fn set_grant_types_supported(&mut self, grant_types_supported: Vec<String>) {
        self.grant_types_supported = Some(grant_types_supported);
    }

    pub fn registration_endpoint(&self) -> &Option<String> {
        &self.registration_endpoint
    }

    pub fn set_registration_endpoint(&mut self, registration_endpoint: impl Into<String>) {
        self.registration_endpoint = Some(registration_endpoint.into());
    }

    pub fn id_token_signing_alg_values_supported(&self) -> &Option<Vec<String>> {
        &self.id_token_signing_alg_values_supported
    }

    pub fn set_id_token_signing_alg_values_supported(
        &mut self,
        id_token_signing_alg_values_supported: Vec<String>,
    ) {
        self.id_token_signing_alg_values_supported =
            Some(id_token_signing_alg_values_supported.into());
    }

    pub fn id_token_encryption_alg_values_supported(&self) -> &Option<Vec<String>> {
        &self.id_token_encryption_alg_values_supported
    }

    pub fn set_id_token_encryption_alg_values_supported(
        &mut self,
        id_token_encryption_alg_values_supported: Vec<String>,
    ) {
        self.id_token_encryption_alg_values_supported =
            Some(id_token_encryption_alg_values_supported.into());
    }

    pub fn id_token_encryption_enc_values_supported(&self) -> &Option<Vec<String>> {
        &self.id_token_encryption_enc_values_supported
    }

    pub fn set_id_token_encryption_enc_values_supported(
        &mut self,
        id_token_encryption_enc_values_supported: Vec<String>,
    ) {
        self.id_token_encryption_enc_values_supported =
            Some(id_token_encryption_enc_values_supported.into());
    }

    pub fn user_info_signing_alg_values_supported(&self) -> &Option<Vec<String>> {
        &self.user_info_signing_alg_values_supported
    }

    pub fn set_user_info_signing_alg_values_supported(
        &mut self,
        user_info_signing_alg_values_supported: Vec<String>,
    ) {
        self.user_info_signing_alg_values_supported =
            Some(user_info_signing_alg_values_supported.into());
    }

    pub fn request_object_signing_alg_values_supported(&self) -> &Option<Vec<String>> {
        &self.request_object_signing_alg_values_supported
    }

    pub fn set_request_object_signing_alg_values_supported(
        &mut self,
        request_object_signing_alg_values_supported: Vec<String>,
    ) {
        self.request_object_signing_alg_values_supported =
            Some(request_object_signing_alg_values_supported.into());
    }

    pub fn request_object_encryption_alg_values_supported(&self) -> &Option<Vec<String>> {
        &self.request_object_encryption_alg_values_supported
    }

    pub fn set_request_object_encryption_alg_values_supported(
        &mut self,
        request_object_encryption_alg_values_supported: Vec<String>,
    ) {
        self.request_object_encryption_alg_values_supported =
            Some(request_object_encryption_alg_values_supported.into());
    }

    pub fn request_object_encryption_enc_values_supported(&self) -> &Option<Vec<String>> {
        &self.request_object_encryption_enc_values_supported
    }

    pub fn set_request_object_encryption_enc_values_supported(
        &mut self,
        request_object_encryption_enc_values_supported: Vec<String>,
    ) {
        self.request_object_encryption_enc_values_supported =
            Some(request_object_encryption_enc_values_supported.into());
    }

    pub fn response_modes_supported(&self) -> &Option<Vec<String>> {
        &self.response_modes_supported
    }

    pub fn set_response_modes_supported(&mut self, response_modes_supported: Vec<String>) {
        self.response_modes_supported = Some(response_modes_supported);
    }

    pub fn response_types_supported(&self) -> &Option<Vec<String>> {
        &self.response_types_supported
    }

    pub fn set_response_types_supported(&mut self, response_types_supported: Vec<String>) {
        self.response_types_supported = Some(response_types_supported);
    }

    pub fn subject_types_supported(&self) -> &Option<Vec<String>> {
        &self.subject_types_supported
    }

    pub fn set_subject_types_supported(&mut self, subject_types_supported: Vec<String>) {
        self.subject_types_supported = Some(subject_types_supported);
    }

    pub fn token_endpoint_auth_methods_supported(&self) -> &Option<Vec<String>> {
        &self.token_endpoint_auth_methods_supported
    }

    pub fn set_token_endpoint_auth_methods_supported(
        &mut self,
        token_endpoint_auth_methods_supported: Vec<String>,
    ) {
        self.token_endpoint_auth_methods_supported =
            Some(token_endpoint_auth_methods_supported.into());
    }

    pub fn token_endpoint_auth_signing_alg_values_supported(&self) -> &Option<Vec<String>> {
        &self.token_endpoint_auth_signing_alg_values_supported
    }

    pub fn set_token_endpoint_auth_signing_alg_values_supported(
        &mut self,
        token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    ) {
        self.token_endpoint_auth_signing_alg_values_supported =
            Some(token_endpoint_auth_signing_alg_values_supported.into());
    }

    pub fn introspection_endpoint_auth_methods_supported(&self) -> &Option<Vec<String>> {
        &self.introspection_endpoint_auth_methods_supported
    }

    pub fn set_introspection_endpoint_auth_methods_supported(
        &mut self,
        introspection_endpoint_auth_methods_supported: Vec<String>,
    ) {
        self.introspection_endpoint_auth_methods_supported =
            Some(introspection_endpoint_auth_methods_supported.into());
    }

    pub fn introspection_endpoint_auth_signing_alg_values_supported(&self) -> &Option<Vec<String>> {
        &self.introspection_endpoint_auth_signing_alg_values_supported
    }

    pub fn set_introspection_endpoint_auth_signing_alg_values_supported(
        &mut self,
        introspection_endpoint_auth_signing_alg_values_supported: Vec<String>,
    ) {
        self.introspection_endpoint_auth_signing_alg_values_supported =
            Some(introspection_endpoint_auth_signing_alg_values_supported.into());
    }

    pub fn claim_types_supported(&self) -> &Option<Vec<String>> {
        &self.claim_types_supported
    }

    pub fn set_claim_types_supported(&mut self, claim_types_supported: Vec<String>) {
        self.claim_types_supported = Some(claim_types_supported);
    }

    pub fn claims_supported(&self) -> &Option<Vec<String>> {
        &self.claims_supported
    }

    pub fn set_claims_supported(&mut self, claims_supported: Vec<String>) {
        self.claims_supported = Some(claims_supported);
    }

    pub fn authorization_encryption_enc_values_supported(&self) -> &Option<Vec<String>> {
        &self.authorization_encryption_enc_values_supported
    }

    pub fn set_authorization_encryption_enc_values_supported(
        &mut self,
        authorization_encryption_enc_values_supported: Vec<String>,
    ) {
        self.authorization_encryption_enc_values_supported =
            Some(authorization_encryption_enc_values_supported.into());
    }

    pub fn authorization_encryption_alg_values_supported(&self) -> &Option<Vec<String>> {
        &self.authorization_encryption_alg_values_supported
    }

    pub fn set_authorization_encryption_alg_values_supported(
        &mut self,
        authorization_encryption_alg_values_supported: Vec<String>,
    ) {
        self.authorization_encryption_alg_values_supported =
            Some(authorization_encryption_alg_values_supported.into());
    }

    pub fn authorization_signing_alg_values_supported(&self) -> &Option<Vec<String>> {
        &self.authorization_signing_alg_values_supported
    }

    pub fn set_authorization_signing_alg_values_supported(
        &mut self,
        authorization_signing_alg_values_supported: Vec<String>,
    ) {
        self.authorization_signing_alg_values_supported =
            Some(authorization_signing_alg_values_supported);
    }

    pub fn scopes_supported(&self) -> &Option<Vec<String>> {
        &self.scopes_supported
    }

    pub fn set_scopes_supported(&mut self, scopes_supported: Vec<String>) {
        self.scopes_supported = Some(scopes_supported);
    }

    pub fn request_parameter_supported(&self) -> &Option<bool> {
        &self.request_parameter_supported
    }

    pub fn set_request_parameter_supported(
        &mut self,
        request_parameter_supported: impl Into<bool>,
    ) {
        self.request_parameter_supported = Some(request_parameter_supported.into());
    }

    pub fn request_uri_parameter_supported(&self) -> &Option<bool> {
        &self.request_uri_parameter_supported
    }

    pub fn set_request_uri_parameter_supported(
        &mut self,
        request_uri_parameter_supported: impl Into<bool>,
    ) {
        self.request_uri_parameter_supported = Some(request_uri_parameter_supported.into());
    }

    pub fn require_request_uri_registration(&self) -> &Option<bool> {
        &self.require_request_uri_registration
    }

    pub fn set_require_request_uri_registration(
        &mut self,
        require_request_uri_registration: impl Into<bool>,
    ) {
        self.require_request_uri_registration = Some(require_request_uri_registration.into());
    }

    pub fn require_pushed_authorization_requests(&self) -> &Option<bool> {
        &self.require_pushed_authorization_requests
    }

    pub fn set_require_pushed_authorization_requests(
        &mut self,
        require_pushed_authorization_requests: impl Into<bool>,
    ) {
        self.require_pushed_authorization_requests =
            Some(require_pushed_authorization_requests.into());
    }

    pub fn claims_parameter_supported(&self) -> &Option<bool> {
        &self.claims_parameter_supported
    }

    pub fn set_claims_parameter_supported(&mut self, claims_parameter_supported: impl Into<bool>) {
        self.claims_parameter_supported = Some(claims_parameter_supported.into());
    }

    pub fn code_challenge_methods_supported(&self) -> &Option<bool> {
        &self.code_challenge_methods_supported
    }

    pub fn set_code_challenge_methods_supported(
        &mut self,
        code_challenge_methods_supported: impl Into<bool>,
    ) {
        self.code_challenge_methods_supported = Some(code_challenge_methods_supported.into());
    }

    pub fn revocation_endpoint(&self) -> &Option<String> {
        &self.revocation_endpoint
    }

    pub fn set_revocation_endpoint(&mut self, revocation_endpoint: impl Into<String>) {
        self.revocation_endpoint = Some(revocation_endpoint.into());
    }

    pub fn revocation_endpoint_auth_methods_supported(&self) -> &Option<Vec<String>> {
        &self.revocation_endpoint_auth_methods_supported
    }

    pub fn set_revocation_endpoint_auth_methods_supported(
        &mut self,
        revocation_endpoint_auth_methods_supported: Vec<String>,
    ) {
        self.revocation_endpoint_auth_methods_supported =
            Some(revocation_endpoint_auth_methods_supported.into());
    }

    pub fn revocation_endpoint_auth_signing_alg_values_supported(&self) -> &Option<Vec<String>> {
        &self.revocation_endpoint_auth_signing_alg_values_supported
    }

    pub fn set_revocation_endpoint_auth_signing_alg_values_supported(
        &mut self,
        revocation_endpoint_auth_signing_alg_values_supported: Vec<String>,
    ) {
        self.revocation_endpoint_auth_signing_alg_values_supported =
            Some(revocation_endpoint_auth_signing_alg_values_supported.into());
    }

    pub fn pushed_authorization_request_endpoint(&self) -> &Option<String> {
        &self.pushed_authorization_request_endpoint
    }

    pub fn set_pushed_authorization_request_endpoint(
        &mut self,
        pushed_authorization_request_endpoint: impl Into<String>,
    ) {
        self.pushed_authorization_request_endpoint =
            Some(pushed_authorization_request_endpoint.into());
    }
}
