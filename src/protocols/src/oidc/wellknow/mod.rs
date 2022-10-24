use std::sync::Arc;

use self::oidc::oidc_config::OidcConfiguration;
use async_trait::async_trait;
use commons::uri::uri_builder::UriBuilder;
use crypto::providers::{
    cek::CekManagementProviderFactory,
    enc::ContentEncryptionProviderFactory,
    sig::{ClientSignatureVerifierProviderFactory, SignatureProviderFactory},
};
use models::entities::realm::RealmModel;
use serde_json::{Map, Value};
use services::session::darkshield_session::DarkshieldSession;

pub mod oidc;

const DEFAULT_RESPONSE_MODES_SUPPORTED: [&'static str; 7] = [
    "query",
    "fragment",
    "form_post",
    "query.jwt",
    "fragment.jwt",
    "form_post.jwt",
    "jwt",
];

const DEFAULT_SUBJECT_TYPES_SUPPORTED: [&'static str; 2] = ["public", "pairwise"];

const DEFAULT_RESPONSE_TYPES_SUPPORTED: [&'static str; 8] = [
    "code",
    "none",
    "id_token",
    "token",
    "id_token token",
    "code id_token token",
    "code token",
    "code id_token",
];

const DEFAULT_GRANT_TYPES_SUPPORTED: [&'static str; 5] = [
    "authorization_code",
    "implicit",
    "refresh_token",
    "password",
    "client_credentials",
];

const DEFAULT_CLAIM_TYPES_SUPPORTED: [&'static str; 1] = ["normal"];

const DEFAULT_CLAIMS_SUPPORTED: [&'static str; 10] = [
    "aud",
    "sub",
    "iss",
    "auth_time",
    "name",
    "given_name",
    "family_name",
    "preferred_username",
    "email",
    "acr",
];

#[async_trait]
pub trait WellKnownProvider {
    async fn oidc_config(&self) -> Result<OidcConfiguration, String>;
}

#[allow(dead_code)]
pub struct OidcWellKnownProvider {
    realm: Arc<RealmModel>,
    session: Arc<DarkshieldSession>,
    oidc_config_override: Option<Map<String, Value>>,
    include_client_scope: Option<bool>,
}

impl OidcWellKnownProvider {
    pub fn new(
        session: Arc<DarkshieldSession>,
        realm: Arc<RealmModel>,
        oidc_config_override: Option<Map<String, Value>>,
        include_client_scope: Option<bool>,
    ) -> Self {
        Self {
            realm: realm,
            session: session,
            oidc_config_override: oidc_config_override,
            include_client_scope: include_client_scope,
        }
    }

    fn get_supported_signing_algorithms(&self, include_none: bool) -> Vec<String> {
        let mut algos = SignatureProviderFactory::supported_algorithms();
        if include_none {
            algos.push("none".to_owned());
        }
        return algos;
    }

    fn get_supported_encryption_alg(&self, include_none: bool) -> Vec<String> {
        let mut algos = CekManagementProviderFactory::supported_algorithms();
        if include_none {
            algos.push("none".to_owned());
        }
        return algos;
    }

    fn get_supported_encryption_enc(&self, include_none: bool) -> Vec<String> {
        let mut algos = ContentEncryptionProviderFactory::supported_algorithms();
        if include_none {
            algos.push("none".to_owned());
        }
        return algos;
    }

    fn get_supported_client_signing_algorithms(&self, include_none: bool) -> Vec<String> {
        let mut algos = ClientSignatureVerifierProviderFactory::supported_algorithms();
        if include_none {
            algos.push("none".to_owned());
        }
        return algos;
    }

    fn get_supported_encryption_algorithms(&self) -> Vec<String> {
        CekManagementProviderFactory::supported_algorithms()
    }

    #[allow(dead_code)]
    fn get_supported_content_encryption_algorithms(&self) -> Vec<String> {
        return self.get_supported_encryption_enc(false);
    }

    fn get_client_auth_methods_supported(&self) -> Vec<String> {
        todo!()
    }

    fn check_config_override(&self, config: &mut OidcConfiguration) {
        match &self.oidc_config_override {
            Some(oidc_map) => {
                fn override_string_field<F: FnOnce(String)>(map: &Value, field: &str, setter: F) {
                    match &map.get(field) {
                        Some(Value::String(val)) => {
                            setter(val.clone());
                        }
                        _ => {}
                    }
                }

                fn override_bool_field<F: FnOnce(bool)>(map: &Value, field: &str, setter: F) {
                    match &map.get(field) {
                        Some(Value::Bool(val)) => {
                            setter(val.clone());
                        }
                        _ => {}
                    }
                }

                fn override_string_array_field<F: FnOnce(Vec<String>)>(
                    map: &Value,
                    field: &str,
                    setter: F,
                ) {
                    match &map.get(field) {
                        Some(Value::Array(val)) => {
                            let mut values = Vec::new();
                            for val_str in val {
                                if let Value::String(v) = val_str {
                                    values.push(v.clone())
                                }
                            }
                            setter(values);
                        }
                        _ => {}
                    }
                }

                for (field, value) in oidc_map {
                    match field.to_lowercase().as_str() {
                        "issuer" => {
                            override_string_field(value, "issuer", |value: String| {
                                config.set_issuer(value);
                            });
                        }
                        "authorization_endpoint" => {
                            override_string_field(
                                value,
                                "authorization_endpoint",
                                |value: String| {
                                    config.set_authorization_endpoint(value);
                                },
                            );
                        }
                        "token_endpoint" => {
                            override_string_field(value, "token_endpoint", |value: String| {
                                config.set_token_endpoint(value);
                            });
                        }
                        "introspection_endpoint" => {
                            override_string_field(
                                value,
                                "introspection_endpoint",
                                |value: String| {
                                    config.set_introspection_endpoint(value);
                                },
                            );
                        }
                        "userinfo_endpoint" => {
                            override_string_field(value, "userinfo_endpoint", |value: String| {
                                config.set_userinfo_endpoint(value);
                            });
                        }
                        "end_session_endpoint" => {
                            override_string_field(
                                value,
                                "end_session_endpoint",
                                |value: String| {
                                    config.set_end_session_endpoint(value);
                                },
                            );
                        }
                        "jwks_uri" => {
                            override_string_field(value, "jwks_uri", |value: String| {
                                config.set_jwks_uri(value);
                            });
                        }
                        "grant_types_supported" => {
                            override_string_array_field(
                                value,
                                "grant_types_supported",
                                |values: Vec<String>| {
                                    config.set_grant_types_supported(values);
                                },
                            );
                        }
                        "registration_endpoint" => {
                            override_string_field(
                                value,
                                "registration_endpoint",
                                |value: String| {
                                    config.set_registration_endpoint(value);
                                },
                            );
                        }
                        "id_token_signing_alg_values_supported" => {
                            override_string_array_field(
                                value,
                                "id_token_signing_alg_values_supported",
                                |values: Vec<String>| {
                                    config.set_id_token_signing_alg_values_supported(values);
                                },
                            );
                        }
                        "id_token_encryption_alg_values_supported" => {
                            override_string_array_field(
                                value,
                                "id_token_encryption_alg_values_supported",
                                |values: Vec<String>| {
                                    config.set_id_token_encryption_alg_values_supported(values);
                                },
                            );
                        }
                        "id_token_encryption_enc_values_supported" => {
                            override_string_array_field(
                                value,
                                "id_token_encryption_enc_values_supported",
                                |values: Vec<String>| {
                                    config.set_id_token_encryption_enc_values_supported(values);
                                },
                            );
                        }
                        "user_info_signing_alg_values_supported" => {
                            override_string_array_field(
                                value,
                                "user_info_signing_alg_values_supported",
                                |values: Vec<String>| {
                                    config.set_user_info_signing_alg_values_supported(values);
                                },
                            );
                        }
                        "request_object_signing_alg_values_supported" => {
                            override_string_array_field(
                                value,
                                "request_object_signing_alg_values_supported",
                                |values: Vec<String>| {
                                    config.set_request_object_signing_alg_values_supported(values);
                                },
                            );
                        }
                        "request_object_encryption_alg_values_supported" => {
                            override_string_array_field(
                                value,
                                "request_object_encryption_alg_values_supported",
                                |values: Vec<String>| {
                                    config
                                        .set_request_object_encryption_alg_values_supported(values);
                                },
                            );
                        }
                        "request_object_encryption_enc_values_supported" => {
                            override_string_array_field(
                                value,
                                "request_object_encryption_enc_values_supported",
                                |values: Vec<String>| {
                                    config
                                        .set_request_object_encryption_enc_values_supported(values);
                                },
                            );
                        }
                        "response_modes_supported" => {
                            override_string_array_field(
                                value,
                                "response_modes_supported",
                                |values: Vec<String>| {
                                    config.set_response_modes_supported(values);
                                },
                            );
                        }
                        "response_types_supported" => {
                            override_string_array_field(
                                value,
                                "response_types_supported",
                                |values: Vec<String>| {
                                    config.set_response_types_supported(values);
                                },
                            );
                        }
                        "subject_types_supported" => {
                            override_string_array_field(
                                value,
                                "subject_types_supported",
                                |values: Vec<String>| {
                                    config.set_subject_types_supported(values);
                                },
                            );
                        }
                        "token_endpoint_auth_methods_supported" => {
                            override_string_array_field(
                                value,
                                "token_endpoint_auth_methods_supported",
                                |values: Vec<String>| {
                                    config.set_token_endpoint_auth_methods_supported(values);
                                },
                            );
                        }
                        "token_endpoint_auth_signing_alg_values_supported" => {
                            override_string_array_field(
                                value,
                                "token_endpoint_auth_signing_alg_values_supported",
                                |values: Vec<String>| {
                                    config.set_token_endpoint_auth_signing_alg_values_supported(
                                        values,
                                    );
                                },
                            );
                        }
                        "introspection_endpoint_auth_methods_supported" => {
                            override_string_array_field(
                                value,
                                "introspection_endpoint_auth_methods_supported",
                                |values: Vec<String>| {
                                    config
                                        .set_introspection_endpoint_auth_methods_supported(values);
                                },
                            );
                        }
                        "introspection_endpoint_auth_signing_alg_values_supported" => {
                            override_string_array_field(
                                value,
                                "introspection_endpoint_auth_signing_alg_values_supported",
                                |values: Vec<String>| {
                                    config
                                        .set_introspection_endpoint_auth_signing_alg_values_supported(values);
                                },
                            );
                        }
                        "claim_types_supported" => {
                            override_string_array_field(
                                value,
                                "claim_types_supported",
                                |values: Vec<String>| {
                                    config.set_claim_types_supported(values);
                                },
                            );
                        }
                        "claims_supported" => {
                            override_string_array_field(
                                value,
                                "claims_supported",
                                |values: Vec<String>| {
                                    config.set_claims_supported(values);
                                },
                            );
                        }
                        "authorization_encryption_enc_values_supported" => {
                            override_string_array_field(
                                value,
                                "authorization_encryption_enc_values_supported",
                                |values: Vec<String>| {
                                    config
                                        .set_authorization_encryption_enc_values_supported(values);
                                },
                            );
                        }
                        "authorization_encryption_alg_values_supported" => {
                            override_string_array_field(
                                value,
                                "authorization_encryption_alg_values_supported",
                                |values: Vec<String>| {
                                    config
                                        .set_authorization_encryption_alg_values_supported(values);
                                },
                            );
                        }
                        "authorization_signing_alg_values_supported" => {
                            override_string_array_field(
                                value,
                                "authorization_signing_alg_values_supported",
                                |values: Vec<String>| {
                                    config.set_authorization_signing_alg_values_supported(values);
                                },
                            );
                        }
                        "scopes_supported" => {
                            override_string_array_field(
                                value,
                                "scopes_supported",
                                |values: Vec<String>| {
                                    config.set_scopes_supported(values);
                                },
                            );
                        }
                        "request_parameter_supported" => {
                            override_bool_field(
                                value,
                                "request_parameter_supported",
                                |value: bool| {
                                    config.set_request_parameter_supported(value);
                                },
                            );
                        }
                        "request_uri_parameter_supported" => {
                            override_bool_field(
                                value,
                                "request_uri_parameter_supported",
                                |value: bool| {
                                    config.set_request_uri_parameter_supported(value);
                                },
                            );
                        }
                        "require_request_uri_registration" => {
                            override_bool_field(
                                value,
                                "require_request_uri_registration",
                                |value: bool| {
                                    config.set_require_request_uri_registration(value);
                                },
                            );
                        }
                        "require_pushed_authorization_requests" => {
                            override_bool_field(
                                value,
                                "require_pushed_authorization_requests",
                                |value: bool| {
                                    config.set_require_pushed_authorization_requests(value);
                                },
                            );
                        }
                        "claims_parameter_supported" => {
                            override_bool_field(
                                value,
                                "claims_parameter_supported",
                                |value: bool| {
                                    config.set_claims_parameter_supported(value);
                                },
                            );
                        }
                        "code_challenge_methods_supported" => {
                            override_bool_field(
                                value,
                                "code_challenge_methods_supported",
                                |value: bool| {
                                    config.set_code_challenge_methods_supported(value);
                                },
                            );
                        }
                        "revocation_endpoint" => {
                            override_string_field(value, "revocation_endpoint", |value: String| {
                                config.set_revocation_endpoint(value);
                            });
                        }
                        "revocation_endpoint_auth_methods_supported" => {
                            override_string_array_field(
                                value,
                                "revocation_endpoint_auth_methods_supported",
                                |values: Vec<String>| {
                                    config.set_revocation_endpoint_auth_methods_supported(values);
                                },
                            );
                        }
                        "revocation_endpoint_auth_signing_alg_values_supported" => {
                            override_string_array_field(
                                value,
                                "revocation_endpoint_auth_signing_alg_values_supported",
                                |values: Vec<String>| {
                                    config
                                        .set_revocation_endpoint_auth_signing_alg_values_supported(
                                            values,
                                        );
                                },
                            );
                        }
                        "pushed_authorization_request_endpoint" => {
                            override_string_field(
                                value,
                                "pushed_authorization_request_endpoint",
                                |value: String| {
                                    config.set_pushed_authorization_request_endpoint(value);
                                },
                            );
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

#[async_trait]
impl WellKnownProvider for OidcWellKnownProvider {
    async fn oidc_config(&self) -> Result<OidcConfiguration, String> {
        let uri = self.session.context().lock().await.uri();
        let uri_builder = UriBuilder::from_uri(uri).paths("auth", "realms", &self.realm.realm_id);
        let base_uri = uri_builder.build();
        let mut config = OidcConfiguration::new();
        config.set_issuer(base_uri.clone());

        config.set_authorization_endpoint(
            uri_builder
                .clone()
                .paths("protocol", "openid-connect", "auth")
                .build(),
        );

        config.set_token_endpoint(
            uri_builder
                .clone()
                .paths("protocol", "openid-connect", "token")
                .build(),
        );

        config.set_introspection_endpoint(
            uri_builder
                .clone()
                .paths("protocol", "openid-connect", "introspection")
                .build(),
        );

        config.set_userinfo_endpoint(
            uri_builder
                .clone()
                .paths("protocol", "openid-connect", "userinfo")
                .build(),
        );

        config.set_end_session_endpoint(
            uri_builder
                .clone()
                .paths("protocol", "openid-connect", "logout")
                .build(),
        );

        config.set_jwks_uri(
            uri_builder
                .clone()
                .paths("protocol", "openid-connect", "certs")
                .build(),
        );

        config.set_registration_endpoint(uri_builder.clone().path("clients-registrations").build());

        config.set_id_token_signing_alg_values_supported(
            self.get_supported_signing_algorithms(false),
        );

        config
            .set_id_token_encryption_alg_values_supported(self.get_supported_encryption_alg(false));

        config
            .set_id_token_encryption_enc_values_supported(self.get_supported_encryption_enc(false));

        config.set_user_info_signing_alg_values_supported(
            self.get_supported_signing_algorithms(true),
        );

        config.set_request_object_signing_alg_values_supported(
            self.get_supported_client_signing_algorithms(true),
        );

        config.set_request_object_encryption_alg_values_supported(
            self.get_supported_encryption_algorithms(),
        );

        let vec_static_string = |values: Vec<&str>| -> Vec<String> {
            let mut res = Vec::new();
            for v in values {
                res.push((*v).to_owned());
            }
            res
        };

        config.set_response_modes_supported(vec_static_string(Vec::from(
            DEFAULT_RESPONSE_MODES_SUPPORTED,
        )));

        config.set_subject_types_supported(vec_static_string(Vec::from(
            DEFAULT_SUBJECT_TYPES_SUPPORTED,
        )));

        config.set_response_types_supported(vec_static_string(Vec::from(
            DEFAULT_RESPONSE_TYPES_SUPPORTED,
        )));

        config
            .set_grant_types_supported(vec_static_string(Vec::from(DEFAULT_GRANT_TYPES_SUPPORTED)));

        config.set_token_endpoint_auth_methods_supported(self.get_client_auth_methods_supported());
        config.set_token_endpoint_auth_signing_alg_values_supported(
            self.get_supported_client_signing_algorithms(false),
        );
        config.set_introspection_endpoint_auth_methods_supported(
            self.get_client_auth_methods_supported(),
        );
        config.set_introspection_endpoint_auth_signing_alg_values_supported(
            self.get_supported_client_signing_algorithms(false),
        );

        config.set_authorization_signing_alg_values_supported(
            self.get_supported_signing_algorithms(false),
        );

        config.set_authorization_encryption_alg_values_supported(
            self.get_supported_encryption_alg(false),
        );
        config.set_authorization_encryption_enc_values_supported(
            self.get_supported_encryption_enc(false),
        );

        config.set_claims_supported(vec_static_string(Vec::from(DEFAULT_CLAIMS_SUPPORTED)));

        config
            .set_claim_types_supported(vec_static_string(Vec::from(DEFAULT_CLAIM_TYPES_SUPPORTED)));

        config.set_claims_parameter_supported(true);

        match self.include_client_scope {
            Some(include_client_scope) => {
                if include_client_scope {
                    let scopes_names = self
                        .session
                        .client_scope_service()
                        .load_client_scope_names_by_protocol(&self.realm.realm_id, "openid-connect")
                        .await;
                    if let Ok(mut scopes) = scopes_names {
                        scopes.insert(0, "openid".to_owned());
                        config.set_scopes_supported(scopes);
                    } else {
                        return Err("failed to load clients scopes".to_owned());
                    }
                }
            }
            _ => {}
        }

        config.set_request_parameter_supported(true);
        config.set_request_uri_parameter_supported(true);
        config.set_require_request_uri_registration(true);
        config.set_code_challenge_methods_supported(true);

        config.set_revocation_endpoint(
            uri_builder
                .clone()
                .paths("protocol", "openid-connect", "revoke")
                .build(),
        );
        config.set_revocation_endpoint_auth_methods_supported(
            self.get_client_auth_methods_supported(),
        );
        config.set_revocation_endpoint_auth_signing_alg_values_supported(
            self.get_supported_client_signing_algorithms(false),
        );
        config.set_require_pushed_authorization_requests(false);
        self.check_config_override(&mut config);
        Ok(config)
    }
}
