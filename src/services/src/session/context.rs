use std::sync::Arc;

use actix_web::{cookie::Cookie, http::Uri, HttpRequest};
use chrono::{DateTime, Utc};
use models::{
    authentication::sessions::AuthenticationSession,
    entities::{client::ClientModel, realm::RealmModel, user::UserModel},
};

#[allow(dead_code)]
pub struct ClientConnection {
    client_host: Option<String>,
    client_port: Option<String>,
    resource_uri: Option<String>,
    remote_ip_address: Option<String>,
}

#[allow(dead_code)]
pub struct DarkshieldContext {
    uri: Uri,
    client: Option<ClientModel>,
    auth_session: Option<AuthenticationSession>,
    client_connection: Option<ClientConnection>,
    response_cookies: Vec<Cookie<'static>>,
    current_time: Option<DateTime<Utc>>,
    http_request: Option<Arc<HttpRequest>>,
    authenticated_user: Option<Arc<UserModel>>,
    realm: Option<RealmModel>,
}

impl DarkshieldContext {
    pub fn from_user(user: UserModel) -> Self {
        let mut auth_session = AuthenticationSession::default();
        let user = Arc::new(user);
        auth_session.update_authenticated_user(&user);
        let mut context = Self {
            uri: Default::default(),
            client: Default::default(),
            auth_session: Default::default(),
            client_connection: Default::default(),
            response_cookies: Default::default(),
            current_time: Default::default(),
            http_request: Default::default(),
            authenticated_user: Default::default(),
            realm: Default::default(),
        };
        context.set_authenticated_user(&user);
        context.set_authentication_session(auth_session);
        return context;
    }

    pub fn uri(&self) -> Uri {
        self.uri.clone()
    }

    pub fn set_uri(&mut self, uri: Uri) {
        self.uri = uri
    }

    pub fn client(&self) -> &Option<ClientModel> {
        &self.client
    }

    pub fn set_client(&mut self, client: ClientModel) {
        self.client = Some(client)
    }

    pub fn realm(&self) -> &Option<RealmModel> {
        &self.realm
    }

    pub fn set_realm(&mut self, realm: RealmModel) {
        self.realm = Some(realm)
    }

    pub fn client_connection(&self) -> &Option<ClientConnection> {
        &self.client_connection
    }

    pub fn response_cookies(&self) -> &Vec<Cookie<'static>> {
        &self.response_cookies
    }

    pub fn set_response_cookies(&mut self, response_cookies: Vec<Cookie<'static>>) {
        self.response_cookies = response_cookies
    }

    pub fn set_current_time(&mut self, current_time: DateTime<Utc>) {
        self.current_time = Some(current_time);
    }

    pub fn current_time(&self) -> DateTime<Utc> {
        match &self.current_time {
            Some(t) => t.clone(),
            None => Utc::now(),
        }
    }

    pub fn authenticated_user(&self) -> &Arc<UserModel> {
        return &self.authenticated_user.as_ref().unwrap();
    }

    pub fn set_authenticated_user(&mut self, user: &Arc<UserModel>) {
        self.authenticated_user = Some(Arc::clone(&user));
    }

    pub fn set_authentication_session(&mut self, auth_session: AuthenticationSession) {
        self.auth_session = Some(auth_session)
    }
}
