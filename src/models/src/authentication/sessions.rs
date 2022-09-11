use std::collections::{HashMap, HashSet};

use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};

use crate::entities::{
    auth::RequiredActionEnum, client::ClientModel, realm::RealmModel, user::UserModel,
};

#[derive(Debug, Serialize, Deserialize, ToSql, FromSql, PartialEq, Eq, Hash)]
#[postgres(name = "usersessionstateenum")]
pub enum UserSessionStateEnum {
    LoggedIn,
    LoggedOut,
    LoggingOut,
    LoggingOutUnconfirmed,
}

impl ToString for UserSessionStateEnum {
    fn to_string(&self) -> String {
        match &self {
            UserSessionStateEnum::LoggedIn => "logged_in".to_owned(),
            UserSessionStateEnum::LoggedOut => "logged_out".to_owned(),
            UserSessionStateEnum::LoggingOut => "logging_out".to_owned(),
            UserSessionStateEnum::LoggingOutUnconfirmed => "logging_out_unconfirmed".to_owned(),
        }
    }
}

pub struct UserSessionModel {
    pub tenant: String,
    pub session_id: String,
    pub realm_id: String,
    pub user_id: String,
    pub login_username: String,
    pub broker_session_id: String,
    pub broker_user_id: String,
    pub auth_method: Option<String>,
    pub ip_address: Option<String>,
    pub started_at: f32,
    pub expiration: Option<f32>,
    pub state: Option<UserSessionStateEnum>,
    pub remember_me: Option<bool>,
    pub last_session_refresh: Option<f32>,
    pub is_offline: Option<bool>,
    pub notes: Option<HashMap<String, String>>,
}

type ClientSessions = HashMap<String, Box<AuthenticatedClientSession>>;
pub struct UserSession {
    pub realm: RealmModel,
    pub session_model: UserSessionModel,
    pub user_id: String,
    pub user: Option<UserModel>,
    pub remember_me: Option<bool>,
    pub authenticated_client_sessions: ClientSessions,
}

impl UserSession {
    pub fn session_id(&self) -> &str {
        &self.session_model.session_id
    }

    pub fn session_model(&self) -> &UserSessionModel {
        &self.session_model
    }

    pub fn set_session_model(&mut self, session: UserSessionModel) {
        self.session_model = session;
    }

    pub fn broker_session_id(&self) -> &str {
        &self.session_model.broker_session_id
    }

    pub fn broker_user_id(&self) -> &str {
        &self.session_model.broker_user_id
    }

    pub fn user_id(&self) -> &str {
        &self.session_model.user_id
    }

    pub fn realm(&self) -> &RealmModel {
        &self.realm
    }

    pub fn login_username(&self) -> &String {
        &self.session_model.login_username
    }

    pub fn ip_address(&self) -> &Option<String> {
        &self.session_model.ip_address
    }

    pub fn auth_method(&self) -> &Option<String> {
        &self.session_model.auth_method
    }

    pub fn remember_me(&self) -> &Option<bool> {
        &self.session_model.remember_me
    }

    pub fn started_at(&self) -> &f32 {
        &self.session_model.started_at
    }

    pub fn expiration(&self) -> &Option<f32> {
        &self.session_model.expiration
    }

    pub fn state(&self) -> &Option<UserSessionStateEnum> {
        &self.session_model.state
    }

    pub fn set_state(&mut self, state: UserSessionStateEnum) {
        self.session_model.state = Some(state);
    }

    pub fn last_session_refresh(&self) -> &Option<f32> {
        &self.session_model.last_session_refresh
    }

    pub fn set_last_session_refresh(&mut self, last_session_refresh: f32) {
        self.session_model.last_session_refresh = Some(last_session_refresh);
    }

    pub fn is_offline(&self) -> &Option<bool> {
        &self.session_model.is_offline
    }

    pub fn set_is_offline(&mut self, is_offline: bool) {
        self.session_model.is_offline = Some(is_offline);
    }

    pub fn client_sessions(&self) -> &ClientSessions {
        &self.authenticated_client_sessions
    }

    pub fn clear_client_sessions(&mut self) {
        self.authenticated_client_sessions.clear();
    }

    pub fn session_notes(&self) -> &ClientSessions {
        &self.authenticated_client_sessions
    }

    pub fn set_session_state(&mut self, state: UserSessionStateEnum) {
        self.session_model.state = Some(state);
    }

    pub fn client_session_by_client(
        self,
        client_id: &str,
    ) -> Option<&Box<AuthenticatedClientSession>> {
        /*let client_session = self.authenticated_client_sessions.get(client_id);
        match client_session {
            None => None,
            Some(session) => session.clone(),
        }*/
        None
    }

    pub fn remove_authenticated_client_sessions(&mut self, client_ids: &HashSet<String>) {
        if !self.authenticated_client_sessions.is_empty() {
            let mut valid_client_session_ids = HashSet::new();
            for key in self.authenticated_client_sessions.keys() {
                if client_ids.contains(key) {
                    valid_client_session_ids.insert(key.clone());
                }
            }
            for session_id in valid_client_session_ids {
                self.authenticated_client_sessions.remove(&session_id);
            }
        }
    }

    pub fn set_note(&mut self, note_name: &str, note_value: &str) {
        match &mut self.session_model.notes {
            None => {
                let mut notes: HashMap<String, String> = HashMap::new();
                notes.insert(note_name.to_owned(), note_value.to_owned());
                self.session_model.notes = Some(notes);
            }
            Some(notes) => {
                notes.insert(note_name.to_owned(), note_value.to_owned());
            }
        }
    }

    pub fn get_note(&mut self, note_name: &str) -> Option<String> {
        match &self.session_model.notes {
            None => None,
            Some(notes) => {
                let value = notes.get(&note_name.to_string());
                match value {
                    None => None,
                    Some(v) => Some(v.clone()),
                }
            }
        }
    }

    pub fn remove_note(&mut self, note_name: &str) -> Option<String> {
        match &mut self.session_model.notes {
            None => None,
            Some(notes) => {
                let value = notes.remove_entry(&note_name.to_string());
                match value {
                    None => None,
                    Some(v) => Some(v.1.clone()),
                }
            }
        }
    }
}

pub struct ClientSessionModel {
    pub tenant: String,
    pub session_id: Option<String>,
    pub realm_id: String,
    pub user_id: String,
    pub user_session_id: String,
    pub client_id: String,
    pub auth_method: Option<String>,
    pub redirect_uri: Option<String>,
    pub action: Option<String>,
    pub started_at: f32,
    pub expiration: Option<f32>,
    pub notes: Option<HashMap<String, String>>,
    pub current_refresh_token: Option<String>,
    pub current_refresh_token_use_count: Option<i32>,
    pub offline: Option<bool>,
}

pub struct AuthenticatedClientSession {
    realm: RealmModel,
    client: ClientModel,
    session_model: ClientSessionModel,
    user_session: UserSession,
    offline: bool,
}

impl AuthenticatedClientSession {
    pub fn new(
        realm: RealmModel,
        client: ClientModel,
        session_model: ClientSessionModel,
        user_session: UserSession,
        offline: bool,
    ) -> Self {
        Self {
            realm,
            client,
            session_model,
            user_session,
            offline,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_model.user_session_id
    }

    pub fn session_model(&self) -> &ClientSessionModel {
        &self.session_model
    }

    pub fn get_started_at(&self) -> &f32 {
        &self.session_model.started_at
    }

    pub fn set_started_at(&mut self, started_at: f32) {
        self.session_model.started_at = started_at;
    }

    pub fn realm(&self) -> &RealmModel {
        &self.realm
    }

    pub fn client(&self) -> &ClientModel {
        &self.client
    }

    pub fn redirect_uri(&self) -> &Option<String> {
        &self.session_model.redirect_uri
    }

    pub fn protocol(&mut self) -> &Option<String> {
        &self.session_model.auth_method
    }

    pub fn set_protocol(&mut self, protocol: &str) {
        self.session_model.auth_method = Some(protocol.to_string());
    }

    pub fn set_note(&mut self, note_name: &str, note_value: &str) {
        match &mut self.session_model.notes {
            None => {
                let mut notes: HashMap<String, String> = HashMap::new();
                notes.insert(note_name.to_owned(), note_value.to_owned());
                self.session_model.notes = Some(notes);
            }
            Some(notes) => {
                notes.insert(note_name.to_owned(), note_value.to_owned());
            }
        }
    }

    pub fn get_note(&mut self, note_name: &str) -> Option<String> {
        match &self.session_model.notes {
            None => None,
            Some(notes) => {
                let value = notes.get(&note_name.to_string());
                match value {
                    None => None,
                    Some(v) => Some(v.clone()),
                }
            }
        }
    }

    pub fn remove_note(&mut self, note_name: &str) -> Option<String> {
        match &mut self.session_model.notes {
            None => None,
            Some(notes) => {
                let value = notes.remove_entry(&note_name.to_string());
                match value {
                    None => None,
                    Some(v) => Some(v.1.clone()),
                }
            }
        }
    }

    pub fn offline(&self) -> &Option<bool> {
        &self.session_model.offline
    }

    pub fn user_session(&self) -> &UserSession {
        &self.user_session
    }

    pub fn set_user_session(&mut self, user_session: UserSession) {
        self.user_session = user_session
    }

    pub fn refresh_token(&mut self) -> &Option<String> {
        &self.session_model.current_refresh_token
    }

    pub fn set_refresh_token(&mut self, refresh_token: &str) {
        self.session_model.current_refresh_token = Some(refresh_token.to_string());
    }

    pub fn refresh_token_use_count(&mut self) -> &Option<i32> {
        &self.session_model.current_refresh_token_use_count
    }

    pub fn set_refresh_token_use_count(&mut self, refresh_token_use_count: i32) {
        self.session_model.current_refresh_token_use_count = Some(refresh_token_use_count);
    }

    pub fn notes(&self) -> &Option<HashMap<String, String>> {
        &self.session_model.notes
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthenticationActionEnum {
    OauthGrant,
    Authenticate,
    LoggedOut,
    LoggingOut,
    RequiredActions,
    UserCodeVerification,
}

impl ToString for AuthenticationActionEnum {
    fn to_string(&self) -> String {
        match &self {
            AuthenticationActionEnum::OauthGrant => "oauth_grant".to_owned(),
            AuthenticationActionEnum::Authenticate => "oauth_grant".to_owned(),
            AuthenticationActionEnum::LoggedOut => "logout".to_owned(),
            AuthenticationActionEnum::LoggingOut => "logging_out".to_owned(),
            AuthenticationActionEnum::RequiredActions => "required_action".to_owned(),
            AuthenticationActionEnum::UserCodeVerification => "user_code_verification".to_owned(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthExecutionStatusEnum {
    Failed,
    Success,
    SetupRequired,
    Attempted,
    Skipped,
    Challenged,
    EvaluatedTrue,
    EvaluatedFalse,
    CredentialSetupRequired,
}

impl ToString for AuthExecutionStatusEnum {
    fn to_string(&self) -> String {
        match &self {
            AuthExecutionStatusEnum::Failed => "Failed".to_owned(),
            AuthExecutionStatusEnum::Success => "Success".to_owned(),
            AuthExecutionStatusEnum::SetupRequired => "SetupRequired".to_owned(),
            AuthExecutionStatusEnum::Attempted => "Attempted".to_owned(),
            AuthExecutionStatusEnum::Skipped => "Skipped".to_owned(),
            AuthExecutionStatusEnum::Challenged => "Challenged".to_owned(),
            AuthExecutionStatusEnum::EvaluatedTrue => "EvaluatedTrue".to_owned(),
            AuthExecutionStatusEnum::EvaluatedFalse => "EvaluatedFalse".to_owned(),
            AuthExecutionStatusEnum::CredentialSetupRequired => {
                "CredentialSetupRequired".to_owned()
            }
        }
    }
}

pub struct RootAuthenticationSessionModel {
    pub tenant: String,
    pub session_id: String,
    pub realm_id: String,
    pub timestamp: f32,
}

type AuthenticationSessions = HashMap<String, AuthenticationSession>;
pub struct RootAuthenticationSession {
    realm: RealmModel,
    timestamp: f32,
    session_model: RootAuthenticationSessionModel,
    auth_sessions: AuthenticationSessions,
}

impl RootAuthenticationSession {
    pub fn session_model(&self) -> &RootAuthenticationSessionModel {
        &self.session_model
    }

    pub fn session_id(&self) -> &str {
        &self.session_model.session_id
    }

    pub fn realm(&self) -> &RealmModel {
        &self.realm
    }

    pub fn timestamp(&self) -> &f32 {
        &self.session_model.timestamp
    }

    pub fn set_timestamp(&mut self, timestamp: f32) {
        self.session_model.timestamp = timestamp;
    }

    pub fn authentication_sessions(&self) -> &AuthenticationSessions {
        &self.auth_sessions
    }

    pub fn restart_session(&mut self) {
        if !self.auth_sessions.is_empty() {
            self.auth_sessions.clear();
        }
    }

    pub fn clear_authentication_sessions(&mut self) {
        self.auth_sessions.clear()
    }

    pub fn add_authentication_session(&mut self, auth_session: AuthenticationSession) {
        if self.auth_sessions.is_empty() {
            self.auth_sessions = AuthenticationSessions::new();
        }
        self.auth_sessions
            .insert(auth_session.tab_id().to_string(), auth_session);
    }

    pub fn remove_authentication_session_by_tab_id(&mut self, tab_id: &str) {
        if self.auth_sessions.contains_key(tab_id) {
            self.auth_sessions.remove(tab_id);
        }
    }

    /*pub fn authentication_session(
        &mut self,
        client: ClientModel,
        tab_id: &str,
    ) -> Option<AuthenticationSession> {
        let auth_session = self.auth_sessions.get(tab_id);
        match auth_session {
            None => None,
            Some(auth) => match auth.client {
                None => None,
                Some(ref session_client) => {
                    if session_client.client_id.eq(&client.client_id) {
                        Some(auth)
                    } else {
                        None
                    }
                }
            },
        }
    }*/
}
pub struct AuthenticationSessionModel {
    pub tenant: String,
    pub tab_id: String,
    pub auth_user_id: Option<String>,
    pub realm_id: String,
    pub root_session_id: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_scopes: Option<HashSet<String>>,
    pub timestamp: f32,
    pub action: Option<String>,
    pub protocol: Option<String>,
    pub execution_status: Option<HashMap<String, AuthExecutionStatusEnum>>,
    pub client_notes: Option<HashMap<String, String>>,
    pub auth_notes: Option<HashMap<String, String>>,
    pub required_actions: Option<HashSet<RequiredActionEnum>>,
    pub user_session_notes: Option<HashMap<String, String>>,
}

pub struct AuthenticationSession {
    parent_session: RootAuthenticationSession,
    session_model: AuthenticationSessionModel,
    client: Option<ClientModel>,
    user: Option<UserModel>,
}

impl AuthenticationSession {
    pub fn session_model(&self) -> &AuthenticationSessionModel {
        &self.session_model
    }

    pub fn tab_id(&self) -> &str {
        &self.session_model.tab_id
    }

    pub fn client(&self) -> &Option<ClientModel> {
        &self.client
    }

    pub fn set_client(&mut self, client: ClientModel) {
        self.client = Some(client);
    }

    pub fn parent_session(&self) -> &RootAuthenticationSession {
        &self.parent_session
    }

    pub fn set_parent_session(&mut self, parent_session: RootAuthenticationSession) {
        self.parent_session = parent_session;
    }

    pub fn update_authenticated_user(&mut self, authenticated_user: Option<UserModel>) {
        self.user = authenticated_user;
    }

    pub fn set_authenticated_user(&mut self, authenticated_user: &Option<UserModel>) {
        if let Some(auth) = authenticated_user {
            self.session_model.auth_user_id = Some(auth.user_id.clone());
        }
        self.user = None
    }

    pub fn required_actions(&self) -> &Option<HashSet<RequiredActionEnum>> {
        &self.session_model.required_actions
    }

    pub fn add_required_action(&mut self, action: RequiredActionEnum) {
        if let Some(actions) = &mut self.session_model.required_actions {
            actions.insert(action);
        } else {
            let mut actions = HashSet::new();
            actions.insert(action);
            self.session_model.required_actions = Some(actions);
        }
    }

    pub fn remove_required_action(&mut self, action: &RequiredActionEnum) {
        if let Some(actions) = &mut self.session_model.required_actions {
            actions.remove(action);
        }
    }

    pub fn action(&self) -> &Option<String> {
        &self.session_model.action
    }

    pub fn set_action(&mut self, action: &str) {
        self.session_model.action = Some(action.to_owned());
    }

    pub fn protocol(&self) -> &Option<String> {
        &self.session_model.protocol
    }

    pub fn set_protocol(&mut self, protocol: &str) {
        self.session_model.protocol = Some(protocol.to_owned());
    }

    pub fn client_scopes_ids(&self) -> &Option<HashSet<String>> {
        &self.session_model.client_scopes
    }

    pub fn set_client_scopes_ids(&mut self, client_scopes: HashSet<String>) {
        self.session_model.client_scopes = Some(client_scopes);
    }

    pub fn execution_status(&self) -> &Option<HashMap<String, AuthExecutionStatusEnum>> {
        &self.session_model.execution_status
    }

    pub fn set_execution_status(&mut self, authenticator: &str, status: AuthExecutionStatusEnum) {
        match &mut self.session_model.execution_status {
            Some(execution_status) => {
                if execution_status.contains_key(authenticator) {
                    execution_status.remove(authenticator);
                }
                execution_status.insert(authenticator.to_string(), status);
            }
            None => {
                let mut execution_status = HashMap::new();
                execution_status.insert(authenticator.to_string(), status);
                self.session_model.execution_status = Some(execution_status);
            }
        }
    }

    pub fn clear_execution_status(&mut self) {
        if let Some(status) = &mut self.session_model.execution_status {
            status.clear();
        }
    }

    pub fn redirect_uri(&self) -> &Option<String> {
        &self.session_model.redirect_uri
    }

    pub fn set_redirect_uri(&mut self, redirect_uri: &str) {
        self.session_model.redirect_uri = Some(redirect_uri.to_owned());
    }

    pub fn clear_client_notes(&mut self) {
        if let Some(client_notes) = &mut self.session_model.client_notes {
            client_notes.clear();
        }
    }

    pub fn remove_user_session_notes(&mut self, note_name: &str) {
        if let Some(user_session_notes) = &mut self.session_model.user_session_notes {
            if user_session_notes.contains_key(note_name) {
                user_session_notes.remove(note_name);
            }
        }
    }

    pub fn set_user_session_note(&mut self, note_name: &str, value: &str) {
        match &mut self.session_model.user_session_notes {
            Some(user_session_notes) => {
                if user_session_notes.contains_key(note_name) {
                    user_session_notes.remove(note_name);
                }
                user_session_notes.insert(note_name.to_string(), value.to_string());
            }
            None => {
                let mut user_session_notes = HashMap::new();
                user_session_notes.insert(note_name.to_string(), value.to_string());
                self.session_model.user_session_notes = Some(user_session_notes);
            }
        }
    }

    pub fn get_user_session_notes(&self, note_name: &str) -> Option<String> {
        if let Some(user_session_notes) = &self.session_model.user_session_notes {
            let value = user_session_notes.get(note_name);
            if let Some(v) = value {
                return Some(v.clone());
            }
        }
        None
    }

    pub fn user_session_notes(&self) -> &Option<HashMap<String, String>> {
        &self.session_model.user_session_notes
    }

    pub fn client_notes(&self) -> &Option<HashMap<String, String>> {
        &self.session_model.client_notes
    }

    pub fn clear_user_session_notes(&mut self) {
        if let Some(user_session_notes) = &mut self.session_model.user_session_notes {
            user_session_notes.clear();
        }
    }

    pub fn remove_client_notes(&mut self, note_name: &str) {
        if let Some(client_notes) = &mut self.session_model.client_notes {
            if client_notes.contains_key(note_name) {
                client_notes.remove(note_name);
            }
        }
    }

    pub fn set_client_note(&mut self, note_name: &str, value: &str) {
        match &mut self.session_model.client_notes {
            Some(client_notes) => {
                if client_notes.contains_key(note_name) {
                    client_notes.remove(note_name);
                }
                client_notes.insert(note_name.to_string(), value.to_string());
            }
            None => {
                let mut client_notes = HashMap::new();
                client_notes.insert(note_name.to_string(), value.to_string());
                self.session_model.client_notes = Some(client_notes);
            }
        }
    }

    pub fn get_client_note(&self, note_name: &str) -> Option<String> {
        if let Some(client_notes) = &self.session_model.client_notes {
            let value = client_notes.get(note_name);
            if let Some(v) = value {
                return Some(v.clone());
            }
        }
        None
    }

    pub fn auth_notes(&self) -> &Option<HashMap<String, String>> {
        &self.session_model.auth_notes
    }

    pub fn clear_auth_notes(&mut self) {
        if let Some(auth_notes) = &mut self.session_model.auth_notes {
            auth_notes.clear();
        }
    }

    pub fn remove_auth_note(&mut self, note_name: &str) {
        if let Some(auth_notes) = &mut self.session_model.auth_notes {
            if auth_notes.contains_key(note_name) {
                auth_notes.remove(note_name);
            }
        }
    }

    pub fn set_auth_note(&mut self, note_name: &str, value: &str) {
        match &mut self.session_model.auth_notes {
            Some(auth_notes) => {
                if auth_notes.contains_key(note_name) {
                    auth_notes.remove(note_name);
                }
                auth_notes.insert(note_name.to_string(), value.to_string());
            }
            None => {
                let mut auth_notes = HashMap::new();
                auth_notes.insert(note_name.to_string(), value.to_string());
                self.session_model.auth_notes = Some(auth_notes);
            }
        }
    }

    pub fn get_auth_note(&self, note_name: &str) -> Option<String> {
        if let Some(auth_notes) = &self.session_model.auth_notes {
            let value = auth_notes.get(note_name);
            if let Some(v) = value {
                return Some(v.clone());
            }
        }
        None
    }
}
pub struct AuthenticationSessionCompoundId {
    pub root_session: Option<String>,
    pub tab_id: Option<String>,
    pub client_id: Option<String>,
    pub encoded_id: Option<String>,
}

impl AuthenticationSessionCompoundId {
    pub fn new(root_auth_session_id: &str, tab_id: &str, client_id: &str) -> Self {
        let encoded_id = format!("{root_auth_session_id}.{tab_id}.{client_id}");
        Self {
            root_session: Some(root_auth_session_id.to_owned()),
            tab_id: Some(tab_id.to_owned()),
            client_id: Some(client_id.to_owned()),
            encoded_id: Some(encoded_id),
        }
    }

    pub fn from_auth_session(session: &AuthenticationSession) -> Self {
        Self::new(
            session.parent_session.session_id(),
            session.tab_id(),
            &session.client().as_ref().unwrap().client_id.to_owned(),
        )
    }

    pub fn root_session(&self) -> &Option<String> {
        &self.root_session
    }

    pub fn tab_id(&self) -> &Option<String> {
        &self.tab_id
    }

    pub fn client_id(&self) -> &Option<String> {
        &self.client_id
    }

    pub fn encoded_id(&self) -> &Option<String> {
        &self.encoded_id
    }
}
