use async_trait::async_trait;
use models::authentication::sessions::*;
use shaku::Interface;

#[async_trait]
pub trait IRootAuthenticationSessionProvider: Interface {
    async fn create_root_authentication_session(
        &self,
        root_session: &RootAuthenticationSession,
    ) -> Result<(), String>;

    async fn update_root_authentication_session(
        &self,
        root_session: &RootAuthenticationSession,
    ) -> Result<(), String>;

    async fn load_root_authentication_session(
        &self,
        realm_id: &str,
        auth_session_id: &str,
    ) -> Result<Option<RootAuthenticationSessionModel>, String>;

    async fn remove_realm_authentication_sessions(&self, realm_id: &str) -> Result<(), String>;

    async fn remove_root_authentication_session(
        &self,
        realm_id: &str,
        root_session_id: &str,
    ) -> Result<(), String>;
}

#[async_trait]
pub trait IAuthenticationSessionProvider: Interface {
    async fn create_authentication_session(
        &self,
        session: &AuthenticationSessionModel,
    ) -> Result<(), String>;

    async fn update_authentication_session(
        &self,
        session: &AuthenticationSessionModel,
    ) -> Result<(), String>;

    async fn remove_authentication_session(
        &self,
        realm_id: &str,
        client_id: &str,
        tab_id: &str,
    ) -> Result<(), String>;

    async fn load_authentication_sessions(
        &self,
        realm_id: &str,
        auth_session_id: &str,
    ) -> Result<Vec<AuthenticationSessionModel>, String>;
}

#[async_trait]
pub trait IUserSessionProvider: Interface {
    async fn create_user_session(&self, user_session: &UserSessionModel) -> Result<(), String>;

    async fn create_client_session(
        &self,
        client_session: &ClientSessionModel,
    ) -> Result<(), String>;

    async fn attach_client_session(
        &self,
        user_session: &UserSessionModel,
        client_session: &ClientSessionModel,
    ) -> Result<(), String>;

    async fn update_user_session(&self, user_session: &UserSessionModel) -> Result<(), String>;

    async fn restart_user_session(&self, user_session: &UserSessionModel) -> Result<(), String>;

    async fn full_update_user_session(
        &self,
        user_session: &UserSessionModel,
        client_sessions: &Vec<ClientSessionModel>,
    ) -> Result<(), String>;

    async fn full_update_client_session(
        &self,
        user_session: &UserSessionModel,
        client_sessions: &ClientSessionModel,
    ) -> Result<(), String>;

    async fn update_client_session(
        &self,
        client_session_model: &ClientSessionModel,
    ) -> Result<(), String>;

    async fn count_active_users_sessions(
        &self,
        realm_id: &str,
        client_id: &str,
        offline: bool,
    ) -> Result<i64, String>;

    async fn clear_client_sessions(self, realm_id: &str, client_id: &str) -> Result<(), String>;

    async fn load_user_session(
        &self,
        realm_id: &str,
        user_session_id: &str,
        offline: bool,
    ) -> Result<Option<UserSessionModel>, String>;

    async fn load_user_session_entities(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<UserSessionModel>, String>;

    async fn load_user_sessions_by_client_id(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Vec<UserSessionModel>, String>;

    async fn load_user_sessions_stream(
        &self,
        realm_id: &str,
        user_id: &str,
        offline: bool,
    ) -> Result<Vec<UserSessionModel>, String>;

    async fn delete_user_session_by_realm_id(
        &self,
        realm_id: &str,
        offline: &Option<bool>,
    ) -> Result<(), String>;

    async fn delete_user_session(&self, realm_id: &str, session_id: &str) -> Result<(), String>;

    async fn delete_user_session_by_user_id(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<(), String>;

    async fn delete_client_session(&self, realm_id: &str, session_id: &str) -> Result<(), String>;

    async fn load_client_sessions(
        &self,
        realm_id: &str,
        user_session_id: &str,
    ) -> Result<Vec<ClientSessionModel>, String>;

    async fn user_session_exists(&self, realm_id: &str, session_id: &str) -> Result<bool, String>;
}
