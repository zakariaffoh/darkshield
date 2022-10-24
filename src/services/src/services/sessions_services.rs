use crate::{
    catalog::DarkshieldServices, services::client_services::IClientService,
    session::darkshield_session::DarkshieldSession,
};
use async_trait::async_trait;
use chrono::Utc;
use commons::ApiResult;
use futures::lock::Mutex;
use log;
use models::{
    authentication::sessions::{
        AuthenticatedClientSession, AuthenticationSession, AuthenticationSessionByTab,
        RootAuthenticationSession, RootAuthenticationSessionModel, UserSession, UserSessionModel,
    },
    entities::{client::ClientModel, realm::RealmModel},
};
use shaku::HasComponent;
use std::collections::HashMap;
use std::sync::Arc;
use store::providers::interfaces::session_providers::{
    IAuthenticationSessionProvider, IRootAuthenticationSessionProvider, IUserSessionProvider,
};

pub struct AuthenticationSessionManager {
    session: Arc<DarkshieldServices>,
}

/*#[async_trait]
pub trait IAuthenticationSessionManager {
    async fn create_root_authentication_session(
        &self,
        realm: &RealmModel,
        browser_cookie: bool,
    ) -> Result<RootAuthenticationSession, String>;

    async fn create_authentication_session(
        &self,
        root_auth_session: &RootAuthenticationSession,
        client: &ClientModel,
    ) -> Result<RootAuthenticationSession, String>;

    async fn update_authentication_session(
        &self,
        auth_session: &AuthenticationSession,
    ) -> Result<(), String>;

    async fn load_current_root_authentication_session(
        &self,
        realm: &RealmModel,
    ) -> Result<(), String>;

    async fn load_current_authentication_session(
        &self,
        realm: &RealmModel,
        client: &ClientModel,
        tab_id: &str,
    ) -> Result<Option<RootAuthenticationSession>, String>;

    async fn get_auth_session_cookies(&self, realm: &RealmModel) -> Result<Vec<String>, String>;

    async fn remove_authentication_session(
        &self,
        realm: &RealmModel,
        auth_session: &AuthenticationSession,
        expire_restart_cookie: bool,
    ) -> Result<(), String>;

    async fn load_user_session(
        &self,
        auth_session: &Arc<AuthenticationSession>,
    ) -> Result<Option<UserSession>, String>;

    async fn load_authentication_session_by_id_and_client(
        &self,
        realm: &Arc<RealmModel>,
        auth_session_id: &str,
        client: &Arc<ClientModel>,
        tab_id: &str,
    ) -> Result<Option<Arc<Mutex<AuthenticationSession>>>, String>;

    async fn load_root_authentication_session(
        &self,
        realm: &Arc<RealmModel>,
        auth_session_id: &str,
    ) -> Result<Option<Arc<RootAuthenticationSession>>, String>;

    async fn remove_root_authentication_session(
        &self,
        realm: &Arc<RealmModel>,
        root_auth_session: &Arc<RootAuthenticationSession>,
    ) -> Result<(), String>;

    async fn remove_authentication_session_by_tab_id(
        &self,
        root_auth_session: &Arc<Mutex<RootAuthenticationSession>>,
        tab_id: &str,
    ) -> Result<(), String>;

    async fn restart_session(
        &self,
        root_auth_session: &Arc<Mutex<RootAuthenticationSession>>,
    ) -> Result<(), String>;

    async fn create_root_authentication_session_from_session_id(
        &self,
        realm: &Arc<RealmModel>,
        session_id: &str,
    ) -> Result<RootAuthenticationSession, String>;

    async fn set_auth_session_cookie(
        self,
        session: &DarkshieldSession,
        realm: &RealmModel,
        auth_session_id: &str,
    ) -> Result<(), String>;

    async fn on_realm_removed(&self, realm_id: &str) -> Result<(), String>;

    async fn read_user_session(
        &self,
        realm: &Arc<RealmModel>,
        user_session: UserSessionModel,
        user_id: &str,
    ) -> Result<Arc<UserSession>, String>;

    async fn load_associated_client_sessions(
        &self,
        realm: &Arc<RealmModel>,
        user_session_id: &str,
        offline: bool,
    ) -> Result<HashMap<String, Arc<Mutex<AuthenticatedClientSession>>>, String>;
}

#[async_trait]
impl IAuthenticationSessionManager for AuthenticationSessionManager {
    async fn create_root_authentication_session(
        &self,
        realm: &RealmModel,
        browser_cookie: bool,
    ) -> Result<RootAuthenticationSession, String> {
        todo!();
    }

    async fn create_authentication_session(
        &self,
        root_auth_session: &RootAuthenticationSession,
        client: &ClientModel,
    ) -> Result<RootAuthenticationSession, String> {
        todo!();
    }

    async fn update_authentication_session(
        &self,
        auth_session: &AuthenticationSession,
    ) -> Result<(), String> {
        todo!();
    }

    async fn load_current_root_authentication_session(
        &self,
        realm: &RealmModel,
    ) -> Result<(), String> {
        todo!();
    }

    async fn load_current_authentication_session(
        &self,
        realm: &RealmModel,
        client: &ClientModel,
        tab_id: &str,
    ) -> Result<Option<RootAuthenticationSession>, String> {
        todo!();
    }

    async fn get_auth_session_cookies(&self, realm: &RealmModel) -> Result<Vec<String>, String> {
        todo!();
    }

    async fn remove_authentication_session(
        &self,
        realm: &RealmModel,
        auth_session: &AuthenticationSession,
        expire_restart_cookie: bool,
    ) -> Result<(), String> {
        todo!();
    }

    async fn load_user_session(
        &self,
        auth_session: &Arc<AuthenticationSession>,
    ) -> Result<Option<UserSession>, String> {
        let session_provider: &dyn IUserSessionProvider = self.session.resolve_ref();
        let session = session_provider
            .load_user_session(
                &auth_session
                    .parent_session()
                    .unwrap()
                    .realm()
                    .realm_id
                    .clone(),
                auth_session.parent_session().unwrap().session_id(),
                false,
            )
            .await;
        match session {
            Ok(user_session_model) => match user_session_model {
                Some(user_session) => {
                    let loaded_session = self
                        .read_user_session(
                            &auth_session.parent_session().unwrap().realm(),
                            user_session,
                            &auth_session.parent_session().unwrap().session_id(),
                        )
                        .await;
                    if let Ok(read_user_session) = loaded_session {
                        Ok(Some(read_user_session))
                    } else {
                        Ok(None)
                    }
                }
                None => return Ok(None),
            },
            Err(err) => Err(err),
        }
    }

    async fn read_user_session(
        &self,
        realm: &Arc<RealmModel>,
        user_session: UserSessionModel,
        user_id: &str,
    ) -> Result<Arc<UserSession>, String> {
        let session_provider: &dyn IUserSessionProvider = self.session.resolve_ref();
        let associated_client_sessions = self
            .load_associated_client_sessions(realm, &user_session.session_id, false)
            .await;
        let user_session = Arc::new(UserSession {
            realm: realm.clone(),
            session_model: user_session,
            user_id: user_id.to_owned(),
            user: None,
            remember_me: None,
            authenticated_client_sessions: associated_client_sessions.unwrap(),
        });
        for (_, client_session) in user_session.authenticated_client_sessions.iter() {
            let auth = client_session.lock().await;
            auth.set_user_session(user_session.clone());
        }
        Ok(user_session)
    }

    async fn load_associated_client_sessions(
        &self,
        realm: &Arc<RealmModel>,
        user_session_id: &str,
        offline: bool,
    ) -> Result<HashMap<String, Arc<Mutex<AuthenticatedClientSession>>>, String> {
        todo!()
    }

    async fn load_authentication_session_by_id_and_client(
        &self,
        realm: &Arc<RealmModel>,
        auth_session_id: &str,
        client: &Arc<ClientModel>,
        tab_id: &str,
    ) -> Result<Option<Arc<Mutex<AuthenticationSession>>>, String> {
        let root_auth_session = self
            .load_root_authentication_session(realm, auth_session_id)
            .await;
        match root_auth_session {
            Ok(session) => match session {
                Some(session) => {
                    let auth_session = session.get_authentication_session(client, tab_id).await;
                    Ok(auth_session)
                }
                None => Ok(None),
            },
            Err(err) => Err(err),
        }
    }

    async fn load_root_authentication_session(
        &self,
        realm: &Arc<RealmModel>,
        auth_session_id: &str,
    ) -> Result<Option<Arc<RootAuthenticationSession>>, String> {
        let root_session_provider: &dyn IRootAuthenticationSessionProvider =
            self.session.resolve_ref();
        let result = root_session_provider
            .load_root_authentication_session(&realm.realm_id, &auth_session_id)
            .await;
        if let Err(err) = result {
            return Err(err);
        }
        let root_session = result.unwrap();
        if let None = root_session {
            return Ok(None);
        }
        let root_session = root_session.unwrap();
        let auth_session_provider: &dyn IAuthenticationSessionProvider = self.session.resolve_ref();
        let auth_session_entities = auth_session_provider
            .load_authentication_sessions(&realm.realm_id, auth_session_id)
            .await;
        if let Err(err) = auth_session_entities {
            return Err(err);
        }
        let auth_session_entities = auth_session_entities.unwrap();
        let clients_ids: Vec<String> = auth_session_entities
            .iter()
            .map(|v| v.client_id.as_ref().unwrap().clone())
            .collect();

        let client_service: &dyn IClientService = self.session.resolve_ref();
        let clients_data = client_service
            .load_client_by_ids(&realm.realm_id, &clients_ids)
            .await;

        let mut auth_sessions_tabs: HashMap<String, Arc<Mutex<AuthenticationSession>>> =
            HashMap::new();
        match clients_data {
            ApiResult::Data(clients) => {
                if clients.len() != clients_ids.len() {
                    log::error!("Found invalid clients");
                    return Ok(None);
                }
                let client_mapping: HashMap<String, Arc<ClientModel>> = clients
                    .into_iter()
                    .map(|client| (client.client_id.clone(), Arc::new(client)))
                    .collect::<HashMap<_, _>>();

                for auth_session in auth_session_entities {
                    let client_id = auth_session.client_id.clone().unwrap();
                    let tab_id = auth_session.tab_id.clone();
                    let mut session = AuthenticationSession {
                        parent_session: None,
                        session_model: auth_session,
                        client: None,
                        user: None,
                    };
                    let client = client_mapping.get(&client_id).unwrap();

                    session.set_client(client);
                    auth_sessions_tabs.insert(tab_id, Arc::new(Mutex::new(session)));
                }
            }
            ApiResult::Error(err) => {
                return Err(err.to_string());
            }
            _ => return Ok(None),
        }
        let root_auth_session = Arc::new(RootAuthenticationSession {
            realm: realm.clone(),
            timestamp: 0,
            session_model: root_session,
            auth_sessions: auth_sessions_tabs,
        });
        for (_, auth_session) in root_auth_session.auth_sessions.iter() {
            let auth = auth_session.lock().await;
            auth.set_parent_session(root_auth_session.clone());
        }
        Ok(Some(root_auth_session))
    }

    async fn remove_root_authentication_session(
        &self,
        realm: &Arc<RealmModel>,
        root_auth_session: &Arc<RootAuthenticationSession>,
    ) -> Result<(), String> {
        let root_session_provider: &dyn IRootAuthenticationSessionProvider =
            self.session.resolve_ref();
        let result = root_session_provider
            .remove_root_authentication_session(&realm.realm_id, root_auth_session.session_id())
            .await;
        match result {
            Err(err) => Err(err),
            _ => Ok(()),
        }
    }

    async fn remove_authentication_session_by_tab_id(
        &self,
        root_auth_session: &Arc<Mutex<RootAuthenticationSession>>,
        tab_id: &str,
    ) -> Result<(), String> {
        /*let session_provider: &dyn IAuthenticationSessionProvider = self.session.resolve_ref();
        let mut root_auth = root_auth_session.lock().await;
        if !root_auth.authentication_sessions().is_empty() {
            let auth_session = root_auth.authentication_sessions().get(tab_id);
            match auth_session {
                Some(session) => {
                    let result = session_provider
                        .remove_authentication_session(
                            &root_auth.realm().realm_id,
                            &session.client().as_ref().unwrap().client_id,
                            tab_id,
                        )
                        .await;
                    match result {
                        Err(err) => return Err(err),
                        _ => return Ok(()),
                    }
                }
                None => return Ok(()),
            }
        }

        root_auth.remove_authentication_session_by_tab_id(tab_id);
        if root_auth.authentication_sessions().is_empty() {
            let root_session_provider: &dyn IRootAuthenticationSessionProvider =
                self.session.resolve_ref();
            let result = root_session_provider
                .remove_root_authentication_session(
                    &root_auth.realm().realm_id,
                    root_auth.session_id(),
                )
                .await;
            match result {
                Err(err) => return Err(err),
                _ => return Ok(()),
            }
        }*/
        Ok(())
    }

    async fn restart_session(
        &self,
        root_auth_session: &Arc<Mutex<RootAuthenticationSession>>,
    ) -> Result<(), String> {
        let session_provider: &dyn IRootAuthenticationSessionProvider = self.session.resolve_ref();
        let timestamp = Utc::now().timestamp();
        let mut root_auth = root_auth_session.lock().await;
        root_auth.clear_authentication_sessions();
        root_auth.set_timestamp(timestamp);
        session_provider
            .update_root_authentication_session(&root_auth.session_model())
            .await
    }

    async fn create_root_authentication_session_from_session_id(
        &self,
        realm: &Arc<RealmModel>,
        session_id: &str,
    ) -> Result<RootAuthenticationSession, String> {
        let timestamp = Utc::now().timestamp();
        let root_auth_session_model = RootAuthenticationSessionModel {
            tenant: realm.metadata.as_ref().unwrap().tenant.clone(),
            session_id: session_id.to_owned(),
            realm_id: realm.realm_id.clone(),
            timestamp: timestamp,
        };

        let session_provider: &dyn IRootAuthenticationSessionProvider = self.session.resolve_ref();
        let result = session_provider
            .create_root_authentication_session(&root_auth_session_model)
            .await;
        match result {
            Ok(_) => {
                let root_auth_session = RootAuthenticationSession {
                    realm: Arc::clone(realm),
                    timestamp: timestamp,
                    session_model: root_auth_session_model,
                    auth_sessions: HashMap::new(),
                };
                Ok(root_auth_session)
            }
            Err(err) => {
                log::error!("Failed to create root authentication model");
                Err(err)
            }
        }
    }

    async fn set_auth_session_cookie(
        self,
        _session: &DarkshieldSession,
        _realm: &RealmModel,
        _auth_session_id: &str,
    ) -> Result<(), String> {
        todo!();
    }

    async fn on_realm_removed(&self, realm_id: &str) -> Result<(), String> {
        let session_provider: &dyn IRootAuthenticationSessionProvider = self.session.resolve_ref();
        session_provider
            .remove_realm_authentication_sessions(realm_id)
            .await
    }
}

#[async_trait]
impl IAuthenticationSessionManager for AuthenticationSessionManager {
    async fn create_root_authentication_session(
        &self,
        realm: &RealmModel,
        browser_cookie: bool,
    ) -> Result<RootAuthenticationSession, String> {
        todo!()
    }

    async fn create_authentication_session(
        &self,
        root_auth_session: &RootAuthenticationSession,
        client: &ClientModel,
    ) -> Result<RootAuthenticationSession, String> {
        todo!()
    }

    async fn update_authentication_session(
        &self,
        auth_session: &AuthenticationSession,
    ) -> Result<(), String> {
        todo!()
    }

    async fn load_current_root_authentication_session(
        &self,
        realm: &RealmModel,
    ) -> Result<(), String> {
        todo!()
    }

    async fn load_current_authentication_session(
        &self,
        realm: &RealmModel,
        client: &ClientModel,
        tab_id: &str,
    ) -> Result<Option<RootAuthenticationSession>, String> {
        todo!()
    }

    async fn get_auth_session_cookies(&self, realm: &RealmModel) -> Result<Vec<String>, String> {
        todo!()
    }

    async fn remove_authentication_session(
        &self,
        realm: &RealmModel,
        auth_session: &AuthenticationSession,
        expire_restart_cookie: bool,
    ) -> Result<(), String> {
        todo!()
    }

    async fn load_user_session(
        &self,
        auth_session: &AuthenticationSession,
    ) -> Result<Option<UserSession>, String> {
        todo!()
    }

    async fn load_authentication_session_by_id_and_client(
        &self,
        realm: &RealmModel,
        auth_session_id: &str,
        client: &ClientModel,
        tab_id: &str,
    ) -> Result<Option<AuthenticationSession>, String> {
        todo!()
    }

    async fn load_root_authentication_session(
        &self,
        realm: &RealmModel,
        auth_session_id: &str,
    ) -> Result<Option<RootAuthenticationSession>, String> {
        let root_session_provider: &dyn IRootAuthenticationSessionProvider =
            self.session.resolve_ref();
        let result = root_session_provider
            .load_root_authentication_session(&realm.realm_id, &auth_session_id)
            .await;
        if let Err(err) = result {
            return Err(err);
        }
        let root_session = result.unwrap();
        if let None = root_session {
            return Ok(None);
        }
        let root_session = root_session.unwrap();
        let auth_session_provider: &dyn IAuthenticationSessionProvider = self.session.resolve_ref();
        let auth_session_entities = auth_session_provider
            .load_authentication_sessions(&realm.realm_id, auth_session_id)
            .await;
        if let Err(err) = auth_session_entities {
            return Err(err);
        }
        let auth_session_entities = auth_session_entities.unwrap();
        let clients_ids: Vec<String> = auth_session_entities
            .iter()
            .map(|v| v.client_id.clone())
            .collect();
        let client_service: &dyn IClientService = self.session.resolve_ref();
        let clients_data = client_service
            .load_client_by_ids(&realm.realm_id, &clients_ids)
            .await;
        let mut auth_sessions_tabs: HashMap<String, AuthenticationSession> = HashMap::new();
        match clients_data {
            ApiResult::Data(clients) => {
                if clients.len() != clients_ids.len() {
                    log::error!("Found invalid clients");
                    return Ok(None);
                }
                let client_mapping: HashMap<String, ClientModel> = clients
                    .into_iter()
                    .map(|client| (client.client_id.clone(), client))
                    .collect::<HashMap<_, _>>();

                for auth_session in auth_session_entities {
                    let mut session = AuthenticationSession {
                        parent_session: None,
                        session_model: auth_session,
                        client: None,
                        user: None,
                    };
                    session.set_client(
                        client_mapping
                            .get(&session.session_model().client_id.as_ref().unwrap())
                            .unwrap(),
                    );
                    auth_sessions_tabs.insert(auth_session.tab_id.clone(), session);
                }
            }
            ApiResult::Error(err) => {
                return Err(err);
            }
            _ => return Ok(None),
        }
        let root_auth_session = RootAuthenticationSession {
            realm: realm,
            timestamp: 0,
            session_model: root_session,
            auth_sessions: auth_sessions_tabs,
        };
        todo!();
    }

    async fn remove_root_authentication_session(
        &self,
        realm: &RealmModel,
        root_auth_session: &RootAuthenticationSession,
    ) -> Result<(), String> {
        let root_session_provider: &dyn IRootAuthenticationSessionProvider =
            self.session.resolve_ref();
        let result = root_session_provider
            .remove_root_authentication_session(
                &root_auth_session.realm().realm_id,
                root_auth_session.session_id(),
            )
            .await;
        match result {
            Err(err) => Err(err),
            _ => Ok(()),
        }
    }

    async fn remove_authentication_session_by_tab_id(
        &self,
        root_auth_session: &mut RootAuthenticationSession,
        tab_id: &str,
    ) -> Result<(), String> {
        let session_provider: &dyn IAuthenticationSessionProvider = self.session.resolve_ref();
        if !root_auth_session.authentication_sessions().is_empty() {
            let auth_session = root_auth_session.authentication_sessions().get(tab_id);
            match auth_session {
                Some(session) => {
                    let result = session_provider
                        .remove_authentication_session(
                            &root_auth_session.realm().realm_id,
                            &session.client().as_ref().unwrap().client_id,
                            tab_id,
                        )
                        .await;
                    if let Err(err) = result {
                        return Err(err);
                    } else {
                        return Ok(());
                    }
                }
                None => return Ok(()),
            }
        }

        root_auth_session.remove_authentication_session_by_tab_id(tab_id);
        if root_auth_session.authentication_sessions().is_empty() {
            let root_session_provider: &dyn IRootAuthenticationSessionProvider =
                self.session.resolve_ref();
            let result = root_session_provider
                .remove_root_authentication_session(
                    &root_auth_session.realm().realm_id,
                    root_auth_session.session_id(),
                )
                .await;
            if let Err(err) = result {
                return Err(err);
            } else {
                return Ok(());
            }
        }
        Ok(())
    }

    async fn restart_session(
        &self,
        root_auth_session: &mut RootAuthenticationSession,
    ) -> Result<(), String> {
        let session_provider: &dyn IRootAuthenticationSessionProvider = self.session.resolve_ref();
        root_auth_session.clear_authentication_sessions();
        let timestamp = Utc::now().timestamp();
        root_auth_session.set_timestamp(timestamp);
        session_provider
            .update_root_authentication_session(root_auth_session.session_model())
            .await
    }

    async fn create_root_authentication_session_from_session_id(
        &self,
        realm: &Rc<RealmModel>,
        session_id: &str,
    ) -> Result<RootAuthenticationSession, String> {
        let timestamp = Utc::now().timestamp();
        let root_auth_session_model = RootAuthenticationSessionModel {
            tenant: realm.metadata.as_ref().unwrap().tenant.clone(),
            session_id: session_id.to_owned(),
            realm_id: realm.realm_id,
            timestamp: timestamp,
        };

        let session_provider: &dyn IRootAuthenticationSessionProvider = self.session.resolve_ref();
        let result = session_provider
            .create_root_authentication_session(&root_auth_session_model)
            .await;
        match result {
            Ok(_) => {
                let root_auth_session = RootAuthenticationSession {
                    realm: realm,
                    timestamp: timestamp,
                    session_model: root_auth_session_model,
                    auth_sessions: HashMap::new(),
                };
                Ok(root_auth_session)
            }
            Err(err) => {
                log::error!("Failed to create root authentication model");
                Err(err)
            }
        }
    }

    async fn set_auth_session_cookie(
        self,
        _session: &DarkshieldSession,
        _realm: &Rc<RealmModel>,
        _auth_session_id: &str,
    ) -> Result<(), String> {
        todo!()
    }

    async fn on_realm_removed(&self, realm_id: &str) -> Result<(), String> {
        let session_provider: &dyn IRootAuthenticationSessionProvider = self.session.resolve_ref();
        session_provider
            .remove_realm_authentication_sessions(realm_id)
            .await
    }
}
*/
