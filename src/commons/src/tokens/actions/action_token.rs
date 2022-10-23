use anyhow::bail;
use base64_url::base64;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::str;

use crate::tokens::jwt_error::ActionTokenError;

#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize)]
pub struct ActionToken {
    pub user_id: String,
    pub action_id: String,
    pub expiration_in_seconds: i64,
    pub action_verification_nonce: Option<String>,
    pub notes: BTreeMap<String, String>,
}

impl ActionToken {
    pub fn new(
        user_id: &str,
        action_id: &str,
        expiration_in_seconds: i64,
        action_verification_nonce: &str,
        notes: BTreeMap<String, String>,
    ) -> Self {
        Self {
            user_id: user_id.to_owned(),
            action_id: action_id.to_owned(),
            expiration_in_seconds: expiration_in_seconds,
            action_verification_nonce: Some(action_verification_nonce.to_owned()),
            notes: notes.clone(),
        }
    }

    pub fn serialize(&self) -> String {
        let verification_nonce = if let Some(n) = &self.action_verification_nonce {
            n.clone()
        } else {
            String::new()
        };

        let token = format!(
            "{}.{}.{}.{}",
            self.user_id, self.action_id, self.expiration_in_seconds, verification_nonce
        );
        base64::encode_config(token, base64::URL_SAFE_NO_PAD)
    }

    pub fn deserialize(action_token: &str) -> Result<ActionToken, ActionTokenError> {
        (|| -> anyhow::Result<ActionToken> {
            let decoded_token =
                base64::decode_config(&action_token.as_bytes(), base64::URL_SAFE_NO_PAD);

            match decoded_token {
                Ok(res) => {
                    let decoded_string = str::from_utf8(&res);
                    match decoded_string {
                        Ok(decoded_token) => {
                            let tokens: Vec<_> = decoded_token.split(".").collect();
                            if tokens.len() == 4 {
                                let expiration_in_seconds = tokens[2].parse::<i64>();
                                if let Err(_) = expiration_in_seconds {
                                    bail!("{}", action_token)
                                }

                                let action = ActionToken::new(
                                    tokens[0],
                                    tokens[1],
                                    expiration_in_seconds.unwrap(),
                                    tokens[3],
                                    BTreeMap::new(),
                                );
                                return Ok(action);
                            } else {
                                bail!("{}", action_token)
                            }
                        }
                        _ => bail!("{}", action_token),
                    }
                }
                Err(_) => bail!("{}", action_token),
            }
        })()
        .map_err(|err| match err.downcast::<ActionTokenError>() {
            Ok(err) => err,
            Err(err) => ActionTokenError::InvalidActionTokenFormat(err),
        })
    }

    pub fn set_note(&mut self, name: &str, value: &str) -> Option<String> {
        let existing_note = self.notes.get(name).cloned();
        self.notes.insert(name.to_owned(), value.to_owned());
        if let Some(d) = existing_note {
            return Some(d.clone());
        } else {
            None
        }
    }

    pub fn remove_note(&mut self, name: &str) -> Option<String> {
        let existing_note = self.notes.get(name).cloned();
        self.notes.remove(name);
        if let Some(d) = existing_note {
            return Some(d.clone());
        } else {
            None
        }
    }
}
