use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SingleUseToken {
    pub tenant: String,
    pub realm_id: String,
    pub token_id: String,
    pub lifespan_in_secs: f64,
}
