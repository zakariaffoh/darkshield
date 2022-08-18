use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct RealmCreateModel {
    realm_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct RealmUpdateModel {
    realm_id: String,
}
