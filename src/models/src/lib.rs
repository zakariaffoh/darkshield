use serde::Deserialize;

pub mod auditable;
pub mod authentication;
pub mod credentials;
pub mod entities;

#[derive(Deserialize, Debug)]
pub struct PagingParams {
    pub page_index: Option<u64>,
    pub page_size: Option<u64>,
}
