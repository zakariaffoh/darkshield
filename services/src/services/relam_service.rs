use models::entities::realm::RealmModel;
use store::providers::rds::client::postgres_client::DataBaseManager;

#[allow(dead_code)]
pub struct RealmService<'d> {
    database: &'d DataBaseManager,
}

impl<'d> RealmService<'d> {
    pub fn new(database: &'d DataBaseManager) -> Self {
        Self { database: database }
    }
    pub async fn create_realm(&self, realm: RealmModel) {}
}
