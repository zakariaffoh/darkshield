use store::providers::rds::client::postgres_client::DataBaseManager;

#[allow(dead_code)]
pub struct DarkShieldContext {
    database: DataBaseManager,
}

#[allow(dead_code)]
impl DarkShieldContext {
    pub fn new(database: DataBaseManager) -> Self {
        Self { database: database }
    }

    pub fn database(&self) -> &DataBaseManager {
        &self.database
    }
}
