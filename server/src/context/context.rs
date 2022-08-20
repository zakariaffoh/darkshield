use store::providers::rds::client::postgres_client::DataBaseManager;

#[allow(dead_code)]
pub struct DarkShieldContext {
    database: DataBaseManager,
    message: String,
}

#[allow(dead_code)]
impl DarkShieldContext {
    pub fn new(database: DataBaseManager) -> Self {
        Self {
            database: database,
            message: "My Context".to_owned(),
        }
    }

    pub fn database(&self) -> &DataBaseManager {
        &self.database
    }
    pub fn message(&self) -> &String {
        &self.message
    }
}
