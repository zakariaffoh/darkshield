use async_trait::async_trait;
use deadpool_postgres::{Object, Pool, Runtime};
use tokio_postgres::NoTls;

use shaku::{Component, Interface};

#[async_trait]
pub trait IDataBaseManager: Interface {
    async fn connection(&self) -> Result<Object, String>;
}

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IDataBaseManager)]
pub struct DataBaseManager {
    pub connection_pool: Option<Pool>,
}

impl DataBaseManager {
    pub fn new(config: deadpool_postgres::Config) -> Self {
        let pool = config
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(|err| err.to_string())
            .unwrap();
        Self {
            connection_pool: Some(pool),
        }
    }
}

#[async_trait]
impl IDataBaseManager for DataBaseManager {
    async fn connection(&self) -> Result<Object, String> {
        self.connection_pool
            .as_ref()
            .unwrap()
            .get()
            .await
            .map_err(|err| err.to_string())
    }
}
