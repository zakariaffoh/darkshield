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

#[async_trait]
impl IDataBaseManager for DataBaseManager {
    async fn connection(&self) -> Result<Object, String> {
        let connection = self.connection_pool.as_ref().unwrap().get().await;
        match connection {
            Err(err) => Err(err.to_string()),
            Ok(connection) => Ok(connection),
        }
    }
}
