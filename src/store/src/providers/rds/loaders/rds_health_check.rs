use crate::providers::{
    interfaces::health_check::IHealthCheckProvider,
    rds::{client::postgres_client::IDataBaseManager, tables::health_table::HEALTH_CHECK_QUERY},
};
use async_trait::async_trait;
use shaku::Component;
use std::sync::Arc;

#[allow(dead_code)]
#[derive(Component)]
#[shaku(interface = IHealthCheckProvider)]
pub struct RdsHealthCheckProvider {
    #[shaku(inject)]
    pub database_manager: Arc<dyn IDataBaseManager>,
}

#[async_trait]
impl IHealthCheckProvider for RdsHealthCheckProvider {
    async fn health_check(&self) -> Result<(), String> {
        let db_client = self.database_manager.connection().await;
        if let Err(err) = db_client {
            return Err(err);
        }
        let client = db_client.unwrap();
        let health_stmt = client.prepare_cached(&HEALTH_CHECK_QUERY).await.unwrap();
        let response = client.query_one(&health_stmt, &[]).await;
        match response {
            Ok(row) => {
                let res = row.get::<usize, i32>(0);
                if res == 1 {
                    Ok(())
                } else {
                    Err("Health check failed".to_owned())
                }
            }
            Err(error) => Err(error.to_string()),
        }
    }
}
