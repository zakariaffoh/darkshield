use deadpool_postgres::Config;
use store::providers::rds::client::postgres_client::*;

pub fn rds_data_base() -> DataBaseManager {
    let mut config = Config::new();
    config.user = Some("om-devops-db".to_owned());
    config.password = Some("mairie3golfe".to_owned());
    config.dbname = Some("darkshield_store_dev".to_owned());
    config.host = Some("20.72.115.220".to_owned());
    config.port = Some(5432);
    DataBaseManager::new(config)
}
