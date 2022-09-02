use deadpool_postgres::PoolConfig;
use dotenv::dotenv;
use serde::Deserialize;
use std::{env, time::Duration};

use services::catalog::DarkshieldServices;

#[allow(dead_code)]
pub struct DarkShieldContext {
    services: DarkshieldServices,
}

impl DarkShieldContext {
    pub fn new(services: DarkshieldServices) -> Self {
        Self { services: services }
    }

    pub fn services(&self) -> &DarkshieldServices {
        &self.services
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct EnvironmentConfig {
    pg_host: String,
    pg_port: u16,
    pg_user: String,
    pg_password: String,
    pg_dbname: String,
    pg_pool_max_size: usize,
    pg_connection_timeouts_secs: u64,
    pg_pool_timeouts_wait_nanos: u64,
    server_host: String,
    server_port: u16,
    log_level: String,
}

#[allow(dead_code)]
impl EnvironmentConfig {
    pub fn from_env() -> Self {
        Self {
            pg_host: env::var("DS_PG_HOST").unwrap(),
            pg_port: env::var("DS_PG_PORT").unwrap().parse::<u16>().unwrap(),
            pg_user: env::var("DS_PG_USER").unwrap(),
            pg_password: env::var("DS_PG_PASSWORD").unwrap(),
            pg_dbname: env::var("DS_PG_DBNAME").unwrap(),
            pg_pool_max_size: env::var("DS_PG_POOL_MAX_SIZE")
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            pg_connection_timeouts_secs: env::var("DS_PG_CONNECTION_TIMEOUT_SECS")
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            pg_pool_timeouts_wait_nanos: env::var("DS_PG_POOL_TIMEOUTS_WAIT_NANOS")
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            server_host: env::var("DS_SEVER_HOST").unwrap(),
            server_port: env::var("DS_SEVER_PORT").unwrap().parse::<u16>().unwrap(),
            log_level: env::var("RUST_LOG").unwrap(),
        }
    }
    pub fn static_configs() -> Self {
        Self {
            pg_host: "20.72.115.220".to_owned(),
            pg_port: 5432,
            pg_user: "om-devops-db".to_owned(),
            pg_password: "mairie3golfe".to_owned(),
            pg_dbname: "darkshield_store_dev".to_owned(),
            pg_pool_max_size: 16,
            pg_connection_timeouts_secs: 60,
            pg_pool_timeouts_wait_nanos: 0,
            server_host: "127.0.0.1".to_owned(),
            server_port: 8080,
            log_level: "actix_web=debug,actix_server=debug".to_owned(),
        }
    }

    pub fn database_config(&self) -> deadpool_postgres::Config {
        let mut config = deadpool_postgres::Config::new();
        config.user = Some(self.pg_user.clone());
        config.password = Some(self.pg_password.clone());
        config.dbname = Some(self.pg_dbname.clone());
        config.host = Some(self.pg_host.clone());
        config.port = Some(self.pg_port);
        config.connect_timeout = Some(Duration::from_secs(self.pg_connection_timeouts_secs));
        config.pool = Some(PoolConfig::new(self.pg_pool_max_size));
        config
    }

    pub fn server_host(&self) -> String {
        self.server_host.clone()
    }

    pub fn server_port(&self) -> u16 {
        self.server_port
    }

    pub fn log_level(&self) -> String {
        self.log_level.clone()
    }
}

#[cfg(test)]
mod tests {

    /*use super::*;

    #[test]
    fn test_env_config() {
        let config = EnvironmentConfig::from_env();
        assert_eq!(config.pg_dbname, "darkshield_store_dev");
    }*/
}
