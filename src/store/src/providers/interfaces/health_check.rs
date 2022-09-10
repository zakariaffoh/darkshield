use async_trait::async_trait;
use shaku::Interface;

#[async_trait]
pub trait IHealthCheckProvider: Interface {
    async fn health_check(&self) -> Result<(), String>;
}
