mod api;
mod configs;
mod metrics;
use actix_web::{middleware, web::Data, App, HttpServer};
use configs::EnvironmentConfig;
use deadpool_postgres::{tokio_postgres, Runtime};
use dotenv::dotenv;
use services::factory::DarkshieldServicesFactory;
use store::providers::rds::client::postgres_client::{DataBaseManager, DataBaseManagerParameters};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let config = EnvironmentConfig::static_configs();
    let connection_pool = config
        .database_config()
        .create_pool(Some(Runtime::Tokio1), tokio_postgres::NoTls)
        .unwrap();

    let services_factory = DarkshieldServicesFactory::builder()
        .with_component_parameters::<DataBaseManager>(DataBaseManagerParameters {
            connection_pool: Some(connection_pool),
        })
        .build();

    let context = Data::new(services_factory);
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(middleware::Logger::new("%a %{User-Agent}i"))
            .app_data(context.clone())
            .configure(api::rest::endpoints::api_config::register_apis)
    })
    .bind((config.server_host(), config.server_port()))?
    .run()
    .await
}
