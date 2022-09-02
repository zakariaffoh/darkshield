mod api;
mod context;
mod metrics;
mod services;
use ::services::catalog::DarkshieldServices;
use actix_web::{middleware, web::Data, App, HttpServer};
use context::{DarkShieldContext, EnvironmentConfig};
use deadpool_postgres::{tokio_postgres, Runtime};
use dotenv::dotenv;
use store::providers::rds::client::postgres_client::{DataBaseManager, DataBaseManagerParameters};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    //let config = EnvironmentConfig::from_env();
    let config = EnvironmentConfig::static_configs();
    let connection_pool = config
        .database_config()
        .create_pool(Some(Runtime::Tokio1), tokio_postgres::NoTls)
        .unwrap();

    let darkshield_services = DarkshieldServices::builder()
        .with_component_parameters::<DataBaseManager>(DataBaseManagerParameters {
            connection_pool: Some(connection_pool),
        })
        .build();

    let darkshield_context = DarkShieldContext::new(darkshield_services);
    let context = Data::new(darkshield_context);
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(middleware::Logger::new("%a %{User-Agent}i"))
            .app_data(context.clone())
            .configure(api::rest::endpoints::api_config::register)
    })
    .bind((config.server_host(), config.server_port()))?
    .run()
    .await
}
