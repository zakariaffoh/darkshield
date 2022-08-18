mod api;
mod context;
mod metrics;
mod services;

use actix_web::{middleware::Logger, web::Data, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let context = Data::new(context::context::DarkShieldContext::new(
        services::rds::database::rds_data_base(),
    ));

    HttpServer::new(move || {
        App::new()
            .configure(api::rest::endpoints::api_config::register_apis)
            .wrap(Logger::new("%a %{User-Agent}i"))
            .app_data(context.clone())
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
