mod api;
mod context;
mod metrics;
mod services;

use actix_web::{middleware::Logger, web::Data, App, HttpServer};
use context::context::build_darkshield_context;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let darkshield_context = build_darkshield_context();
    let context = Data::new(darkshield_context);

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
