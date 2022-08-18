mod api;
use actix_web::{middleware::Logger, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .configure(api::rest::endpoints::api_config::register_apis)
            .wrap(Logger::new("%a %{User-Agent}i"))
    })
    .worker_max_blocking_threads(10)
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
