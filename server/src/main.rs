use actix_web::{get, web, App, HttpServer, Responder};
extern crate models;

use models::authz;

#[get("/hello/{name}")]
async fn greet(name: web::Path<String>) -> impl Responder {
    format!("Hello {name}!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let dat = "data".to_string();
    println!("{}", dat);
    HttpServer::new(|| App::new().service(greet))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
