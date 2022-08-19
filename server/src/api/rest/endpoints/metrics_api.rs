use actix_web::{get, HttpResponse, Responder};

use prometheus::TextEncoder;

#[get("/metrics")]
pub async fn metrics_handler() -> impl Responder {
    let encoder = TextEncoder::new();
    let mut writer = String::new();

    encoder
        .encode_utf8(&prometheus::gather(), &mut writer)
        .expect("Failed to encode metrics");

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/plain"))
        .body(writer.to_owned())
}
