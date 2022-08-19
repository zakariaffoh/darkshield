use lazy_static::lazy_static;

use prometheus::{register_counter, register_histogram, Counter, Histogram};

lazy_static! {
    static ref PUSH_COUNTER: Counter = register_counter!(
        "example_push_total",
        "Total number of prometheus client pushed."
    )
    .unwrap();
    static ref PUSH_REQ_HISTOGRAM: Histogram = register_histogram!(
        "example_push_request_duration_seconds",
        "The push request latencies in seconds."
    )
    .unwrap();
}

pub fn register_metrics() {
    let registry = prometheus::default_registry();
}
