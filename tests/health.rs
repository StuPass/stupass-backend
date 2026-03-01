#[allow(unused_imports)]
mod common;
use axum::{Router, routing::get};
use common::get_raw;
use stupass_backend::handlers::general;

#[tokio::test]
async fn health_check_returns_ok() {
    let app = Router::new().route("/health", get(general::health));

    let (status, body) = get_raw(&app, "/health").await;

    assert_eq!(status, 200);
    assert_eq!(body, "everything OK");
}
