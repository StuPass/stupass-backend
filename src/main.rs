use axum::{routing::get, Router};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind to address");

    println!("Server listening on http://0.0.0.0:3000");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

async fn root() -> &'static str {
    ""
}

async fn health() -> &'static str {
    "everything OK"
}
