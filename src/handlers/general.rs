/// Health check endpoint
///
/// Returns server health status. Used by load balancers and monitoring systems.
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Server is healthy", body = String),
    ),
    tag = "general",
)]
pub async fn health() -> &'static str {
    "everything OK"
}
