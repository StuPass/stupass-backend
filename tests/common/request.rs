#![allow(dead_code, unused_imports)]

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tower::ServiceExt;

/// Send a POST request and collect the raw response.
async fn send_post(app: &Router, path: &str, body: Value) -> (u16, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    8080,
                ))))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status().as_u16();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, body_bytes.to_vec())
}

/// Deserialize `bytes` into `T`, panicking with a diagnostic message on failure.
fn deserialize_or_panic<T: DeserializeOwned>(status: u16, path: &str, bytes: &[u8]) -> T {
    serde_json::from_slice(bytes).unwrap_or_else(|e| {
        panic!(
            "Failed to deserialize response into {}\n\
             Status: {status} | Path: {path}\n\
             Error : {e}\n\
             Body  : {}",
            std::any::type_name::<T>(),
            String::from_utf8_lossy(bytes)
        )
    })
}

/// Helper to make JSON POST requests and deserialize response
pub async fn post_json<T: DeserializeOwned>(app: &Router, path: &str, body: Value) -> (u16, T) {
    let (status, body_bytes) = send_post(app, path, body).await;
    let response_body: T = deserialize_or_panic(status, path, &body_bytes);
    (status, response_body)
}

/// Helper to POST and get back a raw `serde_json::Value` (never fails on shape).
pub async fn post_json_value(app: &Router, path: &str, body: Value) -> (u16, Value) {
    let (status, body_bytes) = send_post(app, path, body).await;
    let value: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|e| {
        panic!(
            "Response is not valid JSON\nStatus: {status} | Path: {path}\nError: {e}\nBody: {}",
            String::from_utf8_lossy(&body_bytes)
        )
    });
    (status, value)
}

/// Helper for raw response body (useful for debugging)
pub async fn post_json_raw(app: &Router, path: &str, body: Value) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    8080,
                ))))
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    (status, body_str)
}

/// Helper for GET requests with query parameters
pub async fn get_with_query<T: DeserializeOwned>(app: &Router, path: &str) -> (u16, T) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    8080,
                ))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status().as_u16();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let response_body: T = deserialize_or_panic(status, path, &body_bytes);

    (status, response_body)
}

/// Helper for GET requests returning raw string body (e.g., HTML responses)
pub async fn get_raw(app: &Router, path: &str) -> (u16, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    8080,
                ))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status().as_u16();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    (status, body_str)
}
