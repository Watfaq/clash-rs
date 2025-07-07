use std::collections::HashMap;

use axum::response::IntoResponse;

pub async fn handle() -> axum::response::Response {
    let mut val = HashMap::new();
    val.insert("hello".to_owned(), "clash-rs".to_owned());
    axum::response::Json(val).into_response()
}
