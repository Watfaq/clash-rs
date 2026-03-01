use std::collections::HashMap;

use axum::response::IntoResponse;

const VERSION: &str = env!("CLASH_VERSION_OVERRIDE");

pub async fn handle() -> impl IntoResponse {
    let mut val = HashMap::new();
    val.insert("version".to_owned(), VERSION.to_owned());
    val.insert("meta".to_owned(), "true".to_owned());
    axum::response::Json(val)
}
