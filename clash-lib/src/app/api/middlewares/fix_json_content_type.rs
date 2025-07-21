use axum::{
    extract::Request, http::HeaderValue, middleware::Next, response::Response,
};

pub(crate) async fn fix_content_type(mut req: Request, next: Next) -> Response {
    // Check if body looks like JSON but content-type is wrong
    if let Some(content_type) = req.headers().get("content-type")
        && content_type != "application/json"
    {
        // Modify headers to set correct content-type
        req.headers_mut()
            .insert("content-type", HeaderValue::from_static("application/json"));
    }

    next.run(req).await
}
