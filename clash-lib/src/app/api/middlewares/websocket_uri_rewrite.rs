use axum::{
    extract::Request,
    http::{Uri, header},
};

/// Rewrite WebSocket request URIs by adding /ws prefix to the path
///
/// When a WebSocket upgrade request is detected (by checking for Upgrade:
/// websocket header), this function will transform the URI path from `/uri`
/// to `/ws/uri`. This should be used with tower::ServiceBuilder and map_request
/// to ensure it runs before routing.
pub(crate) fn rewrite_websocket_uri(mut req: Request) -> Request {
    // Check if this is a WebSocket upgrade request
    let is_websocket = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if is_websocket {
        let original_uri = req.uri().clone();
        let path = original_uri.path();

        // Only rewrite if the path doesn't already start with /ws
        if !path.starts_with("/ws") {
            // Construct new path with /ws prefix, removing trailing slash from
            // original path
            let trimmed_path = path.trim_end_matches('/');
            let new_path = if trimmed_path.is_empty() {
                "/ws".to_string()
            } else {
                format!("/ws{}", trimmed_path)
            };

            // Build new URI with the modified path
            let mut parts = original_uri.clone().into_parts();

            // Reconstruct the path and query if present
            let new_path_and_query = if let Some(query) =
                parts.path_and_query.as_ref().and_then(|pq| pq.query())
            {
                format!("{}?{}", new_path, query)
            } else {
                new_path
            };

            // Parse and set the new path and query
            if let Ok(new_pq) = new_path_and_query.parse() {
                parts.path_and_query = Some(new_pq);

                // Reconstruct URI
                if let Ok(new_uri) = Uri::from_parts(parts) {
                    tracing::debug!(
                        "Rewriting WebSocket URI from {} to {}",
                        original_uri,
                        new_uri
                    );
                    *req.uri_mut() = new_uri;
                }
            }
        }
    }

    req
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use tower::{Layer, ServiceExt, util::MapRequestLayer};

    // Helper function to create a test handler
    async fn test_handler(req: Request<Body>) -> impl IntoResponse {
        // Return the URI path that the handler received
        (StatusCode::OK, req.uri().to_string())
    }

    #[tokio::test]
    async fn test_websocket_uri_rewrite_adds_prefix() {
        let router = Router::new().route("/ws/api/messages", get(test_handler));
        let app = MapRequestLayer::new(rewrite_websocket_uri).layer(router);

        let request = Request::builder()
            .uri("/api/messages")
            .header("upgrade", "websocket")
            .header("connection", "upgrade")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let uri = String::from_utf8(body.to_vec()).unwrap();

        assert_eq!(uri, "/ws/api/messages");
    }

    #[tokio::test]
    async fn test_websocket_uri_with_query_params() {
        let router = Router::new().route("/ws/api/messages", get(test_handler));
        let app = MapRequestLayer::new(rewrite_websocket_uri).layer(router);

        let request = Request::builder()
            .uri("/api/messages?token=abc123&limit=10")
            .header("upgrade", "websocket")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let uri = String::from_utf8(body.to_vec()).unwrap();

        assert_eq!(uri, "/ws/api/messages?token=abc123&limit=10");
    }

    #[tokio::test]
    async fn test_non_websocket_request_unchanged() {
        let router = Router::new().route("/api/messages", get(test_handler));
        let app = MapRequestLayer::new(rewrite_websocket_uri).layer(router);

        let request = Request::builder()
            .uri("/api/messages")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let uri = String::from_utf8(body.to_vec()).unwrap();

        assert_eq!(uri, "/api/messages");
    }

    #[tokio::test]
    async fn test_already_has_ws_prefix() {
        let router = Router::new().route("/ws/api/messages", get(test_handler));
        let app = MapRequestLayer::new(rewrite_websocket_uri).layer(router);

        let request = Request::builder()
            .uri("/ws/api/messages")
            .header("upgrade", "websocket")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let uri = String::from_utf8(body.to_vec()).unwrap();

        assert_eq!(uri, "/ws/api/messages");
    }

    #[tokio::test]
    async fn test_trailing_slash_removed() {
        let router = Router::new().route("/ws/api/messages", get(test_handler));
        let app = MapRequestLayer::new(rewrite_websocket_uri).layer(router);

        let request = Request::builder()
            .uri("/api/messages/")
            .header("upgrade", "websocket")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let uri = String::from_utf8(body.to_vec()).unwrap();

        assert_eq!(uri, "/ws/api/messages");
    }

    #[tokio::test]
    async fn test_root_path() {
        let router = Router::new().route("/ws", get(test_handler));
        let app = MapRequestLayer::new(rewrite_websocket_uri).layer(router);

        let request = Request::builder()
            .uri("/")
            .header("upgrade", "websocket")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let uri = String::from_utf8(body.to_vec()).unwrap();

        assert_eq!(uri, "/ws");
    }

    #[tokio::test]
    async fn test_case_insensitive_websocket_header() {
        let router = Router::new().route("/ws/api/chat", get(test_handler));
        let app = MapRequestLayer::new(rewrite_websocket_uri).layer(router);

        let request = Request::builder()
            .uri("/api/chat")
            .header("upgrade", "WebSocket")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let uri = String::from_utf8(body.to_vec()).unwrap();

        assert_eq!(uri, "/ws/api/chat");
    }
}
