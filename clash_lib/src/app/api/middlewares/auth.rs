use axum::{body::Body, extract::Query, http::Request, response::Response};
use futures::future::BoxFuture;

use serde::Deserialize;
use tower::{Layer, Service};

#[derive(Debug, Clone, Deserialize)]
struct AuthQuery {
    token: String,
}

#[derive(Debug, Clone)]
pub struct AuthMiddlewareLayer {
    pub token: String,
}

impl AuthMiddlewareLayer {
    pub fn new(token: String) -> Self {
        Self { token }
    }
}

impl<S> Layer<S> for AuthMiddlewareLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware::new(inner, self.token.clone())
    }
}

#[derive(Debug, Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    token: String,
}

impl<S> AuthMiddleware<S> {
    pub fn new(inner: S, token: String) -> Self {
        Self { inner, token }
    }

    fn is_websocket(&self, req: &Request<Body>) -> bool {
        req.headers()
            .get("upgrade")
            .map(|upgrade| upgrade == "websocket")
            .unwrap_or(false)
    }
}

impl<S> Service<Request<Body>> for AuthMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    type Response = S::Response;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        if self.token.is_empty() {
            return Box::pin(self.inner.call(req));
        }

        let unauthorised = Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .body("unauthorized".to_string().into())
            .unwrap();

        if self.is_websocket(&req) {
            let q = Query::<AuthQuery>::try_from_uri(req.uri()).ok();
            if let Some(q) = q {
                if q.token == self.token {
                    return Box::pin(self.inner.call(req));
                }
            }
        }

        let header = req
            .headers()
            .get("authorization")
            .map(|x| x.to_str().unwrap_or_default())
            .unwrap_or_default();

        if header == format!("Bearer {}", self.token) {
            return Box::pin(self.inner.call(req));
        }

        Box::pin(async move { Ok(unauthorised) })
    }
}
