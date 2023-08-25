use axum::http::Request;
use axum::{body::Body, response::Response};
use futures::future::BoxFuture;
use tower::{Layer, Service};

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
    type Response = S::Response;

    type Error = S::Error;

    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

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
            .body(axum::body::boxed("unauthorized".to_string()))
            .unwrap();

        // uri doesn't contain scheme and host
        let ur =
            url::Url::parse(format!("http://localhost{}", req.uri().to_string()).as_str()).unwrap();

        if self.is_websocket(&req)
            && req
                .uri()
                .query()
                .map(|q| q.contains("token"))
                .unwrap_or(false)
        {
            let token = ur
                .query_pairs()
                .find_map(|(k, v)| {
                    if k == "token" {
                        Some(v.to_string())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            if token == self.token {
                return Box::pin(self.inner.call(req));
            } else {
                return Box::pin(async move { Ok(unauthorised) });
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
