use async_trait::async_trait;

use crate::proxy::AnyStream;

#[async_trait]
pub trait Plugin: Send + Sync {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream>;
}
