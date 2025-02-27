use async_trait::async_trait;

use super::Transport;
use crate::proxy::AnyStream;

#[async_trait]
pub trait Plugin: Send + Sync {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream>;
}

#[async_trait]
impl<T: Transport> Plugin for T {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        Transport::proxy_stream(self, stream).await
    }
}
