use async_trait::async_trait;

use crate::proxy::AnyStream;

use super::Transport;

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
