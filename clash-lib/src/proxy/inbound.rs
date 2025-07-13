use async_trait::async_trait;

#[async_trait]
pub trait InboundHandlerTrait: Sync + Send {
    /// support tcp or not
    fn handle_tcp(&self) -> bool;
    /// support udp or not
    fn handle_udp(&self) -> bool;
    async fn listen_tcp(&self) -> std::io::Result<()>;
    async fn listen_udp(&self) -> std::io::Result<()>;
}
