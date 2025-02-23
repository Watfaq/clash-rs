use enum_dispatch::enum_dispatch;

use super::{
    http::HttpInbound, mixed::MixedInbound, socks::SocksInbound,
    tunnel::TunnelInbound,
};

#[enum_dispatch(InboudHandler)]
pub trait InboundHandlerTrait {
    /// support tcp or not
    fn handle_tcp(&self) -> bool;
    /// support udp or not
    fn handle_udp(&self) -> bool;
    async fn listen_tcp(&self) -> anyhow::Result<()>;
    async fn listen_udp(&self) -> anyhow::Result<()>;
}

#[enum_dispatch]
pub enum InboudHandler {
    Http(HttpInbound),
    Socks(SocksInbound),
    Mixed(MixedInbound),
    #[cfg(target_os = "linux")]
    TProxy(super::tproxy::TproxyInbound),
    Tunnel(TunnelInbound),
}
