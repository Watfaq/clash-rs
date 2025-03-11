use std::sync::Arc;

use enum_dispatch::enum_dispatch;

use watfaq_error::Result;
use watfaq_state::{Context, ContextScope};

use super::{
    http::HttpInbound, mixed::MixedInbound, socks::SocksInbound,
    tunnel::TunnelInbound,
};

#[enum_dispatch(InboudHandler)]
pub trait AbstractInboundHandler {
    fn ctx(&self) -> &Context {
        todo!()
    }
    fn clone_ctx(&self) -> Arc<Context> {
        todo!()
    }
    /// support listen on TCP socket or not
    fn handle_tcp(&self) -> bool;
    /// support listen on UDP socket or not
    fn handle_udp(&self) -> bool;
    async fn listen_tcp(&self) -> Result<()>;
    async fn listen_udp(&self) -> Result<()>;
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
