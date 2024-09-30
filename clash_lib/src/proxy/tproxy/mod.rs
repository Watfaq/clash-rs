use std::{net::SocketAddr, sync::Arc};

use crate::{app::dispatcher::Dispatcher, proxy::InboundListener};
use async_trait::async_trait;

use tracing::warn;

pub struct Listener {
    addr: SocketAddr,
    dispather: Arc<Dispatcher>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        warn!("Tproxy inbound listener on {} stopped", self.addr);
    }
}

impl Listener {
    pub fn new(addr: SocketAddr, dispather: Arc<Dispatcher>) -> Self {
        Self { addr, dispather }
    }
}

#[async_trait]
impl InboundListener for Listener {
    fn handle_tcp(&self) -> bool {
        if cfg!(target_os = "linux") {
            true
        } else {
            false
        }
    }

    fn handle_udp(&self) -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    async fn listen_tcp(&self) -> std::io::Result<()> {
        use socket2::{Domain, Socket, Type};
        use tokio::net::TcpListener;
        use tracing::info;

        use crate::{
            proxy::utils::apply_tcp_options,
            session::{Network, Session},
        };

        let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        socket.set_ip_transparent(true)?;
        socket.bind(&self.addr.into())?;
        socket.listen(1024)?;

        let listener = TcpListener::from_std(socket.into())?;

        loop {
            let (socket, src_addr) = listener.accept().await?;

            let socket = apply_tcp_options(socket)?;

            // local_addr is getsockname
            let orig_dst = socket.local_addr()?;

            let sess = Session {
                network: Network::Tcp,
                source: src_addr,
                destination: orig_dst.into(),
                so_mark: Some(0x3332),
                ..Default::default()
            };

            info!("tproxy new conn {}", sess);

            let dispatcher = self.dispather.clone();
            tokio::spawn(async move {
                dispatcher.dispatch_stream(sess, socket).await;
            });
        }
    }

    #[cfg(not(target_os = "linux"))]
    async fn listen_tcp(&self) -> std::io::Result<()> {
        warn!("tproxy not supported on non Linux");
        Ok(())
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        unimplemented!("don't listen to me :)")
    }
}
