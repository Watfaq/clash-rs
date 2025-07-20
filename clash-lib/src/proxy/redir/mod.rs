use super::inbound::InboundHandlerTrait;
use crate::{
    app::dispatcher::Dispatcher,
    proxy::utils::{
        ToCanonical, apply_tcp_options, try_create_dualstack_tcplistener,
    },
    session::{Network, Session, Type},
};

use async_trait::async_trait;
use std::{io, net::SocketAddr, os::fd::AsRawFd, sync::Arc};
use tokio::net::TcpStream;
use tracing::{trace, warn};

pub struct RedirInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
}

impl Drop for RedirInbound {
    fn drop(&mut self) {
        warn!("Redir inbound listener on {} stopped", self.addr);
    }
}

impl RedirInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        fw_mark: Option<u32>,
    ) -> Self {
        Self {
            addr,
            allow_lan,
            dispatcher,
            fw_mark,
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for RedirInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let listener = try_create_dualstack_tcplistener(self.addr)?;

        loop {
            let (socket, _) = listener.accept().await?;
            let src_addr = socket.peer_addr()?.to_canonical();

            if !self.allow_lan
                && src_addr.ip() != socket.local_addr()?.ip().to_canonical()
            {
                warn!("Connection from {} is not allowed", src_addr);
                continue;
            }

            apply_tcp_options(&socket)?;

            // get redirect traffic original destination
            let orig_dst = get_original_destination_addr(&socket)?.to_canonical();

            let sess = Session {
                network: Network::Tcp,
                typ: Type::Tproxy,
                source: src_addr,
                destination: orig_dst.into(),
                so_mark: self.fw_mark,
                ..Default::default()
            };

            trace!("redir new tcp conn {}", sess);

            let dispatcher = self.dispatcher.clone();
            tokio::spawn(async move {
                dispatcher.dispatch_stream(sess, Box::new(socket)).await;
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        panic!("redir doesn't support udp")
    }
}

// get original destination
// https://github.com/shadowsocks/shadowsocks-rust/blob/master/crates/shadowsocks-service/src/local/redir/tcprelay/sys/unix/linux.rs#L111
fn get_original_destination_addr(s: &TcpStream) -> io::Result<SocketAddr> {
    let fd = s.as_raw_fd();

    unsafe {
        let (_, target_addr) =
            socket2::SockAddr::try_init(|target_addr, target_addr_len| {
                // No sufficient method to know whether the destination IPv4 or IPv6.
                // Follow the method in shadowsocks-libev.

                let ret = libc::getsockopt(
                    fd,
                    libc::SOL_IPV6,
                    libc::IP6T_SO_ORIGINAL_DST,
                    target_addr as *mut _,
                    target_addr_len, // libc::socklen_t
                );

                if ret == 0 {
                    return Ok(());
                } else {
                    let err = io::Error::last_os_error();
                    match err.raw_os_error() {
                        None => return Err(err),
                        // ENOPROTOOPT, EOPNOTSUPP (ENOTSUP): IP6T_SO_ORIGINAL_DST
                        // doesn't exist ENOENT: Destination
                        // address is not IPv6
                        #[allow(unreachable_patterns)]
                        Some(libc::ENOPROTOOPT)
                        | Some(libc::ENOENT)
                        | Some(libc::EOPNOTSUPP)
                        | Some(libc::ENOTSUP) => {}
                        Some(..) => return Err(err),
                    }
                }

                let ret = libc::getsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::SO_ORIGINAL_DST,
                    target_addr as *mut _,
                    target_addr_len, // libc::socklen_t
                );

                if ret != 0 {
                    let err = io::Error::last_os_error();
                    return Err(err);
                }

                Ok(())
            })?;

        // Convert sockaddr_storage to SocketAddr
        Ok(target_addr.as_socket().expect("SocketAddr"))
    }
}
