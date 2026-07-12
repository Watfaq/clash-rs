use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tracing::{Instrument, error, info_span};

use crate::{
    Inbound, ProxyRequest,
    config::AuthUser,
    config::MixedServerCfg,
    error::{SError, SResult},
    http::inbound::{HttpProxyServer, ProxyBasicAuth},
    socks::inbound::SocksServer,
    utils::dual_socket::to_ipv4_mapped,
    utils::replay_stream::ReplayStream,
};

pub struct MixedServer {
    cfg: MixedServerCfg,
    request_sender: Sender<ProxyRequest>,
    request_receiver: Receiver<ProxyRequest>,
}

impl MixedServer {
    pub async fn new(cfg: MixedServerCfg) -> Result<Self, SError> {
        let (s, r) = channel(20);
        Ok(Self {
            cfg,
            request_sender: s,
            request_receiver: r,
        })
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    http: Arc<HttpProxyServer>,
    users: Arc<Vec<AuthUser>>,
    sender: Sender<ProxyRequest>,
) -> SResult<()> {
    use tokio::io::AsyncReadExt;

    let local_addr = to_ipv4_mapped(stream.local_addr().unwrap());
    let first_byte = stream.read_u8().await?;

    let req = if first_byte == 0x05 {
        let prefix = vec![first_byte];
        SocksServer::accept_stream_with_local_addr(
            ReplayStream::new(prefix, stream),
            local_addr,
            &users,
        )
        .await?
    } else {
        let prefix = vec![first_byte];
        http.accept_stream(ReplayStream::new(prefix, stream))
            .await?
    };

    sender
        .send(req)
        .await
        .map_err(|_| SError::ChannelError("mixed request channel closed".into()))
}

#[async_trait]
impl Inbound for MixedServer {
    async fn accept(&mut self) -> Result<ProxyRequest, SError> {
        let recv = self
            .request_receiver
            .recv()
            .await
            .ok_or(SError::InboundUnavailable)?;
        Ok(recv)
    }

    async fn init(&self) -> Result<(), SError> {
        let bind_addr = self.cfg.bind_addr;
        let dual_stack = bind_addr.is_ipv6();
        let socket = Socket::new(
            if dual_stack {
                Domain::IPV6
            } else {
                Domain::IPV4
            },
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        if dual_stack {
            let _ = socket
                .set_only_v6(false)
                .map_err(|e| tracing::warn!("failed to set dual stack for socket: {}", e));
        }
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&bind_addr.into())?;
        socket.listen(256)?;

        let listener = TcpListener::from_std(socket.into())
            .map_err(|e| SError::SocksError(format!("failed to create TcpListener: {e}")))?;

        let http_users = self
            .cfg
            .users
            .iter()
            .map(|u| ProxyBasicAuth {
                username: u.username.clone(),
                password: u.password.clone(),
            })
            .collect();

        let http = Arc::new(HttpProxyServer::with_users(http_users));
        let users = Arc::new(self.cfg.users.clone());
        let req_send = self.request_sender.clone();

        let fut = async move {
            loop {
                let (stream, addr) = listener.accept().await?;
                let span = info_span!("mixed", src = %addr);
                let _enter = span.enter();
                let http = http.clone();
                let users = users.clone();
                let req_send = req_send.clone();
                tokio::spawn(async move {
                    handle_connection(stream, http, users, req_send)
                        .in_current_span()
                        .await
                        .map_err(|x| error!("failed to handle mixed connection: {}", x))
                });
            }
            #[allow(unreachable_code)]
            SResult::<()>::Ok(())
        };
        tokio::spawn(fut);

        Ok(())
    }
}
