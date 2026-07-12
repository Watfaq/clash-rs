use std::{net::ToSocketAddrs, sync::Arc};

use crate::{
    TcpSession, UdpRecv, UdpSend, UdpSession,
    msgs::socks5::{
        CmdReply, PasswordAuthReply, PasswordAuthReq, SOCKS5_AUTH_METHOD_PASSWORD,
        SOCKS5_CMD_TCP_CONNECT, SOCKS5_CMD_UDP_ASSOCIATE, SOCKS5_REPLY_SUCCEEDED, SOCKS5_RESERVE,
        SOCKS5_VERSION,
    },
    socks::UdpSocksWrap,
    utils::socket_opt::{SocketFactory, TcpSocketFactory, UdpSocketFactory},
};
use tokio::{
    io::{AsyncReadExt, copy_bidirectional_with_sizes},
    net::{TcpStream, UdpSocket},
    sync::OnceCell,
};

use async_trait::async_trait;
use tracing::{Instrument, error, info_span};

use crate::{
    Outbound, ProxyRequest,
    config::SocksClientCfg,
    error::SError,
    msgs::socks5::{AuthReply, AuthReq, CmdReq, SOCKS5_AUTH_METHOD_NONE, VarVec},
    msgs::{SDecode, SEncode},
};

#[derive(Clone)]
pub struct SocksClient {
    pub cfg: SocksClientCfg,
    pub(crate) tcp_socket_factory: Arc<dyn SocketFactory>,
}

impl std::fmt::Debug for SocksClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocksClient")
            .field("cfg", &self.cfg)
            .finish()
    }
}

#[async_trait]
impl Outbound for SocksClient {
    async fn handle(&mut self, req: ProxyRequest) -> Result<(), SError> {
        let span = info_span!("socks", server = self.cfg.addr);
        let client = self.clone();
        let fut = async move {
            match req {
                ProxyRequest::Tcp(tcp_session) => client.handle_tcp(tcp_session).await,
                ProxyRequest::Udp(udp_session) => client.handle_udp(udp_session).await,
            }
        };

        tokio::spawn(
            async {
                fut.await
                    .map_err(|x| error!("error due to handle socks request:{}", x))
            }
            .instrument(span),
        );
        Ok(())
    }
}

impl SocksClient {
    pub fn new(cfg: SocksClientCfg) -> Self {
        let tcp_socket_factory = Arc::new(TcpSocketFactory {
            addr: cfg.addr.clone(),
            interface: cfg.socket_opt.bind_interface.clone(),
            fw_mark: cfg.socket_opt.fw_mark,
            protect_path: None,
        });
        Self {
            cfg,
            tcp_socket_factory,
        }
    }
    async fn authenticate(&self, mut tcp: TcpStream) -> Result<TcpStream, SError> {
        let method = if self.cfg.username.is_some() {
            SOCKS5_AUTH_METHOD_PASSWORD
        } else {
            SOCKS5_AUTH_METHOD_NONE
        };
        let auth = AuthReq {
            version: SOCKS5_VERSION,
            methods: VarVec {
                len: 1,
                contents: vec![method],
            },
        };

        auth.encode(&mut tcp).await?;
        let rep = AuthReply::decode(&mut tcp).await?;
        if rep.version != SOCKS5_VERSION {
            return Err(SError::SocksError("version not supported".into()));
        }
        if rep.method != method {
            return Err(SError::SocksError(
                "authenticate method not supported".into(),
            ));
        }
        if let Some(username) = &self.cfg.username {
            let auth = PasswordAuthReq {
                version: 0x01, // This is password auth version not socks version
                username: VarVec {
                    len: username.len() as u8,
                    contents: username.as_bytes().to_vec(),
                },
                password: VarVec {
                    len: self.cfg.password.as_ref().unwrap().len() as u8,
                    contents: self
                        .cfg
                        .password
                        .as_ref()
                        .ok_or(SError::SocksError("password not provided".into()))?
                        .as_bytes()
                        .to_vec(),
                },
            };
            auth.encode(&mut tcp).await?;
            let rep = PasswordAuthReply::decode(&mut tcp).await?;
            if rep.status != SOCKS5_REPLY_SUCCEEDED {
                return Err(SError::SocksError("authenticate failed".into()));
            }
        }
        Ok(tcp)
    }

    async fn handle_tcp(&self, mut tcp_session: TcpSession) -> Result<(), SError> {
        tracing::info!(server = %self.cfg.addr, "connect to socks server");
        let socket = self.tcp_socket_factory.create_socket().await?;
        let std_stream: std::net::TcpStream = socket.into();
        let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
        let addr = self.cfg.addr.to_socket_addrs()?.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "socks server address not found",
            )
        })?;
        let tcp = tokio_socket.connect(addr).await?;
        tcp.set_nodelay(true)?;
        let mut tcp = self.authenticate(tcp).await?;
        let socksreq = CmdReq {
            version: SOCKS5_VERSION,
            cmd: SOCKS5_CMD_TCP_CONNECT,
            rsv: SOCKS5_RESERVE,
            dst: tcp_session.dst,
        };
        socksreq.encode(&mut tcp).await?;
        let _rep = CmdReply::decode(&mut tcp).await?;
        tracing::trace!("socks tcp connection established");
        copy_bidirectional_with_sizes(&mut tcp, &mut tcp_session.stream, 16 * 1024, 16 * 1024)
            .await?;
        Ok(())
    }

    async fn handle_udp(&self, mut udp_session: UdpSession) -> Result<(), SError> {
        tracing::info!("connect to socks server: {}", self.cfg.addr);
        let socket = self.tcp_socket_factory.create_socket().await?;
        let std_stream: std::net::TcpStream = socket.into();
        let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
        let addr = self.cfg.addr.to_socket_addrs()?.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "socks server address not found",
            )
        })?;
        let tcp = tokio_socket.connect(addr).await?;
        tcp.set_nodelay(true)?;

        let mut tcp = self.authenticate(tcp).await?;

        let socksreq = CmdReq {
            version: SOCKS5_VERSION,
            cmd: SOCKS5_CMD_UDP_ASSOCIATE,
            rsv: SOCKS5_RESERVE,
            dst: udp_session.bind_addr.clone(),
        };
        socksreq.encode(&mut tcp).await?;
        let rep = CmdReply::decode(&mut tcp).await?;
        tracing::trace!("socks udp association established");
        let peer_addr = rep
            .bind_addr
            .to_socket_addrs()
            .expect("socks server return a unresolvable address")
            .next()
            .expect("socks server return a unresolvable address");

        let udp_socket_factory = UdpSocketFactory {
            addr: peer_addr.to_string(),
            interface: self.cfg.socket_opt.bind_interface.clone(),
            fw_mark: self.cfg.socket_opt.fw_mark,
            protect_path: None,
            try_dual_stack: false,
        };
        let socket = udp_socket_factory.create_socket().await?;
        socket.set_nonblocking(true)?;
        let std_socket: std::net::UdpSocket = socket.into();
        let socket = UdpSocket::from_std(std_socket)?;
        socket.connect(peer_addr).await?;
        let mut upstream = UdpSocksWrap(Arc::new(socket), OnceCell::new_with(Some(peer_addr)));

        let upstream_clone = upstream.clone();
        let fut1 = async move {
            loop {
                let (buf, dst) = upstream.recv_from().await?;

                let _ = udp_session.send.send_to(buf, dst).await?;
            }
            #[allow(unreachable_code)]
            (Ok(()) as Result<(), SError>)
        };
        let fut2 = async move {
            loop {
                let (buf, dst) = udp_session.recv.recv_from().await?;

                let _ = upstream_clone.send_to(buf, dst).await?;
            }
            #[allow(unreachable_code)]
            (Ok(()) as Result<(), SError>)
        };
        // control stream, in socks5 inbound, end of control stream
        // means end of udp association.
        let fut3 = async {
            if udp_session.stream.is_none() {
                return Ok(());
            }
            let mut buf = [0u8];
            udp_session
                .stream
                .unwrap()
                .read_exact(&mut buf)
                .await
                .map_err(|x| SError::UDPSessionClosed(x.to_string()))?;
            error!("unexpected data received from socks control stream");
            Err(SError::UDPSessionClosed(
                "unexpected data received from socks control stream".into(),
            )) as Result<(), SError>
        };
        // We can use spawn, but it requirs communication to shutdown the other
        // Flatten spawn handle using try_join! doesn't work. Don't know why
        tokio::try_join!(fut1, fut2, fut3)?;

        Ok(())
    }
}
