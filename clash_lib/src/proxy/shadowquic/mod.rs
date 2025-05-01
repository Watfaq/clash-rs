use std::{io, net::SocketAddr, str::FromStr};

use async_trait::async_trait;
use compat::UdpSessionWrapper;
use shadowquic::{
    config,
    msgs::socks5::SocksAddr as SQAddr,
    shadowquic::{
        SQConn,
        outbound::{self as SQ, ShadowQuicClient},
    },
};
use tokio::sync::{OnceCell, RwLock};
use tokio_util::sync::PollSender;
mod compat;
use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    session::{Session, SocksAddr},
};

use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    utils::new_udp_socket,
};
use crate::app::dispatcher::ChainedStream;
use std::fmt::Debug;

pub type HandlerOptions = config::ShadowQuicClientCfg;

pub struct Handler {
    name: String,
    opts: HandlerOptions,
    ep: OnceCell<ShadowQuicClient>, /* Must be created after session since server
                                     * addr needs to be resolved */
    conn: RwLock<Option<SQConn>>,
}
impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler").field("opts", &self.opts).finish()
    }
}
impl Handler {
    pub fn new(name: String, opts: HandlerOptions) -> Self {
        Self {
            name,
            opts,
            ep: Default::default(),
            conn: Default::default(),
        }
    }

    /// Resolve quic server DNS with clash DNS resolver
    pub async fn prepare_endpoint(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<&ShadowQuicClient> {
        self.ep
            .get_or_try_init(|| async {
                let addr = self.opts.addr.clone();
                let sock_addr = SocksAddr::from_str(&format!("{addr}:443"))
                    .or(SocksAddr::from_str(&addr))
                    .map_err(new_io_error)?;
                tracing::info!("resolving host:{:?}", sock_addr);
                let addr = match sock_addr {
                    SocksAddr::Domain(host, port) => {
                        let addr = resolver
                            .resolve(&host, false)
                            .await
                            .map_err(|x| {
                                io::Error::new(
                                    io::ErrorKind::AddrNotAvailable,
                                    format!(
                                        "failed to resolve shadowquic domain \
                                         name:{:?}",
                                        x
                                    ),
                                )
                            })?
                            .ok_or(io::ErrorKind::AddrNotAvailable)?;
                        SocketAddr::new(addr, port)
                    }
                    SocksAddr::Ip(socket_addr) => socket_addr,
                };
                let socket = {
                    new_udp_socket(
                        None,
                        sess.iface.clone(),
                        #[cfg(target_os = "linux")]
                        sess.so_mark,
                    )
                    .await?
                };
                let mut ep = ShadowQuicClient::new_with_socket(
                    self.opts.clone(),
                    socket.into_std()?,
                );
                ep.dst_addr = addr.to_string();
                Ok(ep) as io::Result<ShadowQuicClient>
            })
            .await
    }

    async fn prepare_conn(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<SQConn> {
        let ep = self.prepare_endpoint(sess, resolver).await?;
        if let Some(x) = &*self.conn.read().await {
            if x.close_reason().is_none() {
                return Ok(x.clone());
            }
        }
        let mut conn = self.conn.write().await;
        let newconn = ep.get_conn().await.map_err(|x| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("can't open shadowquic conection due to:{}", x),
            )
        })?;
        conn.replace(newconn.clone());
        Ok(newconn)
    }
}

#[async_trait]
impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    /// The name of the outbound handler
    fn name(&self) -> &str {
        &self.name
    }

    /// The protocol of the outbound handler
    /// only contains Type information, do not rely on the underlying value
    fn proto(&self) -> OutboundType {
        OutboundType::ShadowQuic
    }

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool {
        true
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let conn = self.prepare_conn(sess, resolver).await?;
        let conn =
            SQ::connect_tcp(&conn, to_sq_socks_addr(sess.destination.clone()))
                .await
                .map_err(|x| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("can't open shadowquic stream due to:{}", x),
                    )
                })?;
        let s = ChainedStreamWrapper::new(conn);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let conn = self.prepare_conn(sess, resolver).await?;
        // clash-rs didn't expose udp associate address, so set to unspecified
        // address
        let addr = if sess.source.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = SQ::associate_udp(
            &conn,
            addr.parse::<SocketAddr>().unwrap().into(),
            self.opts.over_stream,
        )
        .await
        .map_err(|x| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("can't open shadowquic stream due to:{}", x),
            )
        })?;
        let chain = ChainedDatagramWrapper::new(UdpSessionWrapper {
            s: PollSender::new(socket.0),
            r: socket.1,
            src_addr: sess.source.into(),
        });
        chain.append_to_chain(self.name()).await;
        Ok(Box::new(chain))
    }

    /// relay related
    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }
}

fn to_sq_socks_addr(x: SocksAddr) -> SQAddr {
    match x {
        SocksAddr::Ip(socket_addr) => SQAddr::from(socket_addr),
        SocksAddr::Domain(host, port) => SQAddr::from_domain(host, port),
    }
}
fn to_clash_socks_addr(x: SQAddr) -> SocksAddr {
    match x.addr {
        shadowquic::msgs::socks5::AddrOrDomain::V4(ip) => {
            SocksAddr::Ip(SocketAddr::new(ip.into(), x.port))
        }
        shadowquic::msgs::socks5::AddrOrDomain::V6(ip) => {
            SocksAddr::Ip(SocketAddr::new(ip.into(), x.port))
        }
        shadowquic::msgs::socks5::AddrOrDomain::Domain(domain) => {
            SocksAddr::Domain(String::from_utf8(domain.contents).unwrap(), x.port)
        }
    }
}
