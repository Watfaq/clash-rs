use std::{
    collections::BTreeMap,
    io,
    ops::{Deref, DerefMut},
};

use async_trait::async_trait;
use futures::{AsyncRead, channel::mpsc::Sender};
use hyper_util::server::conn;
use shadowquic::{
    AnyTcp, Outbound, config,
    msgs::socks5::SocksAddr as SQAddr,
    shadowquic::{
        SQConn,
        outbound::{self as SQ, ShadowQuicClient},
    },
};
use tokio::sync::{OnceCell, RwLock};

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
        net::get_outbound_interface,
    },
    session::{Session, SocksAddr},
};

use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    utils::new_udp_socket,
};
use crate::app::dispatcher::ChainedStream;
use std::fmt::Debug;

mod compat;
pub type HandlerOptions = config::ShadowQuicClientCfg;

pub struct Handler {
    opts: HandlerOptions,
    ep: OnceCell<ShadowQuicClient>, /* Must be created after session since server
                                     * addr needs be resolved */
    conn: RwLock<Option<SQConn>>,
    udp_conn: RwLock<BTreeMap<SocksAddr, ()>>,
}
impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler").field("opts", &self.opts).finish()
    }
}
impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        let ep = ShadowQuicClient::new(opts.clone());
        Self {
            opts,
            ep: Default::default(),
            conn: Default::default(),
            udp_conn: Default::default(),
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
                let iter: Vec<&str> = self.opts.addr.split(":").collect();
                let host = iter[0].to_string();
                tracing::info!("resolving host:{}", host);
                let addr = resolver
                    .resolve(&host, false)
                    .await
                    .map_err(|x| {
                        io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            format!(
                                "failed to resolve shadowquic domain name:{:?}",
                                x
                            ),
                        )
                    })?
                    .ok_or(io::ErrorKind::AddrNotAvailable)?;
                tracing::info!("host resolved:{}", addr);
                let socket = {
                    let iface = get_outbound_interface();
                    new_udp_socket(
                        None,
                        iface.map(|x| x.name.as_str().into()),
                        #[cfg(target_os = "linux")]
                        None,
                    )
                    .await?
                };
                let port = iter.get(1).unwrap_or(&"443");
                let mut addr = addr.to_string();
                addr.push_str(":");
                addr.push_str(port);
                let mut ep = ShadowQuicClient::new_with_socket(
                    self.opts.clone(),
                    socket.into_std()?,
                );
                ep.dst_addr = addr;
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
        tracing::info!("endpoint opened");
        if let Some(x) = &*self.conn.read().await {
            if x.close_reason().is_none() {
                return Ok(x.clone());
            }
        }
        let mut conn = self.conn.write().await;
        tracing::info!("open connection");
        let newconn = ep.get_conn().await.map_err(|x| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("can't open shadowquic conection due to:{}", x.to_string()),
            )
        })?;
        conn.replace(newconn.clone());
        tracing::info!("connection opened");
        return Ok(newconn);
    }
}

#[async_trait]
impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    /// The name of the outbound handler
    fn name(&self) -> &str {
        "shadowquic"
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
        tracing::info!("conect shadowquic");
        let conn = self.prepare_conn(sess, resolver).await?;
        let conn =
            SQ::connect_tcp(&conn, to_sq_socks_addr(sess.destination.clone()))
                .await
                .map_err(|x| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "can't open shadowquic stream due to:{}",
                            x.to_string()
                        ),
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
        todo!()
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
