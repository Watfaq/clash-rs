use std::{net, rc::Rc, sync::Arc, time::Duration};

use async_trait::async_trait;
use trust_dns_client::{
    client::{AsyncClient, ClientConnection},
    proto::iocompat::AsyncIoTokioAsStd,
    tcp::{TcpClientConnection, TcpClientStream},
    udp::{UdpClientConnection, UdpClientStream},
};

use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::{net::TcpStream as TokioTcpStream, runtime::Runtime};
use trust_dns_proto::{
    xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
    DnsHandle,
};

use crate::Error;

use super::{resolver::ClashResolver, Client};

pub struct DnsClient {
    c: trust_dns_client::client::AsyncClient,
    runtime: tokio::runtime::Runtime,
}

pub struct Opts {
    r: Option<Arc<dyn ClashResolver>>,
    host: String,
    port: u16,
    net: String,
    iface: Option<net::SocketAddr>,
}

impl DnsClient {
    pub async fn new(opts: Opts) -> Result<Self, Error> {
        let ip = if let Some(r) = opts.r {
            if let Some(ip) = r.resolve(&opts.host).await? {
                ip
            } else {
                return Err(Error::InvalidConfig(format!(
                    "can't resolve default DNS: {}",
                    opts.host
                )));
            }
        } else {
            opts.host
                .parse::<net::IpAddr>()
                .map_err(|x| Error::DNSError(x.to_string()))?
        };
        let rt = Runtime::new()?;

        if opts.net.starts_with("tcp") {
            let (stream, sender) =
                TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::with_bind_addr_and_timeout(
                    net::SocketAddr::new(ip, opts.port),
                    opts.iface,
                    Duration::from_secs(5),
                );
            let (client, bg) = AsyncClient::new(stream, sender, None)
                .await
                .map_err(|x| Error::DNSError(x.to_string()))?;
            trust_dns_proto::spawn_bg(&rt, bg);
            Ok(Self {
                c: client,
                runtime: rt,
            })
        } else {
            let stream = UdpClientStream::<TokioUdpSocket>::with_bind_addr_and_timeout(
                net::SocketAddr::new(ip, opts.port),
                opts.iface,
                Duration::from_secs(5),
            );
            let (client, bg) = AsyncClient::connect(stream)
                .await
                .map_err(|x| Error::DNSError(x.to_string()))?;
            trust_dns_proto::spawn_bg(&rt, bg);

            Ok(Self {
                c: client,
                runtime: rt,
            })
        }
    }
}

#[async_trait]
impl Client for DnsClient {
    async fn exchange(
        &self,
        msg: trust_dns_client::op::Message,
    ) -> Result<trust_dns_client::op::Message, Error> {
        let mut req = DnsRequest::new(msg, DnsRequestOptions::default());
        req.set_id(rand::random::<u16>());
        self.c
            .send(req)
            .first_answer()
            .await
            .map(|x| *x)
            .map_err(|e| Error::DNSError(e.to_string()))
    }
}
