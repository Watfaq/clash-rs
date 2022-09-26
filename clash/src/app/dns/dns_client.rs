use std::{net, sync::Arc, time::Duration};

use async_trait::async_trait;
use trust_dns_client::{
    client, proto::iocompat::AsyncIoTokioAsStd, tcp::TcpClientStream, udp::UdpClientStream,
};

use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::UdpSocket as TokioUdpSocket;
use trust_dns_proto::{
    op,
    xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
    DnsHandle,
};

use crate::Error;

use super::{resolver::ClashResolver, Client};

pub struct DnsClient {
    c: client::AsyncClient,
}

pub struct Opts {
    pub r: Option<Arc<dyn ClashResolver>>,
    pub host: String,
    pub port: u16,
    pub net: String,
    pub iface: Option<net::SocketAddr>,
}

impl DnsClient {
    pub async fn new(opts: Opts) -> anyhow::Result<Self> {
        let ip = if let Some(r) = opts.r {
            if let Some(ip) = r.resolve(&opts.host).await? {
                ip
            } else {
                return Err(Error::InvalidConfig(format!(
                    "can't resolve default DNS: {}",
                    opts.host
                ))
                .into());
            }
        } else {
            opts.host
                .parse::<net::IpAddr>()
                .map_err(|x| Error::DNSError(x.to_string()))?
        };

        if opts.net.starts_with("tcp") {
            let (stream, sender) =
                TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::with_bind_addr_and_timeout(
                    net::SocketAddr::new(ip, opts.port),
                    opts.iface,
                    Duration::from_secs(5),
                );
            let (client, bg) = client::AsyncClient::new(stream, sender, None)
                .await
                .map_err(|x| Error::DNSError(x.to_string()))?;
            tokio::spawn(bg);
            Ok(Self { c: client })
        } else {
            let stream = UdpClientStream::<TokioUdpSocket>::with_bind_addr_and_timeout(
                net::SocketAddr::new(ip, opts.port),
                opts.iface,
                Duration::from_secs(5),
            );
            let (client, bg) = client::AsyncClient::connect(stream)
                .await
                .map_err(|x| Error::DNSError(x.to_string()))?;

            tokio::spawn(bg);
            Ok(Self { c: client })
        }
    }
}

#[async_trait]
impl Client for DnsClient {
    async fn exchange(&mut self, msg: &op::Message) -> Result<op::Message, Error> {
        let mut req = DnsRequest::new(msg.clone(), DnsRequestOptions::default());
        req.set_id(rand::random::<u16>());
        self.c
            .send(req)
            .first_answer()
            .await
            .map(|x| x.into())
            .map_err(|e| Error::DNSError(e.to_string()))
    }
}
