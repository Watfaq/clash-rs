use std::io;

use async_trait::async_trait;

use crate::{
    proxy::{AnyStream, OutboundConnect, OutboundDatagram, OutboundStreamHandler},
    session::{Network, Session, SocksAddr},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        mut stream: AnyStream,
    ) -> io::Result<AnyStream> {
        match &sess.destination {
            SocksAddr::Ip(ip) => {
                async_socks5::connect(&mut stream, ip.to_owned(), None)
                    .await
                    .map_err(|x| io::Error::new(io::ErrorKind::Other, x))?;
            }
            SocksAddr::Domain(domain, port) => {
                async_socks5::connect(&mut stream, (domain.to_owned(), port.to_owned()), None)
                    .await
                    .map_err(|x| io::Error::new(io::ErrorKind::Other, x))?;
            }
        }
        Ok(stream)
    }
}
