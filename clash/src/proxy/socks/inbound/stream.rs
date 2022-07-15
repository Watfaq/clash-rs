use std::io::{self, ErrorKind};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    proxy::{AnyInboundTransport, AnyStream, InboundStreamHandler, InboundTransport},
    session::{Session, SocksAddr},
};

pub struct Handler;

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle(
        &self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        let mut buf = BytesMut::new();

        buf.resize(2, 0);
        stream.read_exact(&mut buf).await?;

        if buf[0] != 0x05 {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                format!("unkown socks version {}", buf[0]),
            ));
        }

        if buf[1] == 0 {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("unkown socks5 authentication method"),
            ));
        }

        let nmethods = buf[1] as usize;
        buf.resize(nmethods, 0);
        stream.read_exact(&mut buf[..]).await?;
        let supported_method = 0x0; // NO AUTHENTICATION REQUIRED
        if let Some(method_index) = buf.iter().position(|&x| x == supported_method) {
            stream.write_all(&[0x05, method_index as u8]).await?;
        } else {
            stream.write_all(&[0x05, 0xff]).await?; // NO ACCEPTABLE METHODS
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("unsupported socks5 authentication methods"),
            ));
        }

        buf.resize(3, 0);

        stream.read_exact(&mut buf[..]).await?;
        if buf[0] != 0x05 {
            stream.write_all(&[0x05, 0x01]).await?; // general SOCKS server failure
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unknown socks5 version {}", buf[0]),
            ));
        }
        if buf[2] != 0x0 {
            stream.write_all(&[0x05, 0x01]).await?; // general SOCKS server failure
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("socks5 reserved field non-zero"),
            ));
        }
        let cmd = buf[1];
        if cmd != 0x01 && cmd != 0x03 {}

        let destination = SocksAddr::read_from(&mut stream).await?;

        match cmd {
            0x01 => {
                buf.clear();
                buf.put_u8(0x05);
                buf.put_u8(0x0);
                buf.put_u8(0x0);
                let bond_addr = match destination {
                    SocksAddr::Ip(ip) => match ip {
                        std::net::SocketAddr::V4(_) => SocksAddr::any_ipv4(),
                        std::net::SocketAddr::V6(_) => SocksAddr::any_ipv6(),
                    },
                    SocksAddr::Domain(_, _) => SocksAddr::any_ipv4(),
                };
                bond_addr.write_buf(&mut buf);
                stream.write_all(&buf[..]).await?;
                sess.destination = destination;
                Ok(InboundTransport::Stream(stream, sess))
            }

            0x03 => {
                buf.clear();
                buf.put_u8(0x05);
                buf.put_u8(0x0);
                buf.put_u8(0x0);
                let bound_addr = SocksAddr::from(sess.local_addr);
                bound_addr.write_buf(&mut buf);
                stream.write_all(&buf[..]).await?;
                tokio::spawn(async move {
                    let mut buf = [0u8; 1];
                    if let Err(e) = stream.read_exact(&mut buf).await {
                        println!("udp association finished: {}", e);
                    }
                });
                Ok(InboundTransport::Empty)
            }

            _ => {
                stream.write_all(&[0x05, 0x07]).await?; // Command not supported
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("unsupported socks5 cmd {}", cmd),
                ))
            }
        }
    }
}
