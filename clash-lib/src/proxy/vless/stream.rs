use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error};

use crate::{proxy::AnyStream, session::SocksAddr};

const VLESS_VERSION: u8 = 0;
const VLESS_COMMAND_TCP: u8 = 1;
const VLESS_COMMAND_UDP: u8 = 2;

const MAX_ADDITIONAL_INFO_LEN: u8 = 255;

pub struct VlessStream {
    inner: AnyStream,
    handshake_done: bool,
}

impl VlessStream {
    pub async fn new(
        mut stream: AnyStream,
        uuid: &str,
        destination: &SocksAddr,
        is_udp: bool,
    ) -> io::Result<Self> {
        let uuid = uuid::Uuid::parse_str(uuid).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid UUID format")
        })?;

        debug!("VLESS handshake starting for destination: {}", destination);

        let mut buf = BytesMut::new();

        // VLESS request header:
        // Version (1 byte) + UUID (16 bytes) + Additional info length (1 byte)
        // + Command (1 byte) + Port (2 bytes) + Address type + Address + Additional
        //   info

        buf.put_u8(VLESS_VERSION);
        buf.put_slice(uuid.as_bytes());
        buf.put_u8(0); // Additional info length (0 for simplicity)

        if is_udp {
            buf.put_u8(VLESS_COMMAND_UDP);
        } else {
            buf.put_u8(VLESS_COMMAND_TCP);
        }

        // Encode destination address
        match destination {
            SocksAddr::Ip(addr) => {
                buf.put_u16(addr.port());
                match addr.ip() {
                    std::net::IpAddr::V4(ip) => {
                        buf.put_u8(1); // IPv4
                        buf.put_slice(&ip.octets());
                    }
                    std::net::IpAddr::V6(ip) => {
                        buf.put_u8(3); // IPv6
                        buf.put_slice(&ip.octets());
                    }
                }
            }
            SocksAddr::Domain(domain, port) => {
                buf.put_u16(*port);
                buf.put_u8(2); // Domain
                if domain.len() > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "domain name too long",
                    ));
                }
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
            }
        }

        // Send handshake
        tokio::io::AsyncWriteExt::write_all(&mut stream, &buf)
            .await
            .map_err(|e| {
                error!("Failed to send VLESS handshake: {}", e);
                e
            })?;

        debug!("VLESS handshake sent, waiting for response");

        // Read response (VLESS response is just version + additional info length +
        // additional info)
        let mut response = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut response)
            .await
            .map_err(|e| {
                error!("Failed to read VLESS response: {}", e);
                e
            })?;

        if response[0] != VLESS_VERSION {
            error!("Invalid VLESS response version: {}", response[0]);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid VLESS response version: {}", response[0]),
            ));
        }

        let additional_info_len = response[1];
        if additional_info_len > MAX_ADDITIONAL_INFO_LEN {
            error!("VLESS additional info too long: {}", additional_info_len);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS additional info too long",
            ));
        }

        if additional_info_len > 0 {
            let mut additional_info = vec![0u8; additional_info_len as usize];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut additional_info)
                .await
                .map_err(|e| {
                    error!("Failed to read VLESS additional info: {}", e);
                    e
                })?;
            debug!(
                "VLESS additional info received: {} bytes",
                additional_info_len
            );
        }

        debug!("VLESS handshake completed successfully");

        Ok(Self {
            inner: stream,
            handshake_done: true,
        })
    }

    fn validate_state(&self) -> io::Result<()> {
        if !self.handshake_done {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS handshake not completed",
            ));
        }
        Ok(())
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(e) = self.validate_state() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if let Err(e) = self.validate_state() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if let Err(e) = self.validate_state() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if let Err(e) = self.validate_state() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
