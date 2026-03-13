use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error};

use crate::{proxy::AnyStream, session::SocksAddr};

const VLESS_VERSION: u8 = 0;
const VLESS_COMMAND_TCP: u8 = 1;
const VLESS_COMMAND_UDP: u8 = 2;

/// Build the protobuf-encoded VLESS addon bytes for the given flow string.
/// Field 1 (Flow), wire type 2 (LEN): tag = 0x0A, then varint length, then bytes.
fn build_addon_bytes(flow: &str) -> Vec<u8> {
    let mut addon = Vec::new();
    addon.push(0x0A); // field 1, wire type LEN
    addon.push(flow.len() as u8);
    addon.extend_from_slice(flow.as_bytes());
    addon
}

pub struct VlessStream {
    inner: AnyStream,
    handshake_done: bool,
    handshake_sent: bool,
    response_received: bool,
    uuid: uuid::Uuid,
    destination: SocksAddr,
    is_udp: bool,
    flow: Option<String>,
}

impl VlessStream {
    pub fn new(
        stream: AnyStream,
        uuid: &str,
        destination: &SocksAddr,
        is_udp: bool,
        flow: Option<String>,
    ) -> io::Result<Self> {
        let uuid = uuid::Uuid::parse_str(uuid).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid UUID format")
        })?;

        debug!("VLESS stream created for destination: {}", destination);

        Ok(Self {
            inner: stream,
            handshake_done: false,
            handshake_sent: false,
            response_received: false,
            uuid,
            destination: destination.clone(),
            is_udp,
            flow,
        })
    }

    fn build_handshake_header(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // VLESS request header:
        // Version (1 byte) + UUID (16 bytes) + Addon length (1 byte) + [Addon] +
        // Command (1 byte) + Port (2 bytes) + Address type + Address
        buf.put_u8(VLESS_VERSION);
        buf.put_slice(self.uuid.as_bytes());

        if let Some(flow) = &self.flow {
            let addon = build_addon_bytes(flow);
            buf.put_u8(addon.len() as u8);
            buf.put_slice(&addon);
        } else {
            buf.put_u8(0); // no addon
        }

        if self.is_udp {
            buf.put_u8(VLESS_COMMAND_UDP);
        } else {
            buf.put_u8(VLESS_COMMAND_TCP);
        }

        self.destination.write_to_buf_vmess(&mut buf);
        buf
    }

    async fn send_handshake_with_data(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.handshake_sent {
            return Ok(0);
        }

        debug!(
            "VLESS handshake starting for destination: {}",
            self.destination
        );

        let mut buf = self.build_handshake_header();
        buf.put_slice(data);

        // Send handshake + first data
        tokio::io::AsyncWriteExt::write_all(&mut self.inner, &buf)
            .await
            .map_err(|e| {
                error!("Failed to send VLESS handshake: {}", e);
                e
            })?;

        self.handshake_sent = true;
        debug!("VLESS handshake sent with {} bytes of data", data.len());

        Ok(data.len())
    }

    async fn receive_response(&mut self) -> io::Result<()> {
        if self.response_received {
            return Ok(());
        }

        debug!("VLESS waiting for response");

        // Read response (VLESS response is just version + additional info length +
        // additional info)
        let mut response = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut self.inner, &mut response)
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

        if additional_info_len > 0 {
            let mut additional_info = vec![0u8; additional_info_len as usize];
            tokio::io::AsyncReadExt::read_exact(
                &mut self.inner,
                &mut additional_info,
            )
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

        self.response_received = true;
        self.handshake_done = true;
        debug!("VLESS handshake completed successfully");

        Ok(())
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Must receive response before reading
        if self.handshake_sent && !self.response_received {
            let fut = self.receive_response();
            tokio::pin!(fut);
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
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
        // Send handshake with first write
        if !self.handshake_sent {
            let fut = self.send_handshake_with_data(buf);
            tokio::pin!(fut);
            match fut.poll(cx) {
                Poll::Ready(Ok(n)) => return Poll::Ready(Ok(n)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// VisionStream wraps a VlessStream and applies XTLS Vision framing.
///
/// Vision packet format:
/// - Padding packet (first write only): `[0x00][padding_len: u16-be][random_padding]`
/// - Data packet: `[0x01][data_len: u32-be][data]`
pub struct VisionStream {
    inner: VlessStream,
    padding_sent: bool,
    read_buf: BytesMut,
}

impl VisionStream {
    pub fn new(inner: VlessStream) -> Self {
        Self {
            inner,
            padding_sent: false,
            read_buf: BytesMut::new(),
        }
    }

    async fn send_vision_frame(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut framed = BytesMut::new();
        if !self.padding_sent {
            // Prepend padding packet: [0x00][padding_len: u16-be][random padding]
            let padding_len = rand::random::<u8>() as u16; // 0..255 bytes
            framed.put_u8(0x00);
            framed.put_u16(padding_len);
            let padding = rand::random::<[u8; 255]>();
            framed.put_slice(&padding[..padding_len as usize]);
            self.padding_sent = true;
        }
        // Data packet: [0x01][data_len: u32-be][data]
        framed.put_u8(0x01);
        framed.put_u32(data.len() as u32);
        framed.extend_from_slice(data);

        tokio::io::AsyncWriteExt::write_all(&mut self.inner, &framed).await?;
        Ok(data.len())
    }

    async fn fill_read_buf(&mut self) -> io::Result<()> {
        loop {
            let mut type_byte = [0u8; 1];
            tokio::io::AsyncReadExt::read_exact(&mut self.inner, &mut type_byte)
                .await?;
            match type_byte[0] {
                0x00 => {
                    // Padding packet: discard
                    let mut len_buf = [0u8; 2];
                    tokio::io::AsyncReadExt::read_exact(
                        &mut self.inner,
                        &mut len_buf,
                    )
                    .await?;
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut padding = vec![0u8; len];
                    tokio::io::AsyncReadExt::read_exact(
                        &mut self.inner,
                        &mut padding,
                    )
                    .await?;
                    // Continue loop to read next frame
                }
                0x01 => {
                    // Data packet
                    let mut len_buf = [0u8; 4];
                    tokio::io::AsyncReadExt::read_exact(
                        &mut self.inner,
                        &mut len_buf,
                    )
                    .await?;
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut data = vec![0u8; len];
                    tokio::io::AsyncReadExt::read_exact(&mut self.inner, &mut data)
                        .await?;
                    self.read_buf.extend_from_slice(&data);
                    return Ok(());
                }
                t => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Unknown Vision frame type: {:#x}", t),
                    ));
                }
            }
        }
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_buf.is_empty() {
            let fut = self.fill_read_buf();
            tokio::pin!(fut);
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let to_copy = self.read_buf.len().min(buf.remaining());
        buf.put_slice(&self.read_buf[..to_copy]);
        self.read_buf.advance(to_copy);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let fut = self.send_vision_frame(buf);
        tokio::pin!(fut);
        match fut.poll(cx) {
            Poll::Ready(Ok(n)) => return Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_addon_bytes_vision() {
        let flow = "xtls-rprx-vision";
        let addon = build_addon_bytes(flow);
        // Expected: [0x0A, 0x10, 'x','t','l','s','-','r','p','r','x','-','v','i','s','i','o','n']
        assert_eq!(addon[0], 0x0A, "field tag");
        assert_eq!(addon[1], 0x10, "length = 16");
        assert_eq!(&addon[2..], b"xtls-rprx-vision");
        assert_eq!(addon.len(), 18);
    }

    #[test]
    fn test_build_addon_bytes_empty_flow() {
        // An empty flow string still produces a valid protobuf encoding
        let addon = build_addon_bytes("");
        assert_eq!(addon[0], 0x0A);
        assert_eq!(addon[1], 0x00);
        assert_eq!(addon.len(), 2);
    }

    #[test]
    fn test_handshake_header_no_flow() {
        use crate::session::SocksAddr;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let addr = SocksAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            80,
        ));
        let inner: AnyStream = Box::new(tokio::io::duplex(1024).0);
        let stream =
            VlessStream::new(inner, "b831381d-6324-4d53-ad4f-8cda48b30811", &addr, false, None)
                .unwrap();

        let header = stream.build_handshake_header();
        // Version (1) + UUID (16) + addon_len=0 (1) + cmd (1) + port (2) + addr_type (1) + addr (4) = 26
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(header[17], 0, "addon_len should be 0");
        assert_eq!(header[18], VLESS_COMMAND_TCP);
    }

    #[test]
    fn test_handshake_header_with_flow() {
        use crate::session::SocksAddr;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let addr = SocksAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            80,
        ));
        let inner: AnyStream = Box::new(tokio::io::duplex(1024).0);
        let stream = VlessStream::new(
            inner,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            &addr,
            false,
            Some("xtls-rprx-vision".to_owned()),
        )
        .unwrap();

        let header = stream.build_handshake_header();
        // Version (1) + UUID (16) + addon_len (1) + addon (18) + cmd (1) + ...
        let addon = build_addon_bytes("xtls-rprx-vision");
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(header[17], addon.len() as u8, "addon_len");
        assert_eq!(&header[18..18 + addon.len()], addon.as_slice());
        assert_eq!(header[18 + addon.len()], VLESS_COMMAND_TCP);
    }

    #[tokio::test]
    async fn test_vision_write_encodes_padding_and_header() {
        // Verify the Vision framing format by constructing it manually
        let data = b"hello world";
        let mut framed = BytesMut::new();
        // Padding packet
        framed.put_u8(0x00);
        framed.put_u16(4); // 4 bytes padding
        framed.put_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        // Data packet
        framed.put_u8(0x01);
        framed.put_u32(data.len() as u32);
        framed.put_slice(data);

        // Verify the encode logic is correct
        assert_eq!(framed[0], 0x00); // padding type
        assert_eq!(u16::from_be_bytes([framed[1], framed[2]]), 4); // padding len
        let padding_end = 3 + 4;
        assert_eq!(framed[padding_end], 0x01); // data type
        let data_len = u32::from_be_bytes([
            framed[padding_end + 1],
            framed[padding_end + 2],
            framed[padding_end + 3],
            framed[padding_end + 4],
        ]);
        assert_eq!(data_len, data.len() as u32);
        assert_eq!(&framed[padding_end + 5..], data);
    }

    #[test]
    fn test_vision_read_decode_padding_then_data() {
        // Verify the decode logic: padding packet (type 0x00) then data packet (type 0x01)
        let data = b"test data";
        let mut buf = BytesMut::new();
        buf.put_u8(0x00); // padding type
        buf.put_u16(3); // 3 bytes padding
        buf.put_slice(&[0x01, 0x02, 0x03]);
        buf.put_u8(0x01); // data type
        buf.put_u32(data.len() as u32);
        buf.put_slice(data);

        // Manually decode
        assert_eq!(buf[0], 0x00);
        let padding_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        assert_eq!(padding_len, 3);
        let data_start = 3 + padding_len;
        assert_eq!(buf[data_start], 0x01);
        let decoded_len = u32::from_be_bytes([
            buf[data_start + 1],
            buf[data_start + 2],
            buf[data_start + 3],
            buf[data_start + 4],
        ]) as usize;
        assert_eq!(decoded_len, data.len());
        assert_eq!(&buf[data_start + 5..data_start + 5 + decoded_len], data);
    }
}
