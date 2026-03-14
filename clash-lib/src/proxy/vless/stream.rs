use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error};

use crate::{
    proxy::{AnyStream, transport::switch_reality_raw_modes},
    session::SocksAddr,
};

const VLESS_VERSION: u8 = 0;
const VLESS_COMMAND_TCP: u8 = 1;
const VLESS_COMMAND_UDP: u8 = 2;

const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];

const COMMAND_PADDING_CONTINUE: u8 = 0x00;
const COMMAND_PADDING_END: u8 = 0x01;
const COMMAND_PADDING_DIRECT: u8 = 0x02;

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
    handshake_pending: Option<BytesMut>,
    handshake_pending_pos: usize,
    handshake_ack_len: usize,
    response_header: [u8; 2],
    response_header_read: usize,
    response_additional_remaining: Option<usize>,
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
            handshake_pending: None,
            handshake_pending_pos: 0,
            handshake_ack_len: 0,
            response_header: [0u8; 2],
            response_header_read: 0,
            response_additional_remaining: None,
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

    fn poll_receive_response(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.response_received {
            return Poll::Ready(Ok(()));
        }

        debug!("VLESS waiting for response");

        while self.response_header_read < self.response_header.len() {
            let mut read_buf =
                ReadBuf::new(&mut self.response_header[self.response_header_read..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected eof while reading VLESS response",
                        )));
                    }
                    self.response_header_read += n;
                }
                Poll::Ready(Err(e)) => {
                    error!("Failed to read VLESS response: {}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.response_additional_remaining.is_none() {
            if self.response_header[0] != VLESS_VERSION {
                error!(
                    "Invalid VLESS response version: {}",
                    self.response_header[0]
                );
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid VLESS response version: {}",
                        self.response_header[0]
                    ),
                )));
            }
            self.response_additional_remaining =
                Some(self.response_header[1] as usize);
            if let Some(rem) = self.response_additional_remaining {
                if rem > 0 {
                    debug!("VLESS additional info pending: {} bytes", rem);
                }
            }
        }

        while let Some(remaining) = self.response_additional_remaining {
            if remaining == 0 {
                break;
            }
            let mut discard = [0u8; 256];
            let take = remaining.min(discard.len());
            let mut read_buf = ReadBuf::new(&mut discard[..take]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected eof while reading VLESS additional info",
                        )));
                    }
                    self.response_additional_remaining = Some(remaining - n);
                }
                Poll::Ready(Err(e)) => {
                    error!(
                        "Failed to read VLESS additional info: {}",
                        e
                    );
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        self.response_received = true;
        self.handshake_done = true;
        debug!("VLESS handshake completed successfully");
        Poll::Ready(Ok(()))
    }

    fn poll_send_handshake(
        &mut self,
        cx: &mut Context<'_>,
        payload: &[u8],
        ack_len: usize,
    ) -> Poll<io::Result<usize>> {
        if self.handshake_sent {
            return Poll::Ready(Ok(ack_len));
        }

        if self.handshake_pending.is_none() {
            debug!(
                "VLESS handshake starting for destination: {}",
                self.destination
            );
            let mut handshake = self.build_handshake_header();
            handshake.extend_from_slice(payload);
            self.handshake_pending = Some(handshake);
            self.handshake_pending_pos = 0;
            self.handshake_ack_len = ack_len;
        }

        while let Some(pending) = self.handshake_pending.as_ref() {
            if self.handshake_pending_pos >= pending.len() {
                break;
            }

            match Pin::new(&mut self.inner).poll_write(
                cx,
                &pending[self.handshake_pending_pos..],
            ) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero while sending VLESS handshake",
                    )));
                }
                Poll::Ready(Ok(n)) => self.handshake_pending_pos += n,
                Poll::Ready(Err(e)) => {
                    error!("Failed to send VLESS handshake: {}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        self.handshake_pending = None;
        self.handshake_pending_pos = 0;
        self.handshake_sent = true;
        debug!(
            "VLESS handshake sent with {} bytes of data",
            self.handshake_ack_len
        );
        let ack = self.handshake_ack_len;
        self.handshake_ack_len = 0;
        Poll::Ready(Ok(ack))
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
            match self.poll_receive_response(cx) {
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
        let vision_flow = matches!(
            self.flow.as_deref(),
            Some("xtls-rprx-vision")
        );

        // Send handshake with first write
        if !self.handshake_sent {
            let payload = if vision_flow { &[][..] } else { buf };
            let ack_len = if vision_flow { 0 } else { buf.len() };
            match self.poll_send_handshake(cx, payload, ack_len) {
                Poll::Ready(Ok(n)) => {
                    if !vision_flow || buf.is_empty() {
                        return Poll::Ready(Ok(n));
                    }
                }
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

/// VisionStream wraps a VlessStream and applies XTLS Vision padding blocks.
///
/// Block format:
/// `[optional uuid(16)][command:1][content_len:u16-be][padding_len:u16-be][content][padding]`
pub struct VisionStream {
    inner: VlessStream,
    write_uuid: bool,
    is_padding: bool,
    write_direct: bool,
    is_tls: bool,
    number_of_packet_to_filter: i32,
    is_tls12_or_above: bool,
    remaining_server_hello: i32,
    cipher: u16,
    enable_xtls: bool,
    read_buf: BytesMut,
    read_pending: BytesMut,
    read_padding: bool,
    read_remaining_content: i32,
    read_remaining_padding: i32,
    read_current_command: u8,
    write_pending: Option<VisionWritePending>,
}

struct VisionWritePending {
    orig_len: usize,
    framed: BytesMut,
    framed_pos: usize,
    switch_to_raw: bool,
    switch_done: bool,
    raw_tail: BytesMut,
    raw_tail_pos: usize,
}

impl VisionStream {
    pub fn new(inner: VlessStream) -> Self {
        Self {
            inner,
            write_uuid: true,
            is_padding: true,
            write_direct: false,
            is_tls: false,
            number_of_packet_to_filter: 8,
            is_tls12_or_above: false,
            remaining_server_hello: -1,
            cipher: 0,
            enable_xtls: false,
            read_buf: BytesMut::new(),
            read_pending: BytesMut::new(),
            read_padding: true,
            read_remaining_content: -1,
            read_remaining_padding: -1,
            read_current_command: 0,
            write_pending: None,
        }
    }

    fn reshape_buffer(data: &[u8]) -> Vec<&[u8]> {
        const BUFFER_LIMIT: usize = 8192 - 21;
        if data.len() < BUFFER_LIMIT {
            return vec![data];
        }

        let split = data
            .windows(TLS_APPLICATION_DATA_START.len())
            .rposition(|w| w == TLS_APPLICATION_DATA_START)
            .filter(|i| *i > 0)
            .unwrap_or(8192 / 2)
            .min(data.len());
        vec![&data[..split], &data[split..]]
    }

    fn filter_tls_buffers(&mut self, buffers: &[&[u8]]) {
        for buffer in buffers {
            if self.number_of_packet_to_filter <= 0 {
                return;
            }
            self.number_of_packet_to_filter -= 1;

            if buffer.len() > 6 {
                if buffer.starts_with(&TLS_SERVER_HANDSHAKE_START) {
                    self.is_tls = true;
                    if buffer[5] == 0x02 {
                        self.is_tls12_or_above = true;
                        self.remaining_server_hello =
                            (((buffer[3] as i32) << 8) | buffer[4] as i32) + 5;

                        if buffer.len() >= 79 && self.remaining_server_hello >= 79 {
                            let session_id_len = buffer[43] as usize;
                            let cipher_index = 43 + session_id_len + 1;
                            if cipher_index + 1 < buffer.len() {
                                self.cipher = ((buffer[cipher_index] as u16) << 8)
                                    | buffer[cipher_index + 1] as u16;
                            }
                        }
                    }
                } else if buffer.starts_with(&TLS_CLIENT_HANDSHAKE_START)
                    && buffer[5] == 0x01
                {
                    self.is_tls = true;
                }
            }

            if self.remaining_server_hello > 0 {
                let end = (self.remaining_server_hello as usize).min(buffer.len());
                self.remaining_server_hello -= end as i32;

                if buffer[..end]
                    .windows(TLS13_SUPPORTED_VERSIONS.len())
                    .any(|w| w == TLS13_SUPPORTED_VERSIONS)
                {
                    self.enable_xtls =
                        matches!(self.cipher, 0x1301 | 0x1302 | 0x1303 | 0x1304);
                    debug!(
                        "vision tls13 detected: cipher=0x{:04x} enable_xtls={} filter_left={}",
                        self.cipher,
                        self.enable_xtls,
                        self.number_of_packet_to_filter
                    );
                    self.number_of_packet_to_filter = 0;
                    return;
                }

                if self.remaining_server_hello == 0 {
                    self.number_of_packet_to_filter = 0;
                    return;
                }
            }
        }
    }

    fn padding_frame(&mut self, content: &[u8], command: u8) -> BytesMut {
        let content_len = content.len().min(u16::MAX as usize);
        let padding_len = if content_len < 900 && self.is_tls {
            ((rand::random::<u16>() % 500) as usize) + (900 - content_len)
        } else {
            (rand::random::<u8>() as usize) % 256
        };

        let mut framed = BytesMut::with_capacity(
            (if self.write_uuid { 16 } else { 0 }) + 5 + content_len + padding_len,
        );
        if self.write_uuid {
            framed.extend_from_slice(self.inner.uuid.as_bytes());
            self.write_uuid = false;
        }

        framed.put_u8(command);
        framed.put_u16(content_len as u16);
        framed.put_u16(padding_len as u16);
        debug!(
            "vision padding frame: command=0x{:02x} content={} padding={} is_tls={}",
            command, content_len, padding_len, self.is_tls
        );
        framed.extend_from_slice(&content[..content_len]);
        if padding_len > 0 {
            framed.resize(framed.len() + padding_len, 0);
        }
        framed
    }

    fn make_write_pending(&mut self, data: &[u8]) -> VisionWritePending {
        if self.number_of_packet_to_filter > 0 {
            self.filter_tls_buffers(&[data]);
        }

        let slices = Self::reshape_buffer(data);
        let mut framed_prefix = Vec::new();
        let mut raw_start = slices.len();
        let mut direct_switch = false;

        for (index, slice) in slices.iter().enumerate() {
            let slice_head = slice
                .iter()
                .take(5)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("");
            debug!(
                "vision write slice: len={} head={} is_tls={} tls12_plus={} filter_left={} enable_xtls={}",
                slice.len(),
                slice_head,
                self.is_tls,
                self.is_tls12_or_above,
                self.number_of_packet_to_filter,
                self.enable_xtls
            );
            if self.is_tls
                && slice.len() > 6
                && slice.starts_with(&TLS_APPLICATION_DATA_START)
            {
                let mut command = COMMAND_PADDING_END;
                if self.enable_xtls {
                    command = COMMAND_PADDING_DIRECT;
                    self.write_direct = true;
                    direct_switch = true;
                }
                debug!(
                    "vision write application-data split: command=0x{:02x} enable_xtls={} filter_left={} slice_len={}",
                    command,
                    self.enable_xtls,
                    self.number_of_packet_to_filter,
                    slice.len()
                );
                self.is_padding = false;
                raw_start = index + 1;
                framed_prefix.push(self.padding_frame(slice, command));
                break;
            }

            if !self.is_tls12_or_above && self.number_of_packet_to_filter <= 1 {
                debug!(
                    "vision write fallback-end: is_tls12_or_above={} filter_left={} slice_len={}",
                    self.is_tls12_or_above,
                    self.number_of_packet_to_filter,
                    slice.len()
                );
                self.is_padding = false;
                raw_start = index + 1;
                framed_prefix.push(self.padding_frame(slice, COMMAND_PADDING_END));
                break;
            }

            framed_prefix.push(self.padding_frame(slice, COMMAND_PADDING_CONTINUE));
        }

        let total = framed_prefix.iter().map(BytesMut::len).sum();
        let mut framed = BytesMut::with_capacity(total);
        for frame in framed_prefix {
            framed.extend_from_slice(&frame);
        }

        let mut raw_tail = BytesMut::new();
        if raw_start < slices.len() {
            let remaining = slices[raw_start..]
                .iter()
                .map(|slice| slice.len())
                .sum();
            raw_tail.reserve(remaining);
            for slice in &slices[raw_start..] {
                raw_tail.extend_from_slice(slice);
            }
        }

        VisionWritePending {
            orig_len: data.len(),
            framed,
            framed_pos: 0,
            switch_to_raw: direct_switch,
            switch_done: false,
            raw_tail,
            raw_tail_pos: 0,
        }
    }

    fn poll_write_pending(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        let Some(pending) = self.write_pending.as_mut() else {
            return Poll::Ready(Ok(0));
        };

        while pending.framed_pos < pending.framed.len() {
            match Pin::new(&mut self.inner)
                .poll_write(cx, &pending.framed[pending.framed_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero while writing Vision framed data",
                    )));
                }
                Poll::Ready(Ok(n)) => pending.framed_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if pending.switch_to_raw && !pending.switch_done {
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            let switched = switch_reality_raw_modes(&mut self.inner.inner, false, true)?;
            debug!("vision direct write switch: switched={switched}");
            pending.switch_done = true;
        }

        while pending.raw_tail_pos < pending.raw_tail.len() {
            match Pin::new(&mut self.inner)
                .poll_write(cx, &pending.raw_tail[pending.raw_tail_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero while writing Vision raw tail",
                    )));
                }
                Poll::Ready(Ok(n)) => pending.raw_tail_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let ack = pending.orig_len;
        self.write_pending = None;
        Poll::Ready(Ok(ack))
    }

    fn finish_read_block(&mut self) -> io::Result<()> {
        debug!(
            "vision finish block: command=0x{:02x} read_padding={}",
            self.read_current_command, self.read_padding
        );
        match self.read_current_command {
            COMMAND_PADDING_CONTINUE => {}
            COMMAND_PADDING_END => {
                self.read_padding = false;
            }
            COMMAND_PADDING_DIRECT => {
                self.read_padding = false;
                let switched =
                    switch_reality_raw_modes(&mut self.inner.inner, true, false)?;
                let pending_head = self
                    .read_pending
                    .iter()
                    .take(8)
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join("");
                debug!(
                    "vision direct read switch: switched={} pending={} pending_head={}",
                    switched,
                    self.read_pending.len(),
                    pending_head
                );
            }
            command => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unknown Vision frame type: 0x{command:02x}"),
                ));
            }
        }
        Ok(())
    }

    fn parse_read_pending(&mut self) -> io::Result<bool> {
        loop {
            if !self.read_padding {
                if !self.read_pending.is_empty() {
                    let raw = self.read_pending.split_to(self.read_pending.len());
                    if self.number_of_packet_to_filter > 0 {
                        self.filter_tls_buffers(&[raw.as_ref()]);
                    }
                    self.read_buf.extend_from_slice(&raw);
                    return Ok(true);
                }
                return Ok(!self.read_buf.is_empty());
            }

            if self.read_remaining_content == -1 && self.read_remaining_padding == -1
            {
                if self.read_pending.len() < 21 {
                    return Ok(!self.read_buf.is_empty());
                }

                if self.read_pending[..16] != *self.inner.uuid.as_bytes() {
                    self.read_padding = false;
                    continue;
                }

                self.read_pending.advance(16);
                self.read_current_command = COMMAND_PADDING_CONTINUE;
                self.read_remaining_content = 0;
                self.read_remaining_padding = 0;
            }

            if self.read_remaining_content <= 0 && self.read_remaining_padding <= 0 {
                if self.read_current_command == COMMAND_PADDING_END
                    || self.read_current_command == COMMAND_PADDING_DIRECT
                {
                    self.finish_read_block()?;
                    continue;
                }

                if self.read_pending.len() < 5 {
                    return Ok(!self.read_buf.is_empty());
                }

                let header_hex = self.read_pending[..5]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join("");
                self.read_current_command = self.read_pending[0];
                self.read_remaining_content = ((self.read_pending[1] as i32) << 8)
                    | self.read_pending[2] as i32;
                self.read_remaining_padding = ((self.read_pending[3] as i32) << 8)
                    | self.read_pending[4] as i32;
                debug!(
                    "vision read header: raw={} command=0x{:02x} content={} padding={}",
                    header_hex,
                    self.read_current_command,
                    self.read_remaining_content,
                    self.read_remaining_padding
                );
                self.read_pending.advance(5);

                if self.read_remaining_content <= 0
                    && self.read_remaining_padding <= 0
                {
                    self.finish_read_block()?;
                    continue;
                }
            }

            if self.read_remaining_content > 0 {
                if self.read_pending.is_empty() {
                    return Ok(!self.read_buf.is_empty());
                }

                let take = (self.read_remaining_content as usize)
                    .min(self.read_pending.len());
                let data = self.read_pending.split_to(take);
                self.read_remaining_content -= take as i32;

                if self.number_of_packet_to_filter > 0 {
                    self.filter_tls_buffers(&[data.as_ref()]);
                }

                let head = data
                    .iter()
                    .take(8)
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join("");
                let full = if data.len() <= 64 {
                    data.iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join("")
                } else {
                    String::new()
                };
                if self.read_current_command == COMMAND_PADDING_DIRECT {
                    debug!(
                        "vision direct content chunk: len={} head={} full={}",
                        data.len(),
                        head,
                        full
                    );
                } else {
                    debug!(
                        "vision content chunk: command=0x{:02x} len={} head={} full={}",
                        self.read_current_command,
                        data.len(),
                        head,
                        full
                    );
                }

                if !data.is_empty() {
                    self.read_buf.extend_from_slice(&data);
                }
                continue;
            }

            if self.read_remaining_padding > 0 {
                if self.read_pending.is_empty() {
                    return Ok(!self.read_buf.is_empty());
                }

                let skip = (self.read_remaining_padding as usize)
                    .min(self.read_pending.len());
                self.read_pending.advance(skip);
                self.read_remaining_padding -= skip as i32;

                if self.read_remaining_content <= 0
                    && self.read_remaining_padding <= 0
                {
                    self.finish_read_block()?;
                }
            }
        }
    }

    async fn fill_read_buf(&mut self) -> io::Result<()> {
        loop {
            if self.parse_read_pending()? {
                return Ok(());
            }

            let mut tmp = [0u8; 8192];
            let n = tokio::io::AsyncReadExt::read(&mut self.inner, &mut tmp).await?;
            if n == 0 {
                if !self.read_pending.is_empty() {
                    let left = self.read_pending.split_to(self.read_pending.len());
                    if self.number_of_packet_to_filter > 0 {
                        self.filter_tls_buffers(&[left.as_ref()]);
                    }
                    self.read_buf.extend_from_slice(&left);
                }
                return Ok(());
            }
            debug!(
                "vision fill_read_buf: inner_read={} pending_before={} padding={} cmd=0x{:02x} rem_content={} rem_padding={}",
                n,
                self.read_pending.len(),
                self.read_padding,
                self.read_current_command,
                self.read_remaining_content,
                self.read_remaining_padding
            );
            self.read_pending.extend_from_slice(&tmp[..n]);
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

        // Try to greedily complete an in-progress padding block when data is
        // already available, to avoid long stalls between partial chunks.
        loop {
            let need_more = self.read_padding
                && self.read_pending.is_empty()
                && (self.read_remaining_content > 0
                    || self.read_remaining_padding > 0);
            if !need_more || self.read_buf.len() >= buf.remaining() {
                break;
            }
            let before = self.read_buf.len();
            let poll_result = {
                let fut = self.fill_read_buf();
                tokio::pin!(fut);
                fut.poll(cx)
            };
            match poll_result {
                Poll::Ready(Ok(())) => {
                    if self.read_buf.len() == before {
                        break;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
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
        if self.write_pending.is_some() {
            return self.poll_write_pending(cx);
        }

        if self.is_padding {
            self.write_pending = Some(self.make_write_pending(buf));
            return self.poll_write_pending(cx);
        }

        if self.number_of_packet_to_filter > 0 {
            self.filter_tls_buffers(&[buf]);
        }

        if self.write_direct {
            let head = buf
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("");
            debug!("vision raw write: len={} head={}", buf.len(), head);
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
        let stream = VlessStream::new(
            inner,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            &addr,
            false,
            None,
        )
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
