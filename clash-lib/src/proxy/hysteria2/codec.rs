use crate::session::SocksAddr;
use anyhow::anyhow;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn_proto::{VarInt, coding::Codec};
use rand::distr::Alphanumeric;
use std::{io::ErrorKind, str::FromStr};
use tokio_util::codec::{Decoder, Encoder};

pub struct Hy2TcpCodec;

/// ### format
///
/// ```text
/// [uint8] Status (0x00 = OK, 0x01 = Error)
/// [varint] Message length
/// [bytes] Message string
/// [varint] Padding length
/// [bytes] Random padding
/// ```
#[derive(Debug)]
pub struct Hy2TcpResp {
    pub status: u8,
    pub msg: String,
}

impl Decoder for Hy2TcpCodec {
    type Error = std::io::Error;
    type Item = Hy2TcpResp;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if !src.has_remaining() {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        let status = src.get_u8();
        let msg_len = VarInt::decode(src)
            .map_err(|_| ErrorKind::InvalidData)?
            .into_inner() as usize;

        if src.remaining() < msg_len {
            return Err(ErrorKind::UnexpectedEof.into());
        }

        let msg: Vec<u8> = src.split_to(msg_len).into();
        let msg: String = String::from_utf8(msg)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

        let padding_len = VarInt::decode(src)
            .map_err(|_| ErrorKind::UnexpectedEof)?
            .into_inner() as usize;

        if src.remaining() < padding_len {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        src.advance(padding_len);

        Ok(Hy2TcpResp { status, msg }.into())
    }
}

#[inline]
pub fn padding(range: std::ops::RangeInclusive<u32>) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::rng();
    let len = rng.random_range(range) as usize;
    rng.sample_iter(Alphanumeric).take(len).collect()
}

impl Encoder<&'_ SocksAddr> for Hy2TcpCodec {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: &'_ SocksAddr,
        buf: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        const REQ_ID: VarInt = VarInt::from_u32(0x401);

        let padding = padding(64..=512);
        let padding_var = VarInt::from_u32(padding.len() as u32);

        let addr = item.to_string().into_bytes();
        let addr_var = VarInt::from_u32(addr.len() as u32);

        buf.reserve(
            var_size(REQ_ID)
                + var_size(padding_var)
                + var_size(addr_var)
                + addr.len()
                + padding.len(),
        );

        REQ_ID.encode(buf);

        addr_var.encode(buf);
        buf.put_slice(&addr);

        padding_var.encode(buf);
        buf.put_slice(&padding);

        Ok(())
    }
}

/// Compute the number of bytes needed to encode this value
pub fn var_size(var: VarInt) -> usize {
    let x = var.into_inner();
    if x < 2u64.pow(6) {
        1
    } else if x < 2u64.pow(14) {
        2
    } else if x < 2u64.pow(30) {
        4
    } else if x < 2u64.pow(62) {
        8
    } else {
        unreachable!("malformed VarInt");
    }
}

/// ```text
/// [uint32] Session ID
/// [uint16] Packet ID
/// [uint8] Fragment ID
/// [uint8] Fragment count
/// [varint] Address length
/// [bytes] Address string (host:port)
/// [bytes] Payload
/// ```
#[allow(unused)]
#[derive(Clone)]
pub struct HysUdpPacket {
    pub session_id: u32,
    pub pkt_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: SocksAddr,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for HysUdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HysUdpPacket")
            .field("session_id", &format_args!("{:#010x}", self.session_id))
            .field("pkt_id", &self.pkt_id)
            .field("frag_id", &self.frag_id)
            .field("frag_count", &self.frag_count)
            .field("addr", &self.addr)
            .field("data_size", &self.data.len())
            .finish()
    }
}

impl HysUdpPacket {
    /// `decode` method, `encode` has been moved to Fragments
    pub fn decode(buf: &mut BytesMut) -> anyhow::Result<Self> {
        if buf.len() < 4 + 2 + 1 + 1 {
            return Err(anyhow!("packet too short"));
        }
        let session_id = buf.get_u32();
        let pkt_id = buf.get_u16();
        let frag_id = buf.get_u8();
        let frag_count = buf.get_u8();
        let addr_len =
            VarInt::decode(buf).map_err(|_| anyhow!(""))?.into_inner() as usize;
        let addr: Vec<u8> = buf.split_to(addr_len).into();
        let data = buf.split().to_vec();
        Ok(Self {
            session_id,
            pkt_id,
            frag_id,
            frag_count,
            addr: to_socksaddr(&addr)?,
            data,
        })
    }
}

fn to_socksaddr(bytes: &[u8]) -> std::io::Result<SocksAddr> {
    let addr_str = std::str::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid UTF-8 in address",
        )
    })?;

    // Split the string at ':' to get host and port
    let (host, port_str) = addr_str.rsplit_once(':').ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Address must be in host:port format",
        )
    })?;

    // Parse the port
    let port = port_str.parse::<u16>().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid port number")
    })?;

    // Try parsing as SocketAddr first
    if let Ok(sock_addr) = std::net::SocketAddr::from_str(addr_str) {
        Ok(SocksAddr::Ip(sock_addr))
    } else {
        // If not a valid IP address, treat as domain
        Ok(SocksAddr::Domain(host.to_string(), port))
    }
}

/// Iterator over fragments of a packet
#[derive(Debug)]
pub struct Fragments<'a, P> {
    session_id: u32,
    pkt_id: u16,
    addr: (Vec<u8>, VarInt),
    frag_total: u8,
    next_frag_id: u8,
    next_frag_start: usize,
    payload: P,
    // used for fragment, not a actual field of packet
    max_pkt_size: usize,
    fixed_size: usize,
    _marker: std::marker::PhantomData<&'a P>,
}

impl<'a, P> Fragments<'a, P>
where
    P: AsRef<[u8]> + 'a,
{
    pub fn new(
        session_id: u32,
        pkt_id: u16,
        addr: SocksAddr,
        max_pkt_size: usize,
        payload: P,
    ) -> Self {
        let addr = addr.to_string().into_bytes();
        let addr_var = VarInt::from_u32(addr.len() as u32);

        let fixed_size = 4 + 2 + 1 + 1 + addr.len() + var_size(addr_var);
        let max_data_size = max_pkt_size - fixed_size;
        // TODO: report warning when frag_total > u8::MAX
        let frag_total = payload.as_ref().len().div_ceil(max_data_size) as u8;

        Self {
            session_id,
            pkt_id,
            addr: (addr, addr_var),
            frag_total,
            next_frag_id: 0,
            next_frag_start: 0,
            payload,
            max_pkt_size,
            fixed_size,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a, P> Iterator for Fragments<'a, P>
where
    P: AsRef<[u8]> + 'a,
{
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_frag_id < self.frag_total {
            let max_payload_size = self.max_pkt_size - self.fixed_size;
            let next_frag_end = (self.next_frag_start + max_payload_size)
                .min(self.payload.as_ref().len());
            let payload =
                &self.payload.as_ref()[self.next_frag_start..next_frag_end];

            let mut buf = BytesMut::new();
            buf.reserve(self.fixed_size + payload.len());

            buf.put_u32(self.session_id);
            buf.put_u16(self.pkt_id);
            buf.put_u8(self.next_frag_id);
            buf.put_u8(self.frag_total);
            self.addr.1.encode(&mut buf);
            buf.put_slice(self.addr.0.as_slice());
            buf.put_slice(payload);
            let frag = buf.freeze();

            self.next_frag_id += 1;
            self.next_frag_start = next_frag_end;

            Some(frag)
        } else {
            None
        }
    }
}

impl<P> ExactSizeIterator for Fragments<'_, P>
where
    P: AsRef<[u8]>,
{
    fn len(&self) -> usize {
        self.frag_total as usize
    }
}

#[derive(Default)]
pub struct Defragger {
    pub pkt_id: u16,
    pub frags: Vec<Option<HysUdpPacket>>,
    pub cnt: u16,
}

impl Defragger {
    pub fn feed(&mut self, pkt: HysUdpPacket) -> Option<HysUdpPacket> {
        if pkt.frag_count == 1 {
            return Some(pkt);
        }
        if pkt.frag_count <= pkt.frag_id {
            tracing::warn!(
                "invalid frag, id, count: {}, {}",
                pkt.frag_id,
                pkt.frag_count
            );
            return None;
        }
        let frag_id = pkt.frag_id as usize;

        if pkt.pkt_id != self.pkt_id || pkt.frag_count as usize != self.frags.len() {
            // new packet, overwrite the old one
            // if the new packet frags is 1, should already return
            self.pkt_id = pkt.pkt_id;
            self.frags.clear();
            self.frags.resize(pkt.frag_count as usize, None);
            self.cnt = 0;
            self.frags[frag_id] = Some(pkt);
            self.cnt += 1;
        } else if frag_id < self.frags.len() && self.frags[frag_id].is_none() {
            self.frags[frag_id] = Some(pkt);
            self.cnt += 1;
            if self.cnt as usize == self.frags.len() {
                // now we have all fragments
                let frags = std::mem::take(&mut self.frags);
                let mut iters = frags.into_iter().map(|x| x.unwrap());
                let mut pkt0 = iters.next().unwrap();
                pkt0.frag_count = 1;
                pkt0.frag_id = 0;
                for pkt in iters {
                    pkt0.data.extend_from_slice(&pkt.data);
                }
                return Some(pkt0);
            }
        }
        None
    }
}

#[test]
fn hy2_resp_parse() {
    let mut src = BytesMut::from(&[0x00, 0x03, 0x61, 0x62, 0x63, 0x00][..]);
    let msg = Hy2TcpCodec.decode(&mut src).unwrap().unwrap();
    assert!(msg.status == 0);
    assert!(msg.msg == "abc");

    let mut src = BytesMut::from(&[0x01, 0x00, 0x00][..]);
    let msg = Hy2TcpCodec.decode(&mut src).unwrap().unwrap();
    assert!(msg.status == 0x1);
    assert!(msg.msg.is_empty());
}

#[test]
fn test_decode_addr() {
    let socket_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 80));
    let addr = SocksAddr::Ip(socket_addr);
    let addr_bytes = addr.to_string().into_bytes();
    let decoded_addr = to_socksaddr(&addr_bytes).unwrap();
    assert_eq!(addr, decoded_addr);

    let addr = SocksAddr::Domain("example.com".to_string(), 80);
    let addr_bytes = addr.to_string().into_bytes();
    let decoded_addr = to_socksaddr(&addr_bytes).unwrap();
    assert_eq!(addr, decoded_addr);
}
