use std::io::ErrorKind;

use bytes::{Buf, BufMut, BytesMut};
use quinn_proto::{coding::Codec, VarInt};
use rand::distributions::Alphanumeric;
use tokio_util::codec::{Decoder, Encoder};

use crate::session::SocksAddr;

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

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
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
        let msg: String =
            String::from_utf8(msg).map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

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
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(range) as usize;
    rng.sample_iter(Alphanumeric).take(len).collect()
}

impl Encoder<&'_ SocksAddr> for Hy2TcpCodec {
    type Error = std::io::Error;
    fn encode(&mut self, item: &'_ SocksAddr, buf: &mut BytesMut) -> Result<(), Self::Error> {
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
