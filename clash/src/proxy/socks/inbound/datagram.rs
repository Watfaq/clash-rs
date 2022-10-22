use crate::session::SocksAddr;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

/*
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+

The fields in the UDP request header are:

o  RSV  Reserved X'0000'
o  FRAG    Current fragment number
o  ATYP    address type of following addresses:
o  IP V4 address: X'01'
o  DOMAINNAME: X'03'
o  IP V6 address: X'04'
o  DST.ADDR       desired destination address
o  DST.PORT       desired destination port
o  DATA     user data
*/
pub struct Socks5UDPCodec;

impl Encoder<(Bytes, SocksAddr)> for Socks5UDPCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: (Bytes, SocksAddr), dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.resize(3 + item.1.size() + item.0.len(), 0);
        dst.put_slice(&[0x0, 0x0, 0x0]);
        item.1.write_buf(dst);
        dst.put_slice(item.0.as_ref());
        Ok(())
    }
}

impl Decoder for Socks5UDPCodec {
    type Item = (SocksAddr, BytesMut);
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 3 {
            return Ok(None);
        }

        if src[2] != 0 {
            return Err(std::io::Error::new(
                io::ErrorKind::Other,
                "unsupported FRAG",
            ));
        }

        src.advance(3);
        let addr = SocksAddr::peek_read(src)?;
        src.advance(addr.size());
        let packet = std::mem::take(src);
        Ok(Some((addr, packet)))
    }
}
