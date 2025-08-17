mod cipher;
mod client;
mod header;
// pub mod http;
mod datagram;
mod kdf;
mod stream;
mod user;

pub(crate) const VERSION: u8 = 1;

pub(crate) const OPTION_CHUNK_STREAM: u8 = 1;
#[allow(unused)]
pub(crate) const OPTION_CHUNK_MASK: u8 = 2;

type Security = u8;

pub(crate) const SECURITY_AES_128_GCM: Security = 3;
pub(crate) const SECURITY_CHACHA20_POLY1305: Security = 4;
pub(crate) const SECURITY_NONE: Security = 5;

pub(crate) const COMMAND_TCP: u8 = 1;
pub(crate) const COMMAND_UDP: u8 = 2;

const CHUNK_SIZE: usize = 1 << 14;
const MAX_CHUNK_SIZE: usize = 17 * 1024;

use std::net::SocketAddr;

use bytes::BufMut;
pub use client::{Builder, VmessOption};
pub use datagram::OutboundDatagramVmess;

use crate::session::SocksAddr;

impl SocksAddr {
    pub(crate) fn write_to_buf_vmess<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::Ip(SocketAddr::V4(addr)) => {
                buf.put_u16(addr.port());
                buf.put_u8(0x01);
                buf.put_slice(&addr.ip().octets());
            }
            Self::Ip(SocketAddr::V6(addr)) => {
                buf.put_u16(addr.port());
                buf.put_u8(0x03);
                for seg in &addr.ip().segments() {
                    buf.put_u16(*seg);
                }
            }
            Self::Domain(domain_name, port) => {
                buf.put_u16(*port);
                buf.put_u8(0x02);
                buf.put_u8(domain_name.len() as u8);
                buf.put_slice(domain_name.as_bytes());
            }
        }
    }
}
