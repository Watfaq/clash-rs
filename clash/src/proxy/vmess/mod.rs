use std::io;

use self::{
    aead::{AeadReader, AeadWriter},
    chunk::{ChunkReader, ChunkWriter},
    user::new_alter_id_list,
};

mod aead;
mod chunk;
mod header;
mod kdf;
mod stream;
mod user;

pub(crate) const VERSION: u8 = 1;

pub(crate) const OPTION_CHUNK_STREAM: u8 = 1;
pub(crate) const OPTION_CHUNK_MASK: u8 = 2;

type Security = u8;

pub(crate) const SECURITY_CHACHA20_POLY1305: Security = 3;
pub(crate) const SECURITY_AES_128_GCM: Security = 4;
pub(crate) const SECURITY_NONE: Security = 5;

pub(crate) const COMMAND_TCP: u8 = 1;
pub(crate) const COMMAND_UDP: u8 = 2;

pub(crate) const ATYP_IPV4: u8 = 1;
pub(crate) const ATYP_DOMAIN_NAME: u8 = 2;
pub(crate) const ATYP_IPV6: u8 = 3;

const CHUNK_SIZE: usize = 1 << 14;
const MAX_CHUNK_SIZE: usize = 17 * 1024;

pub(crate) enum VmessReader {
    None(ChunkReader),
    Aes128Gcm(AeadReader),
    ChaCha20Poly1305(AeadReader),
}

pub(crate) enum VmessWriter {
    None(ChunkWriter),
    Aes128Gcm(AeadWriter),
    ChaCha20Poly1305(AeadWriter),
}

#[derive(Clone)]
pub(crate) struct DstAddr {
    pub udp: bool,
    pub atyp: u8,
    pub addr: bytes::Bytes,
    pub port: u16,
}

pub struct Option {
    pub uuid: String,
    pub alter_id: u16,
    pub security: String,
    pub port: u16,
    pub hostname: String,
    pub is_aead: bool,
}

pub struct Client {
    pub user: Vec<user::ID>,
    pub uuid: uuid::Uuid,
    pub security: Security,
    pub is_aead: bool,
}

impl Client {
    pub fn new(opt: Option) -> io::Result<Self> {
        let uuid = uuid::Uuid::parse_str(&opt.uuid).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid uuid format, should be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            )
        })?;

        let security = match opt.security.as_str() {
            "chacha20-poly1305" => SECURITY_CHACHA20_POLY1305,
            "aes-128-gcm" => SECURITY_AES_128_GCM,
            "none" => SECURITY_NONE,
            "auto" => match std::env::consts::ARCH {
                "x86_64" | "s390x" | "aarch64" => SECURITY_AES_128_GCM,
                _ => SECURITY_CHACHA20_POLY1305,
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid security",
                ))
            }
        };

        Ok(Self {
            user: new_alter_id_list(&user::new_id(&uuid), opt.alter_id),
            uuid,
            security,
            is_aead: opt.is_aead,
        })
    }
}
