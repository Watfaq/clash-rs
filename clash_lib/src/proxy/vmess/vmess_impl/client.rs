use std::io;

use crate::{common::utils, proxy::AnyStream, session::SocksAddr};

use super::{
    stream::{self},
    user::{self, new_alter_id_list},
    Security, SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305, SECURITY_NONE,
};

#[derive(Clone)]
pub struct VmessOption {
    pub uuid: String,
    pub alter_id: u16,
    pub security: String,
    pub udp: bool,
    pub dst: SocksAddr,
}

pub struct Builder {
    pub user: Vec<user::ID>,
    pub uuid: uuid::Uuid,
    pub security: Security,
    pub is_aead: bool,
    pub is_udp: bool,
    pub dst: SocksAddr,
}

impl Builder {
    pub fn new(opt: &VmessOption) -> io::Result<Self> {
        let uuid = uuid::Uuid::parse_str(&opt.uuid).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid uuid format, should be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            )
        })?;

        let security = match opt.security.to_lowercase().as_str() {
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
            is_aead: opt.alter_id == 0,
            is_udp: opt.udp,
            dst: opt.dst.clone(),
        })
    }

    pub async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let idx = utils::rand_range(0..self.user.len());
        let stream = stream::VmessStream::new(
            stream,
            &self.user[idx],
            &self.dst,
            &self.security,
            self.is_aead,
            self.is_udp,
        )
        .await?;

        Ok(Box::new(stream))
    }
}
