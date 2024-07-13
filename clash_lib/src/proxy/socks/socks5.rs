use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{common::errors::new_io_error, proxy::AnyStream, session::SocksAddr};

pub const SOCKS5_VERSION: u8 = 0x05;

const MAX_ADDR_LEN: usize = 1 + 1 + 255 + 2;
const MAX_AUTH_LEN: usize = 255;

pub(crate) mod auth_methods {
    pub const NO_AUTH: u8 = 0x00;
    pub const USER_PASS: u8 = 0x02;
    pub const NO_METHODS: u8 = 0xff;
}

pub(crate) mod socks_command {
    pub const CONNECT: u8 = 0x01;
    // pub const BIND: u8 = 0x02;
    pub const UDP_ASSOCIATE: u8 = 0x3;
}

pub(crate) mod response_code {
    pub const SUCCEEDED: u8 = 0x00;
    pub const FAILURE: u8 = 0x01;
    // pub const RULE_FAILURE: u8 = 0x02;
    // pub const NETWORK_UNREACHABLE: u8 = 0x03;
    // pub const HOST_UNREACHABLE: u8 = 0x04;
    // pub const CONNECTION_REFUSED: u8 = 0x05;
    // pub const TTL_EXPIRED: u8 = 0x06;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    // pub const ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

const ERROR_CODE_LOOKUP: &[&str] = &[
    "succeeded",
    "general SOCKS server failure",
    "connection not allowed by ruleset",
    "network unreachable",
    "host unreachable",
    "connection refused",
    "TTL expired",
    "command not supported",
    "address type not supported",
];

pub(crate) async fn client_handshake(
    s: &mut AnyStream,
    addr: &SocksAddr,
    command: u8,
    username: Option<String>,
    password: Option<String>,
) -> std::io::Result<SocksAddr> {
    let mut buf = BytesMut::with_capacity(MAX_AUTH_LEN);
    buf.put_u8(SOCKS5_VERSION);

    if username.is_some() && password.is_some() {
        buf.put_u8(1);
        buf.put_u8(auth_methods::USER_PASS);
    } else {
        buf.put_u8(1);
        buf.put_u8(auth_methods::NO_AUTH);
    }
    s.write(&buf).await?;

    s.read_exact(&mut buf[..2]).await?;
    if buf[0] != SOCKS5_VERSION {
        return Err(new_io_error("unsupported SOCKS version"));
    }

    let method = buf[1];
    if method == auth_methods::USER_PASS {
        let username = username
            .as_ref()
            .ok_or_else(|| new_io_error("missing username"))?;
        let password = password
            .as_ref()
            .ok_or_else(|| new_io_error("missing password"))?;

        let mut buf = BytesMut::with_capacity(MAX_AUTH_LEN);
        buf.put_u8(1);
        buf.put_u8(username.len() as u8);
        buf.put_slice(username.as_bytes());
        buf.put_u8(password.len() as u8);
        buf.put_slice(password.as_bytes());
        s.write(&buf).await?;

        s.read_exact(&mut buf[..2]).await?;

        if buf[1] != response_code::SUCCEEDED {
            return Err(new_io_error("SOCKS5 authentication failed"));
        }
    } else if method != auth_methods::NO_AUTH {
        return Err(new_io_error("unsupported SOCKS5 authentication method"));
    }

    let mut buf = BytesMut::with_capacity(MAX_ADDR_LEN);
    buf.put_u8(SOCKS5_VERSION);
    buf.put_u8(command);
    buf.put_u8(0x00);
    if command == socks_command::UDP_ASSOCIATE {
        let addr = SocksAddr::any_ipv4();
        addr.write_buf(&mut buf);
    } else {
        addr.write_buf(&mut buf);
    }
    s.write(&buf).await?;

    buf.resize(3, 0);
    s.read_exact(&mut buf).await?;

    if buf[0] != SOCKS5_VERSION {
        return Err(new_io_error("unsupported SOCKS version"));
    }

    if buf[1] != response_code::SUCCEEDED {
        return Err(new_io_error(
            format!(
                "SOCKS5 request failed with {}",
                if buf[1] < ERROR_CODE_LOOKUP.len() as u8 {
                    ERROR_CODE_LOOKUP[buf[1] as usize]
                } else {
                    "unknown error"
                }
            )
            .as_str(),
        ));
    }

    SocksAddr::read_from(s).await
}
