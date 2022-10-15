use crate::proxy::socks::inbound::{auth_methods, response_code, socks_command, SOCKS_VERSION};
use crate::session::{Session, SocksAddr};
use crate::Dispatcher;
use bytes::{BufMut, BytesMut};
use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::{io, str};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(crate) async fn handle_tcp(
    sess: &mut Session,
    s: &mut TcpStream,
    dispatcher: Arc<Dispatcher>,
    users: &HashMap<String, String>,
) -> io::Result<()> {
    // handshake
    let mut buf = BytesMut::new();
    {
        buf.resize(2, 0);
        s.read_exact(&mut buf[..]).await?;

        if buf[0] != SOCKS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "unsupported SOCKS version",
            ));
        }

        let n_methods = buf[1] as usize;
        if n_methods == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "malformed SOCKS data"));
        }

        buf.resize(n_methods, 0);
        s.read_exact(&mut buf[..]).await?;

        let mut response = [SOCKS_VERSION, auth_methods::NO_METHODS];
        let methods = &buf[..];
        if methods.contains(&auth_methods::USER_PASS) {
            response[1] = auth_methods::USER_PASS;
            s.write_all(&response).await?;

            buf.resize(2, 0);
            s.read_exact(&mut buf[..]).await?;
            let ulen = buf[1] as usize;
            buf.resize(ulen, 0);
            s.read_exact(&mut buf[..]).await?;
            let user = unsafe { str::from_utf8_unchecked(buf.to_owned().as_ref()).to_owned() };

            s.read_exact(&mut buf[..1]).await?;
            let plen = buf[0] as usize;
            buf.resize(plen, 0);
            s.read_exact(&mut buf[..]).await?;
            let pass = unsafe { str::from_utf8_unchecked(buf.to_owned().as_ref()).to_owned() };

            match users.get(&user) {
                Some(p) if p == &pass => {
                    response = [0x1, response_code::SUCCEEDED];
                    s.write_all(&response).await?;
                }
                _ => {
                    response = [0x1, response_code::FAILURE];
                    s.write_all(&response).await?;
                    s.shutdown().await?;
                    return Err(io::Error::new(io::ErrorKind::Other, "auth failure"));
                }
            }
        } else if methods.contains(&auth_methods::NO_AUTH) {
            response[1] = auth_methods::NO_AUTH;
            s.write_all(&response).await?;
        } else {
            response[1] = auth_methods::NO_METHODS;
            s.write_all(&response).await?;
            s.shutdown().await?;
            return Err(io::Error::new(io::ErrorKind::Other, "auth failure"));
        }
    }

    buf.resize(3, 0);
    s.read_exact(&mut buf[..]).await?;
    if buf[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "unsupported SOCKS version",
        ));
    }

    let addr = SocksAddr::read_from(s).await?;

    match buf[1] {
        socks_command::CONNECT | socks_command::UDP_ASSOCIATE => {
            buf.clear();
            buf.put_u8(SOCKS_VERSION);
            buf.put_u8(response_code::SUCCEEDED);
            buf.put_u8(0x0);
            let bnd = SocksAddr::from(s.local_addr()?);
            bnd.write_buf(&mut buf);
            s.write_all(&buf[..]).await?;
            sess.destination = addr;
            dispatcher
                .dispatch_stream(sess.to_owned(), Box::new(s) as _)
                .await;
            Ok(())
        }
        _ => {
            buf.clear();
            buf.put_u8(SOCKS_VERSION);
            buf.put_u8(response_code::COMMAND_NOT_SUPPORTED);
            buf.put_u8(0x0);
            SocksAddr::any_ipv4().write_buf(&mut buf);
            s.write_all(&buf).await?;
            Err(io::Error::new(
                io::ErrorKind::Other,
                "unsupported SOCKS command",
            ))
        }
    }
}
