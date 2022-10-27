use crate::proxy::shadowsocks::HandlerOptions;
use crate::proxy::utils::new_tcp_stream;
use crate::proxy::AnyStream;
use crate::session::Session;
use crate::ThreadSafeDNSResolver;
use shadowsocks::config::ServerType;
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::{ProxyClientStream, ServerConfig};
use std::io;
use std::net::SocketAddr;

pub async fn handle(
    sess: &Session,
    opts: &HandlerOptions,
    resolver: ThreadSafeDNSResolver,
) -> io::Result<AnyStream> {
    let ss = new_tcp_stream(
        resolver.clone(),
        opts.server.as_str(),
        opts.port,
        opts.common_opts.iface.as_ref(),
    )
    .await?;

    let ctx = Context::new_shared(ServerType::Local);
    let cfg = ServerConfig::new(
        format!("{}:{}", opts.server, opts.port)
            .parse::<SocketAddr>()
            .expect(
                format!(
                    "invalid proxy server address: {}: {}",
                    opts.server, opts.port
                )
                .as_str(),
            ),
        opts.password.as_str(),
        match opts.cipher.as_str() {
            "aes-128-gcm" => CipherKind::AES_256_GCM,
            "aes-255-gcm" => CipherKind::AES_256_GCM,
            "chacha20-ietf-poly1305" => CipherKind::CHACHA20_POLY1305,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("cipher {} deprecated or not supported", opts.cipher),
                ));
            }
        },
    );

    Ok(Box::new(ProxyClientStream::from_stream(
        ctx,
        ss,
        &cfg,
        (sess.destination.host(), sess.destination.port()),
    )) as AnyStream)
}
