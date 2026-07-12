use std::str;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    ProxyRequest, TcpSession, TcpTrait,
    error::SError,
    msgs::socks5::{AddrOrDomain, SocksAddr},
    utils::replay_stream::ReplayStream,
};

#[derive(Clone, Debug)]
pub struct ProxyBasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Default)]
pub struct HttpProxyServer {
    users: Vec<ProxyBasicAuth>,
}

impl HttpProxyServer {
    pub fn new() -> Self {
        Self { users: Vec::new() }
    }

    pub fn with_users(users: Vec<ProxyBasicAuth>) -> Self {
        Self { users }
    }

    pub fn auth_enabled(&self) -> bool {
        !self.users.is_empty()
    }

    pub async fn accept_stream<S>(&self, mut stream: S) -> Result<ProxyRequest, SError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static + TcpTrait,
    {
        let (header, remain) = Self::read_header(&mut stream).await?;
        let text = str::from_utf8(&header)
            .map_err(|_| SError::SocksError("invalid http request".into()))?;

        let mut lines = text.split("\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| SError::SocksError("empty http request".into()))?;

        let line = request_line.trim();
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();
        let version = parts.next().unwrap_or_default();

        if method.is_empty() || target.is_empty() || version.is_empty() {
            return Err(SError::SocksError("invalid http request line".into()));
        }

        if self.auth_enabled() && !check_proxy_basic_auth(text, &self.users) {
            write_proxy_auth_required(&mut stream).await?;
            return Err(SError::SocksError("http proxy auth failed".into()));
        }

        if method.eq_ignore_ascii_case("CONNECT") {
            let dst = parse_connect_target(target)?;

            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            stream.flush().await?;

            let stream = ReplayStream::new(remain, stream);

            return Ok(ProxyRequest::Tcp(TcpSession {
                stream: Box::new(stream),
                dst,
                user_context: None,
            }));
        }

        let (dst, rewritten_header) = rewrite_forward_request(&header)?;
        let mut first_packet = rewritten_header;
        first_packet.extend_from_slice(&remain);

        let stream = ReplayStream::new(first_packet, stream);

        Ok(ProxyRequest::Tcp(TcpSession {
            stream: Box::new(stream),
            dst,
            user_context: None,
        }))
    }

    async fn read_header<S>(stream: &mut S) -> Result<(Vec<u8>, Vec<u8>), SError>
    where
        S: AsyncRead + Unpin,
    {
        const MAX_HEADER: usize = 32 * 1024;
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 1024];

        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(SError::SocksError(
                    "connection closed before http header completed".into(),
                ));
            }

            buf.extend_from_slice(&tmp[..n]);

            if let Some(end) = find_header_end(&buf) {
                let header = buf[..end].to_vec();
                let remain = buf[end..].to_vec();
                return Ok((header, remain));
            }

            if buf.len() > MAX_HEADER {
                return Err(SError::SocksError("http header too large".into()));
            }
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

fn check_proxy_basic_auth(text: &str, users: &[ProxyBasicAuth]) -> bool {
    let Some(value) = find_header_value(text, "Proxy-Authorization") else {
        return false;
    };

    let value_lower = value.to_ascii_lowercase();
    let Some(encoded) = value_lower.strip_prefix("basic ").map(|_| &value[6..]) else {
        return false;
    };

    let Ok(decoded) = STANDARD.decode(encoded.trim()) else {
        return false;
    };

    let Ok(decoded) = str::from_utf8(&decoded) else {
        return false;
    };

    users
        .iter()
        .any(|u| decoded == format!("{}:{}", u.username, u.password))
}

fn find_header_value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }

        let line = line.trim();
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };

        if k.trim().eq_ignore_ascii_case(name) {
            return Some(v.trim());
        }
    }

    None
}

async fn write_proxy_auth_required<S>(stream: &mut S) -> Result<(), SError>
where
    S: AsyncWrite + Unpin,
{
    let resp = concat!(
        "HTTP/1.1 407 Proxy Authentication Required\r\n",
        "Proxy-Authenticate: Basic realm=\"shadowquic\"\r\n",
        "Content-Length: 0\r\n",
        "Connection: close\r\n",
        "\r\n"
    );

    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

fn parse_connect_target(target: &str) -> Result<SocksAddr, SError> {
    let target = target.trim();
    let (host, port_str) = if let Some(rest) = target.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| SError::SocksError("invalid connect target".into()))?;
        let host = &rest[..end];
        let remain = &rest[end + 1..];
        let port = remain
            .strip_prefix(':')
            .ok_or_else(|| SError::SocksError("missing port".into()))?;
        (host, port)
    } else {
        let idx = target
            .rfind(':')
            .ok_or_else(|| SError::SocksError("missing port".into()))?;
        (&target[..idx], &target[idx + 1..])
    };

    let port: u16 = port_str
        .parse()
        .map_err(|_| SError::SocksError("invalid port".into()))?;

    make_socks_addr(host, port)
}

fn rewrite_forward_request(header: &[u8]) -> Result<(SocksAddr, Vec<u8>), SError> {
    let text =
        str::from_utf8(header).map_err(|_| SError::SocksError("invalid http request".into()))?;
    let text = text.trim_start();
    let mut lines = text.split("\r\n");

    let request_line = lines
        .next()
        .ok_or_else(|| SError::SocksError("empty http request".into()))?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();

    if method.is_empty() || target.is_empty() || version.is_empty() {
        return Err(SError::SocksError("invalid http request line".into()));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        return Err(SError::SocksError("unexpected connect request".into()));
    }

    let parsed = parse_absolute_http_uri(target)?;
    let dst = make_socks_addr(&parsed.host, parsed.port)?;

    let mut out = Vec::with_capacity(header.len() + 64);
    out.extend_from_slice(format!("{method} {} {version}\r\n", parsed.path_and_query).as_bytes());

    let is_ipv6 = parsed.host.parse::<std::net::Ipv6Addr>().is_ok();
    let host_header = if is_ipv6 {
        if parsed.port == 80 {
            format!("[{}]", parsed.host)
        } else {
            format!("[{}]:{}", parsed.host, parsed.port)
        }
    } else if parsed.port == 80 {
        parsed.host.clone()
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };

    for line in lines {
        if line.is_empty() {
            break;
        }

        let lower = line.to_ascii_lowercase();

        if lower.starts_with("host:") {
            continue;
        }
        if lower.starts_with("proxy-connection:") {
            continue;
        }
        if lower.starts_with("connection:") {
            continue;
        }
        if lower.starts_with("keep-alive:") {
            continue;
        }
        if lower.starts_with("proxy-authenticate:") {
            continue;
        }
        if lower.starts_with("proxy-authorization:") {
            continue;
        }

        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(format!("Host: {host_header}\r\n").as_bytes());
    out.extend_from_slice(b"Connection: close\r\n");
    out.extend_from_slice(b"\r\n");

    Ok((dst, out))
}

struct ParsedHttpUri {
    host: String,
    port: u16,
    path_and_query: String,
}

fn parse_absolute_http_uri(target: &str) -> Result<ParsedHttpUri, SError> {
    let rest = target
        .strip_prefix("http://")
        .ok_or_else(|| SError::SocksError("only absolute http:// URI is supported".into()))?;

    let (authority, path_and_query) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    if authority.is_empty() {
        return Err(SError::SocksError("missing authority".into()));
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| SError::SocksError("invalid ipv6 authority".into()))?;
        let host = &rest[..end];
        let remain = &rest[end + 1..];
        let port = if remain.is_empty() {
            80
        } else {
            let p = remain
                .strip_prefix(':')
                .ok_or_else(|| SError::SocksError("invalid ipv6 authority".into()))?;
            p.parse()
                .map_err(|_| SError::SocksError("invalid port".into()))?
        };
        (host.to_string(), port)
    } else {
        match authority.rfind(':') {
            Some(idx) if authority[idx + 1..].chars().all(|c| c.is_ascii_digit()) => {
                let host = &authority[..idx];
                let port: u16 = authority[idx + 1..]
                    .parse()
                    .map_err(|_| SError::SocksError("invalid port".into()))?;
                (host.to_string(), port)
            }
            _ => (authority.to_string(), 80),
        }
    };

    if host.is_empty() {
        return Err(SError::SocksError("missing host".into()));
    }

    Ok(ParsedHttpUri {
        host,
        port,
        path_and_query: path_and_query.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_users() -> Vec<ProxyBasicAuth> {
        vec![ProxyBasicAuth {
            username: "myuser".into(),
            password: "mypass".into(),
        }]
    }

    fn make_request(auth_header: &str) -> String {
        format!(
            "GET http://example.com/ HTTP/1.1\r\n\
             Host: example.com\r\n\
             {}\r\n\
             \r\n",
            auth_header
        )
    }

    #[test]
    fn basic_auth_standard_case() {
        let creds = STANDARD.encode(b"myuser:mypass");
        let req = make_request(&format!("Proxy-Authorization: Basic {}", creds));
        assert!(check_proxy_basic_auth(&req, &make_users()));
    }

    #[test]
    fn basic_auth_lowercase() {
        let creds = STANDARD.encode(b"myuser:mypass");
        let req = make_request(&format!("Proxy-Authorization: basic {}", creds));
        assert!(check_proxy_basic_auth(&req, &make_users()));
    }

    #[test]
    fn basic_auth_uppercase() {
        let creds = STANDARD.encode(b"myuser:mypass");
        let req = make_request(&format!("Proxy-Authorization: BASIC {}", creds));
        assert!(check_proxy_basic_auth(&req, &make_users()));
    }

    #[test]
    fn basic_auth_mixed_case() {
        let creds = STANDARD.encode(b"myuser:mypass");
        let req = make_request(&format!("Proxy-Authorization: bAsIc {}", creds));
        assert!(check_proxy_basic_auth(&req, &make_users()));
    }

    #[test]
    fn basic_auth_wrong_credentials() {
        let creds = STANDARD.encode(b"myuser:wrong");
        let req = make_request(&format!("Proxy-Authorization: Basic {}", creds));
        assert!(!check_proxy_basic_auth(&req, &make_users()));
    }

    #[test]
    fn basic_auth_no_header() {
        let req = make_request("X-Other: value");
        assert!(!check_proxy_basic_auth(&req, &make_users()));
    }

    #[test]
    fn basic_auth_unsupported_scheme() {
        let creds = STANDARD.encode(b"myuser:mypass");
        let req = make_request(&format!("Proxy-Authorization: Bearer {}", creds));
        assert!(!check_proxy_basic_auth(&req, &make_users()));
    }
}

fn make_socks_addr(host: &str, port: u16) -> Result<SocksAddr, SError> {
    let addr = if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        AddrOrDomain::V4(v4.octets())
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        AddrOrDomain::V6(v6.octets())
    } else {
        AddrOrDomain::Domain(host.as_bytes().to_vec().into())
    };

    Ok(SocksAddr { addr, port })
}
