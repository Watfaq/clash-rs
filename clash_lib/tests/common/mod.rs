use futures::TryFutureExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::net::{Shutdown, TcpStream};

pub fn start_clash(options: clash_lib::Options) -> Result<(), clash_lib::Error> {
    clash_lib::start_scaffold(options)
}

pub fn wait_port_ready(port: u16) -> Result<(), clash_lib::Error> {
    let addr = format!("127.0.0.1:{}", port);
    let mut attempts = 0;
    while attempts < 30 {
        if let Ok(stream) = TcpStream::connect(&addr) {
            stream.shutdown(Shutdown::Both).ok();
            return Ok(());
        }
        attempts += 1;
        // it may take some time for downloading the mmdbs
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    Err(clash_lib::Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Port {} is not ready after 10 attempts", port),
    )))
}

/// Sends an HTTP request to the specified URL using a TCP connection.
/// Don't use any domain name in the URL, which will trigger DNS resolution.
/// And libnss_files will likely cause a coredump(in static crt build).
/// TODO: Use a DNS resolver to resolve the domain name in the URL.
pub async fn send_http_request<T>(
    url: hyper::Uri,
    req: hyper::Request<T>,
) -> std::io::Result<http::Response<Incoming>>
where
    T: hyper::body::Body + Send + 'static,
    <T as hyper::body::Body>::Data: Send,
    <T as hyper::body::Body>::Error: Sync + Send + std::error::Error,
{
    let host = url.host().expect("uri has no host");
    let port = url.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);

    let stream = tokio::net::TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to establish connection: {}", e),
            )
        })
        .await?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let res = sender
        .send_request(req)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to send request: {}", e),
            )
        })
        .await?;

    Ok(res)
}
