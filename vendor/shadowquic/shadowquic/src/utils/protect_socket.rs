use std::{
    future,
    io::{self, ErrorKind},
    os::fd::RawFd,
    path::Path,
    task::{Poll, ready},
};

use sendfd::SendWithFd;
use tokio::{io::AsyncReadExt, net::UnixStream};

/// protect socket from loop back on Android
pub async fn protect_socket<P: AsRef<Path>>(path: P, fd: RawFd) -> io::Result<()> {
    let mut stream = UnixStream::connect(path).await?;
    let dummy = [0u8];
    send_with_fd(&stream, &dummy, &[fd]).await?;
    // receive the return value
    let mut response = [0; 1];
    stream.read_exact(&mut response).await?;

    if response[0] == 0xFF {
        return Err(io::Error::other("protect socket failed"));
    }

    Ok(())
}
pub async fn protect_socket_with_retry<P: AsRef<Path>>(path: P, fd: RawFd) -> io::Result<()> {
    let mut out = Ok(());
    for delay in [0, 100, 300, 800] {
        tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
        out = protect_socket(path.as_ref(), fd).await;
        if out.is_ok() {
            break;
        }
    }
    out
}

/// Send data with file descriptors
pub async fn send_with_fd(stream: &UnixStream, buf: &[u8], fds: &[RawFd]) -> io::Result<usize> {
    future::poll_fn(|cx| {
        loop {
            ready!(stream.poll_write_ready(cx))?;

            match stream.send_with_fd(buf, fds) {
                Err(ref err) if err.kind() == ErrorKind::WouldBlock => {}
                x => return Poll::Ready(x),
            }
        }
    })
    .await
}
