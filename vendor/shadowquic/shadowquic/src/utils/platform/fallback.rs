use socket2::Socket;
use std::io;

pub fn bind_device(_socket: &Socket, _device_name: &str) -> io::Result<()> {
    tracing::warn!("bind interface not supported on this platform");
    Ok(())
}
