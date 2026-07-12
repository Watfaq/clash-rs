use socket2::Socket;
use std::io;

pub fn bind_device(socket: &Socket, device_name: &str) -> io::Result<()> {
    socket.bind_device(Some(device_name.as_bytes()))
}
