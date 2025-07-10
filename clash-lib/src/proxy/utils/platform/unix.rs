use std::io;

use crate::app::net::OutboundInterface;

#[allow(dead_code)]
pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &OutboundInterface,
    _family: socket2::Domain,
) -> io::Result<()> {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux",))]
    {
        socket.bind_device(Some(iface.name.as_bytes()))
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    )))]
    {
        use crate::common::errors::new_io_error;
        Err(new_io_error(format!("unsupported platform: {}", name)))
    }
}
