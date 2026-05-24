use std::io;

use crate::app::net::OutboundInterface;

pub(crate) fn must_bind_socket_on_interface(
    #[allow(unused_variables)] socket: &socket2::Socket,
    iface: &OutboundInterface,
    #[allow(unused_variables)] family: socket2::Domain,
) -> io::Result<()> {
    // SO_BINDTODEVICE needs CAP_NET_RAW; on Android the host handles routing.
    #[cfg(target_os = "android")]
    {
        let _ = (socket, iface);
        Ok(())
    }
    #[cfg(any(target_os = "fuchsia", target_os = "linux"))]
    {
        use tracing::error;
        socket
            .bind_device(Some(iface.name.as_bytes()))
            .inspect_err(|e| {
                error!("failed to bind socket to interface {}: {e}", iface.name);
            })
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    )))]
    {
        use crate::common::errors::new_io_error;
        Err(new_io_error(format!(
            "unsupported platform: {}",
            iface.name
        )))
    }
}
