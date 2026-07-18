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
    // FreeBSD has no SO_BINDTODEVICE equivalent. Outbound-interface binding for
    // the tun-mode loop-avoidance scheme is handled instead by per-process /
    // per-socket FIBs (see proxy/tun/routes/freebsd.rs): when route_all is
    // enabled the whole clash process is moved to a bypass FIB via setfib(2),
    // so any socket clash opens is already routed by the physical default
    // gateway and would only loop back into the tun if we tried to bind to the
    // physical interface here. Therefore interface binding is a no-op on
    // FreeBSD.
    #[cfg(target_os = "freebsd")]
    {
        let _ = (socket, iface, family);
        Ok(())
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "freebsd",
    )))]
    {
        use crate::common::errors::new_io_error;
        Err(new_io_error(format!(
            "unsupported platform: {}",
            iface.name
        )))
    }
}