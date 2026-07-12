use socket2::Socket;
use std::io;
use std::os::windows::io::AsRawSocket;
use windows::Win32::Networking::WinSock::{
    IP_MULTICAST_IF, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_MULTICAST_IF, IPV6_UNICAST_IF,
    SOCKET, setsockopt,
};
use windows::core::PCSTR;

pub fn bind_device(socket: &Socket, device_name: &str) -> io::Result<()> {
    let c_device_name = std::ffi::CString::new(device_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let pcstr = PCSTR::from_raw(c_device_name.as_ptr() as *const u8);
    let idx = unsafe { windows::Win32::NetworkManagement::IpHelper::if_nametoindex(pcstr) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }

    let handle = SOCKET(socket.as_raw_socket() as usize);
    let is_udp = socket
        .r#type()
        .map(|t| t == socket2::Type::DGRAM)
        .unwrap_or(false);
    let is_ipv6 = socket
        .local_addr()
        .map(|addr| addr.is_ipv6())
        .unwrap_or(false);

    if is_ipv6 {
        // Bind IPv6 unicast option
        let errno = unsafe {
            setsockopt(
                handle,
                IPPROTO_IPV6.0,
                IPV6_UNICAST_IF,
                Some(idx.to_ne_bytes().as_ref()),
            )
        };
        if errno != 0 {
            let last_err = io::Error::last_os_error();
            tracing::error!(
                "bind socket to interface (IPv6 Unicast) failed, errno: {}, err: {:?}",
                errno,
                last_err
            );
            return Err(last_err);
        }

        // Bind IPv6 multicast option
        if is_udp {
            let errno = unsafe {
                setsockopt(
                    handle,
                    IPPROTO_IPV6.0,
                    IPV6_MULTICAST_IF,
                    Some(idx.to_ne_bytes().as_ref()),
                )
            };
            if errno != 0 {
                let last_err = io::Error::last_os_error();
                tracing::error!(
                    "bind socket to interface (IPv6 Multicast) failed, errno: {}, err: {:?}",
                    errno,
                    last_err
                );
                return Err(last_err);
            }
        }

        // Try bind dual-stack IPv4 unicast option
        // (Don't fail if the socket is IPv6-only)
        let _ = unsafe {
            setsockopt(
                handle,
                IPPROTO_IP.0,
                IP_UNICAST_IF,
                Some(idx.to_be_bytes().as_ref()),
            )
        };
        if is_udp {
            let _ = unsafe {
                setsockopt(
                    handle,
                    IPPROTO_IP.0,
                    IP_MULTICAST_IF,
                    Some(idx.to_be_bytes().as_ref()),
                )
            };
        }
    } else {
        // Bind IPv4 unicast option
        let errno = unsafe {
            setsockopt(
                handle,
                IPPROTO_IP.0,
                IP_UNICAST_IF,
                Some(idx.to_be_bytes().as_ref()),
            )
        };
        if errno != 0 {
            let last_err = io::Error::last_os_error();
            tracing::error!(
                "bind socket to interface (IPv4 Unicast) failed, errno: {}, err: {:?}",
                errno,
                last_err
            );
            return Err(last_err);
        }

        // Bind IPv4 multicast option
        if is_udp {
            let errno = unsafe {
                setsockopt(
                    handle,
                    IPPROTO_IP.0,
                    IP_MULTICAST_IF,
                    Some(idx.to_be_bytes().as_ref()),
                )
            };
            if errno != 0 {
                let last_err = io::Error::last_os_error();
                tracing::error!(
                    "bind socket to interface (IPv4 Multicast) failed, errno: {}, err: {:?}",
                    errno,
                    last_err
                );
                return Err(last_err);
            }
        }
    }

    Ok(())
}
