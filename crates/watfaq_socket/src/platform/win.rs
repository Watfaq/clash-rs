use std::{net::IpAddr, os::windows::io::AsRawSocket};
use tracing::debug;
use watfaq_error::{Result, anyhow};
use watfaq_types::{Iface, Stack};
use windows::Win32::{
    Foundation::GetLastError,
    Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, SOCKET, setsockopt,
    },
};

pub(crate) fn bind_iface(
    socket: &socket2::Socket,
    iface: &Iface,
    stack: Stack,
) -> Result<()> {
    let ip: IpAddr = match stack {
        Stack::V4 => iface
            .ipv4
            .ok_or(anyhow!("IPv4 is not supported on interface {}", iface.name))?
            .into(),
        Stack::V6 => iface
            .ipv6
            .ok_or(anyhow!("IPv6 is not supported on interface {}", iface.name))?
            .into(),
    };

    debug!(
        "binding socket to interface: {}, index {}, ip(suppose) {:?}",
        iface.name, iface.index, ip
    );

    let handle = SOCKET(socket.as_raw_socket().try_into().unwrap());
    let bind_result = unsafe {
        setsockopt(
            handle,
            match stack {
                Stack::V4 => IPPROTO_IP.0,
                Stack::V6 => IPPROTO_IPV6.0,
            },
            IP_UNICAST_IF,
            Some(iface.index.to_be_bytes().as_ref()),
        )
    };
    if bind_result != 0 {
        let err = unsafe { GetLastError().to_hresult().message() };

        return Err(anyhow!("bind socket to interface failed: {err}"));
    }
    Ok(())
}
