use ipnet::{IpNet, Ipv6Net};
use std::{
    io,
    mem::transmute_copy,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr::null_mut,
};
use tracing::{error, info};
use windows::{
    Win32::{
        Foundation::{ERROR_SUCCESS, GetLastError},
        NetworkManagement::{
            IpHelper::{
                CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
                DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
                DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, GetBestInterfaceEx,
                GetIfEntry2, IP_ADDRESS_PREFIX, InitializeIpForwardEntry,
                MIB_IF_ROW2, MIB_IPFORWARD_ROW2, MIB_UNICASTIPADDRESS_ROW,
                SetInterfaceDnsSettings,
            },
            Rras::{
                RTM_ENTITY_ID, RTM_ENTITY_ID_0, RTM_ENTITY_ID_0_0, RTM_ENTITY_INFO,
                RTM_NET_ADDRESS, RTM_NEXTHOP_INFO, RTM_REGN_PROFILE,
                RTM_ROUTE_CHANGE_NEW, RTM_ROUTE_INFO, RTM_VIEW_MASK_MCAST,
                RTM_VIEW_MASK_UCAST, RtmAddNextHop, RtmAddRouteToDest,
                RtmDeregisterEntity, RtmRegisterEntity, RtmReleaseNextHops,
            },
        },
        Networking::WinSock::{
            AF_INET, AF_INET6, IpPrefixOriginManual, IpSuffixOriginManual,
            PROTO_IP_RIP, SOCKADDR_INET,
        },
    },
    core::{GUID, PWSTR},
};

use crate::{
    app::net::OutboundInterface, common::errors::new_io_error,
    config::internal::config::TunConfig, defer,
};

const PROTO_TYPE_UCAST: u32 = 0;
const PROTO_VENDOR_ID: u32 = 0xFFFF;
#[inline]
fn protocol_id(typ: u32, vendor_id: u32, protocol_id: u32) -> u32 {
    ((typ & 0x03) << 30) | ((vendor_id & 0x3FFF) << 16) | (protocol_id & 0xFFFF)
}

pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> io::Result<()> {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe {
        InitializeIpForwardEntry(&mut row);
    }

    row.InterfaceIndex = via.index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: SocketAddr::new(dest.addr(), 0).into(),
        PrefixLength: dest.prefix_len(),
    };
    // May be too harsh to set zero
    let metric = 0;
    let next_hop: SocketAddr = if dest.addr().is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    row.NextHop = next_hop.into();
    row.Metric = metric;

    unsafe { CreateIpForwardEntry2(&mut row) }
        .to_hresult()
        .ok()
        .map_err(new_io_error)
}

fn get_guid(iface: &OutboundInterface) -> Option<GUID> {
    let mut if_row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    if_row.InterfaceIndex = iface.index;

    let result = unsafe { GetIfEntry2(&mut if_row) }.to_hresult().ok();

    match result {
        Ok(_) => Some(if_row.InterfaceGuid),
        Err(e) => {
            error!(
                "failed to get interface row with index: {} due to {}",
                iface.index, e
            );
            None
        }
    }
}
// SetInterfaceDnsSettings()
// See https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings
pub fn set_dns_v4(
    iface: &OutboundInterface,
    name_servers: &Vec<Ipv4Addr>,
) -> anyhow::Result<()> {
    let mut dns_wstr = name_servers
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(",")
        .encode_utf16()
        .collect::<Vec<u16>>();
    dns_wstr.push(0); // ensure ending with null

    let dns_settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_NAMESERVER as u64,
        NameServer: PWSTR::from_raw(dns_wstr.as_mut_ptr()),
        ..Default::default()
    };

    let guid =
        get_guid(iface).ok_or(anyhow!("interface {} not found", iface.name))?;

    unsafe { SetInterfaceDnsSettings(guid, &dns_settings) }
        .to_hresult()
        .ok()
        .map_err(|e| anyhow::anyhow!(e))
}

// SetInterfaceDnsSettings()
// See https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings
pub fn set_dns_v6(
    iface: &OutboundInterface,
    name_servers: &Vec<Ipv6Addr>,
) -> anyhow::Result<()> {
    let mut dns_wstr = name_servers
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(",")
        .encode_utf16()
        .collect::<Vec<u16>>();
    dns_wstr.push(0); // ensure ending with null

    let dns_settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: (DNS_SETTING_NAMESERVER | DNS_SETTING_IPV6) as u64,
        NameServer: PWSTR::from_raw(dns_wstr.as_mut_ptr()),
        ..Default::default()
    };

    let guid =
        get_guid(iface).ok_or(anyhow!("interface {} not found", iface.name))?;

    unsafe { SetInterfaceDnsSettings(guid, &dns_settings) }
        .to_hresult()
        .ok()
        .map_err(|e| anyhow::anyhow!(e))
}

/// Adding ipv4/v6 address to the interface.
/// See https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createunicastipaddressentry
pub fn add_address(
    iface: &OutboundInterface,
    addr_net: IpNet,
) -> anyhow::Result<()> {
    let mut addr_inet = SOCKADDR_INET::default();
    match addr_net {
        IpNet::V4(ipv4_net) => {
            addr_inet.Ipv4.sin_family =
                windows::Win32::Networking::WinSock::ADDRESS_FAMILY(
                    AF_INET.0 as u16,
                );
            addr_inet.Ipv4.sin_addr.S_un.S_addr =
                u32::from_le_bytes(ipv4_net.addr().octets());
        }
        IpNet::V6(ipv6_net) => {
            addr_inet.Ipv6.sin6_family =
                windows::Win32::Networking::WinSock::ADDRESS_FAMILY(
                    AF_INET6.0 as u16,
                );
            addr_inet.Ipv6.sin6_addr.u.Byte = ipv6_net.addr().octets().into();
        }
    }

    let mut row: MIB_UNICASTIPADDRESS_ROW = Default::default();

    // Set the interface index
    row.InterfaceIndex = iface.index;

    // Copy the address
    row.Address = addr_inet;

    // Set prefix length (subnet mask equivalent for IPv6)
    row.OnLinkPrefixLength = addr_net.prefix_len();

    // Set address origin and suffix origin
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;

    // Set valid and preferred lifetimes (0xffffffff means infinite)
    row.ValidLifetime = 0xffffffff;
    row.PreferredLifetime = 0xffffffff;

    // Skip duplicate address detection
    row.SkipAsSource = false.into();

    unsafe {
        CreateUnicastIpAddressEntry(&mut row)
            .to_hresult()
            .ok()
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to add address to tun interface due to:{}",
                    e
                )
            })
    }
}
pub fn maybe_routes_clean_up(_: &TunConfig) -> std::io::Result<()> {
    Ok(())
}

/// Add a route to the routing table.
/// https://learn.microsoft.com/en-us/windows/win32/rras/add-and-update-routes-using-rtmaddroutetodest
/// FIXME: figure out why this doesn't work https://stackoverflow.com/questions/43632619/how-to-properly-use-rtmv2-and-rtmaddroutetodest
#[allow(dead_code)]
pub fn add_route_that_does_not_work(
    via: &OutboundInterface,
    dest: &IpNet,
) -> io::Result<()> {
    let address_family = match dest {
        IpNet::V4(_) => AF_INET,
        IpNet::V6(_) => AF_INET6,
    };

    let mut rtm_reg_handle: isize = 0;
    let mut rtm_entity_info = RTM_ENTITY_INFO::default();
    let mut rtm_regn_profile = RTM_REGN_PROFILE::default();

    rtm_entity_info.RtmInstanceId = 0;
    rtm_entity_info.AddressFamily = address_family.0;
    rtm_entity_info.EntityId = RTM_ENTITY_ID {
        Anonymous: RTM_ENTITY_ID_0 {
            Anonymous: RTM_ENTITY_ID_0_0 {
                EntityProtocolId: PROTO_IP_RIP.0.try_into().unwrap(),
                EntityInstanceId: protocol_id(
                    PROTO_TYPE_UCAST,
                    PROTO_VENDOR_ID,
                    PROTO_IP_RIP.0.try_into().unwrap(),
                ),
            },
        },
    };
    let rv = unsafe {
        RtmRegisterEntity(
            &mut rtm_entity_info,
            null_mut(),
            None,
            false,
            &mut rtm_regn_profile,
            &mut rtm_reg_handle,
        )
    };

    if rv != ERROR_SUCCESS.0 {
        let err = unsafe { GetLastError().to_hresult().message() };
        error!("failed to register entity: {}", err);
        return Err(new_io_error(err));
    }

    defer! {
        let rv = unsafe {RtmDeregisterEntity(rtm_reg_handle)};
        if rv != ERROR_SUCCESS.0 {
            let err = unsafe { GetLastError().to_hresult().message() };
            error!("failed to deregister entity: {}", err);
        }
    }

    let mut next_hop_info = RTM_NEXTHOP_INFO {
        InterfaceIndex: via.index,
        NextHopAddress: RTM_NET_ADDRESS {
            AddressFamily: AF_INET.0,
            NumBits: 32,
            AddrBits: via
                .addr_v4
                .expect("tun interface has no ipv4 address")
                .to_ipv6_compatible()
                .octets(),
        },
        ..Default::default()
    };

    let mut next_hop_handle: isize = 0;
    let mut change_flags = 0u32;

    let status = unsafe {
        RtmAddNextHop(
            rtm_reg_handle,
            &mut next_hop_info,
            &mut next_hop_handle,
            &mut change_flags,
        )
    };

    if status != ERROR_SUCCESS.0 {
        let err = unsafe { GetLastError().to_hresult().message() };
        error!("failed to add next hop: {}", err);
        return Err(new_io_error(err));
    }

    defer! {
        let mut next_hops = [next_hop_handle];
        let rv = unsafe {
            RtmReleaseNextHops(rtm_reg_handle, 1, next_hops.as_mut_ptr())
        };

        if rv != ERROR_SUCCESS.0 {
            let err = unsafe { GetLastError().to_hresult().message() };
            error!("failed to release next hop: {}", err);
        }
    }

    let mut route_info = RTM_ROUTE_INFO::default();
    let mut net_address = RTM_NET_ADDRESS {
        AddressFamily: address_family.0,
        NumBits: dest.prefix_len() as u16,
        AddrBits: match dest {
            IpNet::V4(ip) => ip.addr().to_ipv6_compatible().octets(),
            IpNet::V6(ip) => ip.addr().octets(),
        },
    };
    route_info.Neighbour = next_hop_handle;
    route_info.PrefInfo.Metric = 1;
    route_info.BelongsToViews = RTM_VIEW_MASK_UCAST | RTM_VIEW_MASK_MCAST;
    route_info.NextHopsList.NumNextHops = 1;
    route_info.NextHopsList.NextHops[0] = next_hop_handle;

    let mut change_flags = RTM_ROUTE_CHANGE_NEW;
    let rv = unsafe {
        RtmAddRouteToDest(
            rtm_reg_handle,
            null_mut() as _,
            &mut net_address,
            &mut route_info,
            f32::INFINITY as _,
            0,
            0,
            0,
            &mut change_flags,
        )
    };

    if rv == ERROR_SUCCESS.0 {
        info!("{} is now routed through {}", dest, via.name);
    } else {
        let err = unsafe { GetLastError().to_hresult().message() };
        error!("failed to add route: {}", err);
        return Err(new_io_error(err));
    }

    Ok(())
}
