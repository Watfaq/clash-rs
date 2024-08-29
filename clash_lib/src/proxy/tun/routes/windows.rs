use ipnet::IpNet;
use network_interface::NetworkInterfaceConfig;
use std::{
    f32::INFINITY,
    io,
    net::SocketAddr,
    os::windows::{io::AsRawSocket, raw::HANDLE},
    ptr::null_mut,
};
use tracing::{error, info, trace, warn};
use windows::Win32::{
    Foundation::{GetLastError, ERROR_SUCCESS},
    NetworkManagement::Rras::{
        RtmAddNextHop, RtmAddRouteToDest, RtmRegisterEntity, RtmReleaseNextHops,
        RTM_ENTITY_INFO, RTM_NET_ADDRESS, RTM_NEXTHOP_INFO, RTM_REGN_PROFILE,
        RTM_ROUTE_CHANGE_NEW, RTM_ROUTE_INFO, RTM_VIEW_MASK_MCAST,
        RTM_VIEW_MASK_UCAST,
    },
    Networking::WinSock::{
        setsockopt, AF_INET, AF_INET6, IPPROTO_IP, IPPROTO_IPV6, IP_UNICAST_IF,
        PROTO_IP_RIP, SOCKET,
    },
};

use crate::{
    common::errors::new_io_error,
    proxy::{utils::OutboundInterface, Interface},
};

const PROTO_TYPE_UCAST: u32 = 0;
const PROTO_VENDOR_ID: u32 = 0xFFFF;
#[inline]
fn protocol_id(typ: u32, vendor_id: u32, protocol_id: u32) -> u32 {
    ((typ & 0x03) << 30) | ((vendor_id & 0x3FFF) << 16) | (protocol_id & 0xFFFF)
}

pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> io::Result<()> {
    let address_family = match dest {
        IpNet::V4(_) => AF_INET,
        IpNet::V6(_) => AF_INET6,
    };

    let rtm_reg_handle: HANDLE = null_mut();
    let mut rtm_entity_info = RTM_ENTITY_INFO::default();
    let mut rtm_regn_profile = RTM_REGN_PROFILE::default();

    rtm_entity_info.RtmInstanceId = 0;
    rtm_entity_info.AddressFamily = address_family.0;
    rtm_entity_info
        .EntityId
        .Anonymous
        .Anonymous
        .EntityProtocolId = PROTO_IP_RIP.0.try_into().unwrap();
    rtm_entity_info
        .EntityId
        .Anonymous
        .Anonymous
        .EntityInstanceId = protocol_id(
        PROTO_TYPE_UCAST,
        PROTO_VENDOR_ID,
        PROTO_IP_RIP.0.try_into().unwrap(),
    );
    let rv = unsafe {
        RtmRegisterEntity(
            &mut rtm_entity_info,
            null_mut(),
            None,
            false,
            &mut rtm_regn_profile,
            rtm_reg_handle as *mut _,
        )
    };

    if rv != ERROR_SUCCESS.0 {
        let err = unsafe { GetLastError().to_hresult().message() };
        error!("failed to register entity: {}", err);
        return Err(new_io_error(err));
    }

    let mut next_hop_info = RTM_NEXTHOP_INFO::default();

    next_hop_info.InterfaceIndex = via.index;
    next_hop_info.NextHopAddress = RTM_NET_ADDRESS {
        AddressFamily: address_family.0,
        NumBits: dest.prefix_len() as u16,
        AddrBits: match dest {
            IpNet::V4(ip) => ip.addr().to_ipv6_compatible().octets(),
            IpNet::V6(ip) => ip.addr().octets(),
        },
    };

    let next_hop_handle: HANDLE = null_mut();
    let mut change_flags = 0u32;

    let status = unsafe {
        RtmAddNextHop(
            rtm_reg_handle as _,
            &mut next_hop_info,
            next_hop_handle as *mut _,
            &mut change_flags,
        )
    };

    if status != ERROR_SUCCESS.0 {
        let err = unsafe { GetLastError().to_hresult().message() };
        error!("failed to add next hop: {}", err);
        return Err(new_io_error(err));
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
    route_info.Neighbour = next_hop_handle as _;
    route_info.PrefInfo.Metric = 1;
    route_info.BelongsToViews = RTM_VIEW_MASK_UCAST | RTM_VIEW_MASK_MCAST;
    route_info.NextHopsList.NumNextHops = 1;
    route_info.NextHopsList.NextHops[0] = next_hop_handle as _;

    let mut change_flags = RTM_ROUTE_CHANGE_NEW;

    let rv = unsafe {
        RtmAddRouteToDest(
            rtm_reg_handle as _,
            null_mut() as _,
            &mut net_address,
            &mut route_info,
            INFINITY as _,
            0,
            0,
            0,
            &mut change_flags,
        )
    };

    unsafe {
        RtmReleaseNextHops(rtm_reg_handle as _, 1, next_hop_handle as _);
    }

    if rv == ERROR_SUCCESS.0 {
        info!("{} is now routed through {}", dest, via.name);
    } else {
        let err = unsafe { GetLastError().to_hresult().message() };
        error!("failed to add route: {}", err);
        return Err(new_io_error(err));
    }

    Ok(())
}
