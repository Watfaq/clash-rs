use ipnet::IpNet;
use std::{io, ptr::null_mut};
use tracing::{error, info};
use windows::Win32::{
    Foundation::{GetLastError, ERROR_SUCCESS},
    NetworkManagement::Rras::{
        RtmAddNextHop, RtmAddRouteToDest, RtmDeregisterEntity, RtmRegisterEntity,
        RtmReleaseNextHops, RTM_ENTITY_ID, RTM_ENTITY_ID_0, RTM_ENTITY_ID_0_0,
        RTM_ENTITY_INFO, RTM_NET_ADDRESS, RTM_NEXTHOP_INFO, RTM_REGN_PROFILE,
        RTM_ROUTE_CHANGE_NEW, RTM_ROUTE_INFO, RTM_VIEW_MASK_MCAST,
        RTM_VIEW_MASK_UCAST,
    },
    Networking::WinSock::{AF_INET, AF_INET6, PROTO_IP_RIP},
};

use crate::{common::errors::new_io_error, defer, proxy::utils::OutboundInterface};

const PROTO_TYPE_UCAST: u32 = 0;
const PROTO_VENDOR_ID: u32 = 0xFFFF;
#[inline]
fn protocol_id(typ: u32, vendor_id: u32, protocol_id: u32) -> u32 {
    ((typ & 0x03) << 30) | ((vendor_id & 0x3FFF) << 16) | (protocol_id & 0xFFFF)
}

pub fn add_route(via: &OutboundInterface, dest: &IpNet) -> io::Result<()> {
    let cmd = format!(
        "route add {} mask {} {} if {}",
        dest.addr(),
        dest.netmask(),
        via.addr_v4.expect("tun interface has no ipv4 address"),
        via.index,
    );

    info!("executing: {}", cmd);

    let output = std::process::Command::new("cmd")
        .args(["/C", &cmd])
        .output()
        .map_err(|e| new_io_error(e.to_string().as_str()))?;

    if output.status.success() {
        info!("{} is now routed through {}", dest, via.name);
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&output.stderr);
        error!("failed to add route: {}", err);
        Err(new_io_error(err.to_string().as_str()))
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
