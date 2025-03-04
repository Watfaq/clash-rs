use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use watfaq_types::{Iface, Stack, StackPrefer};

// TODO change function name
// 1. socket helper的new_tcp 与 new_udp 传入 用于覆盖全局的出口网卡，
//    远端地址的可空v4 + 可空v6，用户的v4v6偏好
// 2. 检查出口网卡的网络栈能力 仅支持v4，
//    bind到v4::UNSPECIFIED，但若远端v4空则panic
//    仅支持v6，bind到v6::UNSPECIFIED，但若远端v6空则panic
//    其他情况（出口支持双栈): 若v4v6 = 4、46 ，远端v4不为空 或 v4v6 = 64，
//    远端v6为空 则bind到v4::UNSPECIFIED connect到远端v4 若v4v6 = 6、64
//    ，远端v6不为空 或 v4v6 = 46， 远端v4为空 则bind到v6::UNSPECIFIED
//    connect到远端v6

impl From<&SocketAddr> for TargetStack {
    fn from(value: &SocketAddr) -> Self {
        match value {
            SocketAddr::V4(_) => Self(true, false),
            SocketAddr::V6(_) => Self(false, true),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TargetStack(bool, bool);

#[derive(Clone, Copy, Debug)]
pub struct StackCondition {
    iface_v4: bool,
    iface_v6: bool,
    stack_prefer: StackPrefer,
}

pub fn which_stack_decision(
    iface: &Iface,
    stack_prefer: StackPrefer,
    target: TargetStack,
) -> Option<Stack> {
    let (iface_v4, iface_v6) = (iface.ipv4.is_some(), iface.ipv6.is_some());
    let (target_v4, target_v6) = (target.0, target.1);

    // Check for incompatible single stack scenarios
    match (iface_v4, iface_v6) {
        (true, false) if !target_v4 => return None,
        (false, true) if !target_v6 => return None,
        _ => (),
    }

    // Decision logic based on stack preference
    match stack_prefer {
        StackPrefer::V4 if iface_v4 && target_v4 => Some(Stack::V4),
        StackPrefer::V6 if iface_v6 && target_v6 => Some(Stack::V6),
        StackPrefer::V4V6 => {
            if iface_v4 && target_v4 {
                Some(Stack::V4)
            } else if iface_v6 && target_v6 {
                Some(Stack::V6)
            } else {
                None
            }
        }

        StackPrefer::V6V4 => {
            if iface_v6 && target_v6 {
                Some(Stack::V6)
            } else if iface_v4 && target_v4 {
                Some(Stack::V4)
            } else {
                None
            }
        }

        _ => None,
    }
}
