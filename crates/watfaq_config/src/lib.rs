use watfaq_types::{Iface, StackPrefer};

#[derive(Default, Debug, Clone)]
pub struct OutboundCommonOptions {
    pub dialer: Option<String>,
    pub icon: Option<String>,
    pub interface: Option<Iface>,
    pub stack_prefer: Option<StackPrefer>,
}
