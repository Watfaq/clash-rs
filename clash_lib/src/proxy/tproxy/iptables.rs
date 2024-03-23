use cmd_lib::run_cmd;
use std::process::Command;
use tracing::{debug, error};

#[derive(Debug, Clone, Copy)]
pub enum TProxyStrategy {
    Nftables,
    Iptables,
    None,
}

impl From<&str> for TProxyStrategy {
    fn from(s: &str) -> Self {
        match s {
            "nft" => TProxyStrategy::Nftables,
            "iptables" => TProxyStrategy::Iptables,
            _ => TProxyStrategy::None,
        }
    }
}

impl TProxyStrategy {
    pub fn setup(
        &self,
        skip_mark: u32,
        tproxy_port: u16,
        output_chain_name: Option<&str>,
        prerouting_chain_name: Option<&str>,
    ) {
        match self {
            TProxyStrategy::Nftables => {
                // TODO: support nft
            }
            TProxyStrategy::Iptables => {
                setup_iptables_tproxy(
                    skip_mark,
                    tproxy_port,
                    output_chain_name,
                    prerouting_chain_name,
                );
            }
            TProxyStrategy::None => {
                error!("No tproxy command found");
            }
        }
    }
}

impl Default for TProxyStrategy {
    // auto detect command in system
    fn default() -> Self {
        if command_exists("nft") {
            TProxyStrategy::Nftables
        } else if command_exists("iptables") {
            TProxyStrategy::Iptables
        } else {
            TProxyStrategy::None
        }
    }
}
#[derive(Debug)]
pub struct TProxyGuard {
    strategy: TProxyStrategy,
    skip_mark: u32,
    tproxy_port: u16,
    output_chain_name: Option<String>,
    prerouting_chain_name: Option<String>,
}

impl TProxyGuard {
    pub fn new(
        strategy: TProxyStrategy,
        skip_mark: u32,
        tproxy_port: u16,
        output_chain_name: Option<String>,
        prerouting_chain_name: Option<String>,
    ) -> Self {
        // clean before setup
        clean_iptables_tproxy(
            output_chain_name.as_deref(),
            prerouting_chain_name.as_deref(),
        );
        strategy.setup(
            skip_mark,
            tproxy_port,
            output_chain_name.as_deref(),
            prerouting_chain_name.as_deref(),
        );
        Self {
            strategy,
            skip_mark,
            tproxy_port,
            output_chain_name,
            prerouting_chain_name,
        }
    }
}

impl Drop for TProxyGuard {
    fn drop(&mut self) {
        match self.strategy {
            TProxyStrategy::Nftables => {
                // TODO: support nft
            }
            TProxyStrategy::Iptables => {
                clean_iptables_tproxy(
                    self.output_chain_name.as_deref(),
                    self.prerouting_chain_name.as_deref(),
                );
            }
            TProxyStrategy::None => {}
        }
    }
}

fn command_exists(command: &str) -> bool {
    Command::new(command).arg("-v").output().is_ok()
}

const DEFAULT_OUTPUT_DIVERT_CHAIN: &str = "CLASH_RS_TPROXY_OUTPUT_DIVERT";
const DEFAULT_OUTPUT_CHAIN: &str = "CLASH_RS_TPROXY_OUTPUT";
const DEFAULT_PREROUTING_CHAIN: &str = "CLASH_RS_TPROXY_PREROUTING";
const POLICY_ROUTING_TABLE_NUM: u32 = 400;
const DEFAULT_TPROXY_MARK: u32 = 0x1;
const DEFAULT_TPROXY_MARK_MUSK: &str = "0x1/0x1";

// TODO: handle corner cases in iptables' rules
pub fn setup_iptables_tproxy(
    skip_mark: u32,
    tproxy_port: u16,
    output_chain_name: Option<&str>,
    prerouting_chain_name: Option<&str>,
) {
    let divert_chain_name = DEFAULT_OUTPUT_DIVERT_CHAIN;
    let output_chain_name = output_chain_name.unwrap_or(DEFAULT_OUTPUT_CHAIN);
    let prerouting_chain_name = prerouting_chain_name.unwrap_or(DEFAULT_PREROUTING_CHAIN);

    debug!(
        "clean iptables tproxy, policy_routing_table_num: {}, tproxy_mark: {}, output_chain_name: {}, prerouting_chain_name: {}",
        POLICY_ROUTING_TABLE_NUM, DEFAULT_TPROXY_MARK, output_chain_name, prerouting_chain_name
    );

    run_cmd!(ip rule add fwmark $DEFAULT_TPROXY_MARK lookup $POLICY_ROUTING_TABLE_NUM);
    run_cmd!(ip route add local "0.0.0.0/0" dev lo table $POLICY_ROUTING_TABLE_NUM);

    // re-route the packet flow to the local listener by cooperating with `ip rule`'s fwmark
    // to avoid the infinite loop
    run_cmd!(iptables "-t" mangle "-N" $output_chain_name);
    run_cmd!(iptables "-t" mangle "-F" $output_chain_name);
    run_cmd!(iptables "-t" mangle "-A" $output_chain_name "-j" RETURN "-m" mark "--mark" $skip_mark);
    run_cmd!(iptables "-t" mangle "-A" $output_chain_name "-m" addrtype "--dst-type" LOCAL "-j" RETURN);
    run_cmd!(iptables "-t" mangle "-A" $output_chain_name "-m" addrtype "--dst-type" BROADCAST "-j" RETURN);
    // dig example.com => 93.184.216.34
    run_cmd!(iptables "-t" mangle "-A" $output_chain_name "-p" tcp "--dst" "93.184.216.34" "--dport" 80 "-j" MARK "--set-mark" $DEFAULT_TPROXY_MARK);
    run_cmd!(iptables "-t" mangle "-A" $output_chain_name "-p" udp "--dst" "1.0.0.1" "--dport" 53 -j MARK "--set-mark" $DEFAULT_TPROXY_MARK);
    run_cmd!(iptables "-t" mangle "-A" OUTPUT -p tcp "-j" $output_chain_name);
    run_cmd!(iptables "-t" mangle "-A" OUTPUT -p udp "-j" $output_chain_name);

    // for optimization of tcp
    run_cmd!(iptables "-t" mangle "-N" $divert_chain_name);
    run_cmd!(iptables "-t" mangle "-F" $divert_chain_name);
    run_cmd!(iptables "-t" mangle "-A" $divert_chain_name "-j" MARK "--set-mark" $DEFAULT_TPROXY_MARK);
    run_cmd!(iptables "-t" mangle "-A" $divert_chain_name "-j" ACCEPT);

    // to catch the output socket to the listening socket on port 7893
    run_cmd!(iptables "-t" mangle "-N" $prerouting_chain_name);
    run_cmd!(iptables "-t" mangle "-F" $prerouting_chain_name);
    run_cmd!(iptables "-t" mangle "-A" $prerouting_chain_name "-m" addrtype "--dst-type" LOCAL "-j" RETURN);
    run_cmd!(iptables "-t" mangle "-A" $prerouting_chain_name "-m" mark "--mark" $skip_mark "-j" RETURN);
    run_cmd!(iptables "-t" mangle "-A" $prerouting_chain_name "-p" tcp "-m" socket "-j" divert_chain_name);

    run_cmd!(iptables "-t" mangle "-A" $prerouting_chain_name "-p" tcp "--dst" "93.184.216.34" "--dport" 80 "-j" TPROXY "--tproxy-mark" $DEFAULT_TPROXY_MARK_MUSK "--on-port" $tproxy_port);
    run_cmd!(iptables "-t" mangle "-A" $prerouting_chain_name "-p" udp "--dst" "1.0.0.1" "--dport" 53 "-j" TPROXY "--tproxy-mark" $DEFAULT_TPROXY_MARK_MUSK "--on-port" $tproxy_port);
    run_cmd!(iptables "-t" mangle "-A" PREROUTING "-p" tcp "-j" $prerouting_chain_name);
    run_cmd!(iptables "-t" mangle "-A" PREROUTING "-p" udp "-j" $prerouting_chain_name);
}

pub fn clean_iptables_tproxy(output_chain_name: Option<&str>, prerouting_chain_name: Option<&str>) {
    let output_chain_name = output_chain_name.unwrap_or(DEFAULT_OUTPUT_CHAIN);
    let prerouting_chain_name = prerouting_chain_name.unwrap_or(DEFAULT_PREROUTING_CHAIN);
    debug!(
        "clean iptables tproxy, policy_routing_table_num: {}, tproxy_mark: {}, output_chain_name: {}, prerouting_chain_name: {}",
        POLICY_ROUTING_TABLE_NUM, DEFAULT_TPROXY_MARK, output_chain_name, prerouting_chain_name
    );
    run_cmd!(ip rule del fwmark $DEFAULT_TPROXY_MARK lookup $POLICY_ROUTING_TABLE_NUM);
    run_cmd!(ip route flush table $POLICY_ROUTING_TABLE_NUM);

    run_cmd!(iptables "-t" mangle "-D" OUTPUT "-j" $output_chain_name);
    run_cmd!(iptables "-t" mangle "-F" $output_chain_name);
    run_cmd!(iptables "-t" mangle "-X" $output_chain_name);

    run_cmd!(iptables "-t" mangle "-D" PREROUTING "-j" $prerouting_chain_name);
    run_cmd!(iptables "-t" mangle "-F" $prerouting_chain_name);
    run_cmd!(iptables "-t" mangle "-X" $prerouting_chain_name);
}

#[test]
fn test_setup() {
    setup_iptables_tproxy(0xff, 7893, None, None);
}

#[test]
fn test_clean() {
    clean_iptables_tproxy(None, None);
}
