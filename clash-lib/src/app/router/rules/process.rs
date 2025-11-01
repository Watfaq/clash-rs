use super::RuleMatcher;
use crate::session::Network;

pub struct Process {
    pub name: String,
    pub target: String,
    #[allow(dead_code)]
    pub name_only: bool,
}

impl std::fmt::Display for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} process {}", self.target, self.name)
    }
}

impl RuleMatcher for Process {
    fn apply(&self, sess: &crate::session::Session) -> bool {
        #[cfg(not(windows))]
        {
            use tracing::debug;

            sock2proc::find_process_name(
                Some(sess.source),
                sess.destination.clone().try_into_socket_addr(),
                match sess.network {
                    Network::Tcp => sock2proc::NetworkProtocol::TCP,
                    Network::Udp => sock2proc::NetworkProtocol::UDP,
                },
            )
            .is_some_and(|proc| {
                debug!("Matching process name: {} with {}", proc, self.name);
                if self.name_only {
                    proc == self.name
                } else {
                    proc.contains(&self.name)
                }
            })
        }
        #[cfg(windows)]
        {
            use tracing::info;

            info!("PROCESS-NAME not supported on Windows yet");
            false
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.name.clone()
    }

    fn type_name(&self) -> &str {
        "Process"
    }
}
