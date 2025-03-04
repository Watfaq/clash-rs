use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum DNSMode {
    #[default]
    Normal,
    FakeIp,
    RedirHost,
}
