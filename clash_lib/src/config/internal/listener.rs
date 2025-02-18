use educe::Educe;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum InboundListener {
    #[serde(rename = "tunnel")]
    Tunnel(InboundTunnel),
}


#[derive(Serialize, Deserialize, Debug, Educe, Clone)]
#[educe(Default)]
#[serde(rename_all = "kebab-case")]
pub struct CommonConfigOptions {
    pub name: String,
    #[educe(Default = "127.0.0.1")]
    pub listen: String,
    #[educe(Default = 0)]
    pub port: u16,
    // TODO
    pub rule: Option<String>,
    pub proxy: Option<String>
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct InboundTunnel {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub network: Vec<String>,
    pub target: String
}