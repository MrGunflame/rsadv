use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub interface: String,
    pub mtu: u32,
    pub dns: Ipv6Addr,
    pub db: String,
}
