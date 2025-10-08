use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub interface: String,
    pub mtu: u32,
    pub db: String,
    pub min_rtr_adv_interval: u64,
    pub max_rtr_adv_interval: u64,
    pub announce_on_exit: bool,
}

impl Config {
    pub fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(path)?;

        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let s = std::str::from_utf8(&buf)?;
        Ok(toml::from_str(s)?)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Str(#[from] std::str::Utf8Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
}
