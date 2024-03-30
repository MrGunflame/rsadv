use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Ipv6Addr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Database {
    pub prefixes: Vec<Prefix>,
}

impl Database {
    pub fn load<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(path).map_err(Error::Io)?;

        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(Error::Io)?;

        bincode::deserialize(&buf).map_err(Error::Bincode)
    }

    pub fn save<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        let mut file = File::create(path).map_err(Error::Io)?;

        let buf = bincode::serialize(self).unwrap();
        file.write_all(&buf).map_err(Error::Io)?;

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Prefix {
    pub prefix: Ipv6Addr,
    pub prefix_length: u8,
    pub preferred: Lifetime,
    pub valid: Lifetime,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Lifetime {
    Duration(Duration),
    Until(SystemTime),
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Bincode(bincode::Error),
}
