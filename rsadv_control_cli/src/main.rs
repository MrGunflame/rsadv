use std::fmt::{self, Display, Formatter};
use std::net::{AddrParseError, Ipv6Addr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use clap::{Parser, Subcommand};
use rsadv_control::{Connection, DnsServer, Lifetime, Prefix, Request, CONTROL_SOCKET_ADDR};
use thiserror::Error;

#[derive(Clone, Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// The socket on which the server is listening.
    #[arg(long, default_value = CONTROL_SOCKET_ADDR)]
    socket: PathBuf,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Clone, Debug, Subcommand)]
enum Command {
    /// Manage IPv6 prefixes announced by the daemon.
    Prefix {
        #[command(subcommand)]
        cmd: PrefixCommand,
    },
    /// Manage default DNS servers announced by the daemon.
    Dns {
        #[command(subcommand)]
        cmd: DnsCommand,
    },
}

#[derive(Clone, Debug, Subcommand)]
enum PrefixCommand {
    /// Add a new prefix to be announced.
    Add { prefix: Ipv6Prefix },
    /// Remove a prefix that is being announced.
    Remove { prefix: Ipv6Prefix },
}

#[derive(Clone, Debug, Subcommand)]
enum DnsCommand {
    /// Add a new DNS server.
    Add {
        /// The address of the DNS server.
        addr: Ipv6Addr,
    },
    /// Remove an existing DNS server.
    Remove {
        /// The address of the DNS server.
        addr: Ipv6Addr,
    },
}

fn main() -> ExitCode {
    pretty_env_logger::init();
    let args = Args::parse();

    let mut conn = match Connection::new(&args.socket) {
        Ok(conn) => conn,
        Err(err) => {
            log::error!("failed to connect to socket: {}", err);
            return ExitCode::FAILURE;
        }
    };

    let res = match args.cmd {
        Command::Prefix { cmd } => match cmd {
            PrefixCommand::Add { prefix } => conn.send(Request::AddPrefix(Prefix {
                prefix: prefix.addr,
                prefix_length: prefix.len,
                preferred_lifetime: Lifetime::Duration(Duration::from_secs(3600)),
                valid_lifetime: Lifetime::Duration(Duration::from_secs(3600)),
            })),
            PrefixCommand::Remove { prefix } => conn.send(Request::RemovePrefix(Prefix {
                prefix: prefix.addr,
                prefix_length: prefix.len,
                preferred_lifetime: Lifetime::Duration(Duration::from_secs(3600)),
                valid_lifetime: Lifetime::Duration(Duration::from_secs(3600)),
            })),
        },
        Command::Dns { cmd } => match cmd {
            DnsCommand::Add { addr } => conn.send(Request::AddDnsServer(DnsServer {
                addr,
                lifetime: Lifetime::Duration(Duration::from_secs(3600)),
            })),
            DnsCommand::Remove { addr } => conn.send(Request::RemoveDnsServer(DnsServer {
                addr,
                lifetime: Lifetime::Duration(Duration::from_secs(3600)),
            })),
        },
    };

    match res {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            log::error!("failed to execute command: {}", err);
            ExitCode::FAILURE
        }
    }
}

#[derive(Clone, Debug, Error)]
enum ParseIpv6PrefixError {
    #[error("prefix has no length")]
    PrefixWithoutLength,
    #[error(transparent)]
    InvalidAddr(AddrParseError),
    #[error("invalid prefix length: {0}")]
    InvalidPrefixLength(std::num::ParseIntError),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
struct Ipv6Prefix {
    addr: Ipv6Addr,
    len: u8,
}

impl FromStr for Ipv6Prefix {
    type Err = ParseIpv6PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (lhs, rhs) = s
            .split_once("/")
            .ok_or(ParseIpv6PrefixError::PrefixWithoutLength)?;

        let addr = lhs.parse().map_err(ParseIpv6PrefixError::InvalidAddr)?;
        let len = rhs
            .parse()
            .map_err(ParseIpv6PrefixError::InvalidPrefixLength)?;

        Ok(Self { addr, len })
    }
}

impl Display for Ipv6Prefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}
