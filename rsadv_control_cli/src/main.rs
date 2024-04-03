use std::env::args;
use std::net::Ipv6Addr;
use std::time::Duration;

use rsadv_control::{Connection, DnsServer, Lifetime, Prefix, Request};

fn main() {
    let mut args: Vec<String> = args().collect();

    let mut conn = match Connection::new() {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!("unable to connect to socket: {}", err);
            std::process::exit(1);
        }
    };

    match args.get(1).map(|s| s.as_str()) {
        Some("prefix") => match args.get(2).map(|s| s.as_str()) {
            Some("add") => {
                let prefix = args.get(3).unwrap();
                let (prefix, prefix_length) = prefix.split_once("/").unwrap();
                let prefix: Ipv6Addr = prefix.parse().unwrap();
                let prefix_length: u8 = prefix_length.parse().unwrap();

                conn.send(Request::AddPrefix(Prefix {
                    prefix,
                    prefix_length,
                    preferred_lifetime: Lifetime::Duration(Duration::from_secs(3600)),
                    valid_lifetime: Lifetime::Duration(Duration::from_secs(3600)),
                }))
                .unwrap();
            }
            Some("rm") | Some("del") => {
                let prefix = args.get(3).unwrap();
                let (prefix, prefix_length) = prefix.split_once("/").unwrap();
                let prefix: Ipv6Addr = prefix.parse().unwrap();
                let prefix_length: u8 = prefix_length.parse().unwrap();

                conn.send(Request::RemovePrefix(Prefix {
                    prefix,
                    prefix_length,
                    preferred_lifetime: Lifetime::Duration(Duration::from_secs(3600)),
                    valid_lifetime: Lifetime::Duration(Duration::from_secs(3600)),
                }))
                .unwrap();
            }
            _ => {
                eprintln!("Invalid prefix action");
                std::process::exit(1);
            }
        },
        Some("dns") => match args.get(2).map(|s| s.as_str()) {
            Some("add") => {
                let addr = args.get(3).unwrap();
                let addr: Ipv6Addr = addr.parse().unwrap();

                conn.send(Request::AddDnsServer(DnsServer {
                    addr,
                    lifetime: Lifetime::Duration(Duration::from_secs(3600)),
                }))
                .unwrap();
            }
            Some("rm") | Some("del") => {
                let addr = args.get(3).unwrap();
                let addr: Ipv6Addr = addr.parse().unwrap();

                conn.send(Request::RemoveDnsServer(DnsServer {
                    addr,
                    lifetime: Lifetime::Duration(Duration::from_secs(3600)),
                }))
                .unwrap();
            }
            _ => {
                eprintln!("invalid dns action");
                std::process::exit(1);
            }
        },
        Some(_) | None => {
            eprintln!("No command given; possible are prefix, dns");
            std::process::exit(1);
        }
    }
}
