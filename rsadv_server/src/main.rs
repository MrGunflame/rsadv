//! NDP: https://www.rfc-editor.org/rfc/rfc4861
//! NDP DNS: https://www.rfc-editor.org/rfc/rfc8106

mod config;
mod control;
mod database;
mod linux;
mod ndp;

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};

use config::Config;
use control::control_loop;
use database::Database;
use futures::{pin_mut, FutureExt};
use linux::Interface;
use ndp::{
    Encode, IcmpContent, IcmpOption, IcmpType, LinkLayerAddress, PrefixInformation,
    RecursiveDnsServer, RouterAdvertisement, RouterSolicitation,
};
use ragequit::SHUTDOWN;
use rand::distributions::Uniform;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use rsadv_control::Lifetime;
use rtnetlink::new_connection;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, Notify};

use crate::ndp::{Decode, IcmpPacket};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    pretty_env_logger::init();
    ragequit::init();

    let config = match Config::from_file("config.toml") {
        Ok(config) => config,
        Err(err) => {
            tracing::error!("failed to read config: {}", err);
            std::process::exit(1);
        }
    };

    // MaxRtrAdvInterval MUST be >= 4s && <= 1800s.
    let max_rtr_adv_interval = match Duration::from_secs(config.max_rtr_adv_interval) {
        v if v < Duration::from_secs(4) => {
            tracing::warn!("max_rtr_adv_interval is < 4s; defaulting to 4s");
            Duration::from_secs(4)
        }
        v if v > Duration::from_secs(1800) => {
            tracing::warn!("max_rtr_adv_interval is > 1800s; defaulting to 1800s");
            Duration::from_secs(1800)
        }
        v => v,
    };

    // MinRtrAdvInterval MUST be >= 3s && <= 0.75 * MaxRtrAdvInterval.
    let min_rtr_adv_interval = match Duration::from_secs(config.min_rtr_adv_interval) {
        // We use 0 as a "default" value.
        // Default is 0.33 * MaxRtrAdvInterval if MaxRtrAdvInterval >= 9 seconds,
        // otherwise default is MaxRtrAdvInterval.
        Duration::ZERO => {
            if max_rtr_adv_interval >= Duration::from_secs(9) {
                max_rtr_adv_interval / 3
            } else {
                max_rtr_adv_interval
            }
        }
        v if v < Duration::from_secs(3) => {
            tracing::warn!("min_rtr_adv_interval is < 3s; defaulting to 3s");
            Duration::from_secs(3)
        }
        v if v > max_rtr_adv_interval * 4 / 3 => {
            tracing::warn!("min_rtr_adv_interval is > .75 * max_rtr_adv_interval; defaulting to .75 * max_rtr_adv_interval");
            max_rtr_adv_interval * 4 / 3
        }
        v => v,
    };

    let (conn, handle, _) = new_connection().unwrap();
    tokio::task::spawn(conn);

    let interface = match Interface::new(&handle, &config.interface).await {
        Ok(interface) => interface,
        Err(err) => {
            tracing::error!("failed to open interface {}: {:?}", config.interface, err);
            std::process::exit(1);
        }
    };

    let mac = interface.mac().await.unwrap();
    let addrs = interface.addrs().await.unwrap();
    let scope_id = interface.scope_id();

    let Some(link_local) = addrs.into_iter().find(is_link_local) else {
        tracing::error!("no link local address");
        std::process::exit(1);
    };

    let local_addr = SocketAddrV6::new(link_local, 0, 0, scope_id);

    let socket = match IcmpSocket::new(local_addr) {
        Ok(socket) => Arc::new(socket),
        Err(err) => {
            tracing::error!("failed to bind ICMP: {}", err);
            std::process::exit(1);
        }
    };

    let packet = IcmpPacket {
        typ: IcmpType::RouterSolicitation,
        code: 0,
        checksum: 0,
        content: IcmpContent::RouterSolicitation(RouterSolicitation {
            source_link_layer_addr: Some(LinkLayerAddress(mac)),
        }),
    };

    let state = Arc::new(State {
        prefixes: Default::default(),
        mtu: config.mtu,
        config_changed: Default::default(),
        dns_servers: Default::default(),
    });

    let mut db = match Database::load(&config.db) {
        Ok(db) => {
            let mut prefixes = state.prefixes.write();

            for prefix in &db.prefixes {
                prefixes.insert(
                    prefix.prefix,
                    Prefix {
                        prefix: prefix.prefix,
                        prefix_length: prefix.prefix_length,
                        preferred_lifetime: match prefix.preferred {
                            crate::database::Lifetime::Duration(dur) => Lifetime::Duration(dur),
                            crate::database::Lifetime::Until(ts) => Lifetime::Until(ts),
                        },
                        valid_lifetime: match prefix.valid {
                            crate::database::Lifetime::Duration(dur) => Lifetime::Duration(dur),
                            crate::database::Lifetime::Until(ts) => Lifetime::Until(ts),
                        },
                    },
                );
            }

            db
        }
        Err(err) => {
            tracing::error!("failed to load database: {:?}", err);
            Database::default()
        }
    };

    let mut buf = Vec::new();
    packet.encode(&mut buf);

    {
        let state = state.clone();
        tokio::task::spawn(async move {
            if let Err(err) = control_loop(state).await {
                tracing::error!("failed to run control loop: {}", err);
                SHUTDOWN.quit();
            }
        });
    }

    let (cmd_tx, mut cmd_rx) = mpsc::channel(512);

    {
        let socket = socket.clone();
        let state = state.clone();
        let shutdown = SHUTDOWN.listen();
        tokio::task::spawn(async move {
            let mut last_multicast_ra = Instant::now();
            let mut next_multicast_ra = Instant::now();

            // The interval between unsolicited RAs is chosen by a uniformly
            // distributed random value between MinRtrAdvInterval and
            // MaxRtrAdvInterval.
            debug_assert!(min_rtr_adv_interval <= MIN_DELAY_BETWEEN_RAS);
            let uniform = Uniform::new(min_rtr_adv_interval, max_rtr_adv_interval);
            let mut rng = SmallRng::from_entropy();

            let mut initial_ras_sent = 0;

            pin_mut!(shutdown);
            loop {
                tracing::info!(
                    "next multicast RA in {:?}",
                    next_multicast_ra - Instant::now()
                );

                let addr = futures::select_biased! {
                    _ = shutdown.as_mut().fuse() => {
                        SocketAddrV6::new(Ipv6Addr::MULTICAST_ALL_NODES, 0, 0, scope_id)
                    },
                    _ = tokio::time::sleep_until(next_multicast_ra.into()).fuse() => {
                        SocketAddrV6::new(Ipv6Addr::MULTICAST_ALL_NODES, 0, 0, scope_id)
                    }
                    res = cmd_rx.recv().fuse() => {
                        match res.unwrap() {
                            Command::SendRouterAdvertisement(addr) => {
                                // All RAs in response to RSs MUST be delayed between 0 and `MAX_RA_DELAY_TIME`.
                                let delay = rng.gen_range(Duration::ZERO..MAX_RA_DELAY_TIME);
                                let ts = Instant::now() + delay;

                                // If delaying would take longer then until the next multicast RA is scheduled
                                // we discard the RS. The host will receive a multicast RA in time instead.
                                if ts > next_multicast_ra {
                                    continue;
                                }

                                // If the source address is UNSPECIFIED we MUST send a multicast RA instead,
                                // otherwise we can send it directly to the host as a unicast.
                                if addr.ip().is_unspecified() {
                                    // Multicast RAs MUST be sent no faster than `MIN_DELAY_BETWEEN_RAS`.
                                    let ra_delay = MIN_DELAY_BETWEEN_RAS.checked_sub(last_multicast_ra.elapsed()).unwrap_or_default();
                                    next_multicast_ra += ra_delay + delay;
                                    continue;
                                }

                                // Note that since ts < next_multicast_ra this sleep will never block
                                // for longer than the other branch.
                                tokio::time::sleep_until(ts.into()).await;
                                addr
                            },
                            Command::NewConfig => {
                                next_multicast_ra = Instant::now();
                                initial_ras_sent = 0;
                                SocketAddrV6::new(Ipv6Addr::MULTICAST_ALL_NODES, 0, 0, scope_id)
                            }
                        }
                    }
                };

                // On shutdown we should send a RA with the `router_liftime` field set to 0.
                let router_lifetime = if shutdown.is_in_progress() {
                    Duration::ZERO
                } else {
                    3 * max_rtr_adv_interval
                };

                let mut options = vec![IcmpOption::SourceLinkLayerAddress(LinkLayerAddress(mac))];

                if config.mtu != 0 {
                    options.push(IcmpOption::Mtu(config.mtu));
                }

                {
                    let dns = state.dns_servers.read();

                    if !dns.is_empty() {
                        let addrs = dns.iter().copied().collect();

                        options.push(IcmpOption::RecursiveDnsServer(RecursiveDnsServer {
                            addrs,
                            lifetime: Duration::from_secs(3600),
                        }));
                    }
                }

                for prefix in state.prefixes.read().values() {
                    // We only announce prefixes that are still valid.
                    // Expired prefixes are removed by another task, but it is possible
                    // for a prefix to just have gone invalid and we are running before
                    // the other task has removed it.
                    if prefix.valid_lifetime.duration().is_zero() {
                        continue;
                    }

                    options.push(IcmpOption::PrefixInformation(PrefixInformation {
                        prefix: prefix.prefix,
                        prefix_length: prefix.prefix_length,
                        on_link: true,
                        autonomous: true,
                        preferred_lifetime: prefix.preferred_lifetime.duration(),
                        valid_lifetime: prefix.valid_lifetime.duration(),
                    }));
                }

                let packet = IcmpPacket {
                    typ: IcmpType::RouterAdvertisement,
                    code: 0,
                    checksum: 0,
                    content: IcmpContent::RouterAdvertisement(RouterAdvertisement {
                        cur_hop_limit: 64,
                        managed: false,
                        other: false,
                        router_lifetime,
                        reachable_timer: None,
                        retrans_timer: None,
                        options,
                    }),
                };

                if let Err(err) = socket.send_to(&packet, addr).await {
                    tracing::error!("failed to send RA: {}", err);
                }

                if shutdown.is_in_progress() {
                    break;
                }

                let mut interval = rng.sample(uniform);

                // For the first MAX_INITIAL_RTR_ADVERTISEMENTS we should clamp the random
                // interval to `MAX_INITIAL_RTR_ADVERT_INTERVAL`.
                // TODO: We MAY repeat this procedure if the advertised information changes.
                if initial_ras_sent < MAX_INITIAL_RTR_ADVERTISEMENTS {
                    initial_ras_sent += 1;
                    interval = Duration::min(interval, MAX_INITIAL_RTR_ADVERT_INTERVAL);
                }

                debug_assert!(interval >= MIN_DELAY_BETWEEN_RAS);
                debug_assert!(interval <= MAX_DELAY_BETWEEN_RAS);

                last_multicast_ra = next_multicast_ra;
                next_multicast_ra += interval;
            }

            if let Err(err) = socket.close().await {
                tracing::error!("failed to close socket: {}", err);
            }
        });
    }

    {
        let cmd_tx = cmd_tx.clone();
        tokio::task::spawn(async move {
            loop {
                let (packet, addr) = match socket.recv_from().await {
                    Ok(res) => res,
                    Err(err) => {
                        tracing::error!("failed to read from socket: {}", err);
                        return;
                    }
                };

                if !router_solicit_is_valid(*addr.ip(), &packet) {
                    continue;
                }

                let _ = cmd_tx.send(Command::SendRouterAdvertisement(addr)).await;
            }
        });
    }

    tokio::task::spawn(async move {
        let mut next_prefix_lifetime = None;

        loop {
            // Wait until we get a new prefix or an existing prefix expires.
            if let Some(next_prefix_lifetime) = next_prefix_lifetime {
                futures::select_biased! {
                    _ = state.config_changed.notified().fuse() => (),
                    _ = tokio::time::sleep(next_prefix_lifetime).fuse() => (),
                }
            } else {
                state.config_changed.notified().await;
            }

            state.prefixes.write().retain(|_, prefix| {
                if prefix.valid_lifetime.duration().is_zero() {
                    false
                } else {
                    let lifetime =
                        next_prefix_lifetime.get_or_insert(prefix.valid_lifetime.duration());

                    if prefix.valid_lifetime.duration() < *lifetime {
                        *lifetime = prefix.valid_lifetime.duration();
                    }

                    true
                }
            });

            // Config has changed and we should send a new multicast RA.
            let _ = cmd_tx.send(Command::NewConfig).await;

            db.prefixes.clear();
            db.dns_servers.clear();

            let prefixes = state.prefixes.read().clone();
            for prefix in prefixes.values() {
                let addr = generate_addr(prefix.prefix, mac);

                if let Err(err) = interface
                    .add_addr(
                        IpAddr::V6(addr),
                        prefix.prefix_length,
                        Some(prefix.preferred_lifetime.duration()),
                        Some(prefix.valid_lifetime.duration()),
                    )
                    .await
                {
                    tracing::error!("failed to add addr to interface: {:?}", err);
                }

                db.prefixes.push(database::Prefix {
                    prefix: prefix.prefix,
                    prefix_length: prefix.prefix_length,
                    preferred: match prefix.preferred_lifetime {
                        Lifetime::Duration(dur) => crate::database::Lifetime::Duration(dur),
                        Lifetime::Until(ts) => crate::database::Lifetime::Until(ts),
                    },
                    valid: match prefix.valid_lifetime {
                        Lifetime::Duration(dur) => crate::database::Lifetime::Duration(dur),
                        Lifetime::Until(ts) => crate::database::Lifetime::Until(ts),
                    },
                });
            }

            for dns in state.dns_servers.read().clone() {
                db.dns_servers.push(dns);
            }

            if let Err(err) = db.save(&config.db) {
                tracing::error!("failed to save db: {:?}", err);
            }
        }
    });

    SHUTDOWN.wait().await;
}

#[derive(Debug, Default)]
pub struct State {
    prefixes: parking_lot::RwLock<HashMap<Ipv6Addr, Prefix>>,
    mtu: u32,
    config_changed: Notify,
    dns_servers: parking_lot::RwLock<HashSet<Ipv6Addr>>,
}

#[derive(Clone, Debug)]
pub struct Prefix {
    pub prefix: Ipv6Addr,
    pub prefix_length: u8,
    pub preferred_lifetime: Lifetime,
    pub valid_lifetime: Lifetime,
}

pub struct IcmpSocket {
    socket: AsyncFd<Socket>,
}

impl IcmpSocket {
    fn new(addr: SocketAddrV6) -> Result<Self, io::Error> {
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        socket.bind(&(addr.into()))?;
        socket.set_nonblocking(true)?;
        socket.join_multicast_v6(&Ipv6Addr::MULTICAST_ALL_ROUTERS, addr.scope_id())?;
        socket.set_multicast_hops_v6(255)?;
        socket.set_unicast_hops_v6(255)?;

        Ok(Self {
            socket: AsyncFd::new(socket)?,
        })
    }

    async fn recv_from(&self) -> Result<(IcmpPacket, SocketAddrV6), io::Error> {
        loop {
            let mut guard = self.socket.readable().await?;

            let mut buf = Vec::with_capacity(1500);
            match guard.try_io(|socket| socket.get_ref().recv_from(buf.spare_capacity_mut())) {
                Ok(Ok((len, addr))) => {
                    unsafe {
                        buf.set_len(len);
                    }

                    let addr = addr.as_socket_ipv6().unwrap();
                    match IcmpPacket::decode(&buf[..]) {
                        Ok(packet) => return Ok((packet, addr)),
                        Err(err) => {
                            tracing::debug!("failed to decode packet from {:?}: {:?}", addr, err);
                        }
                    }
                }
                Ok(Err(err)) => return Err(err),
                Err(_) => continue,
            }
        }
    }

    async fn send_to(&self, packet: &IcmpPacket, addr: SocketAddrV6) -> Result<(), io::Error> {
        let mut buf = Vec::new();
        packet.encode(&mut buf);

        loop {
            let mut guard = self.socket.writable().await?;

            match guard.try_io(|socket| socket.get_ref().send_to(&buf, &(addr.into()))) {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(err)) => return Err(err),
                Err(_) => continue,
            }
        }
    }

    async fn close(&self) -> Result<(), io::Error> {
        let socket = self.socket.get_ref();

        let addr = socket.local_addr()?.as_socket_ipv6().unwrap();
        socket.leave_multicast_v6(&Ipv6Addr::MULTICAST_ALL_ROUTERS, addr.scope_id())?;

        Ok(())
    }
}

fn is_link_local(addr: &Ipv6Addr) -> bool {
    addr.octets().starts_with(&[0xfe, 0x80])
}

fn router_solicit_is_valid(src: Ipv6Addr, packet: &IcmpPacket) -> bool {
    // https://www.rfc-editor.org/rfc/rfc4861#section-7.1.1
    // Requirements for valid RS:
    // - IP hop limit is set to 255
    // - ICMP checksum is valid
    // - ICMP code is 0
    // - ICMP length is >= 8
    // - All included options have length > 0
    // - If src IP is unspecified, no source link layer addr in message

    if packet.code != 0 {
        return false;
    }

    match &packet.content {
        IcmpContent::RouterSolicitation(sol) => {
            if src == Ipv6Addr::UNSPECIFIED {
                sol.source_link_layer_addr.is_none()
            } else {
                true
            }
        }
        _ => false,
    }
}

pub trait Ipv6AddrExt {
    const MULTICAST_ALL_NODES: Self;
    const MULTICAST_ALL_ROUTERS: Self;
}

impl Ipv6AddrExt for Ipv6Addr {
    const MULTICAST_ALL_NODES: Self = Self::new(0xff02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);
    const MULTICAST_ALL_ROUTERS: Self = Self::new(0xff02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02);
}

fn generate_addr(prefix: Ipv6Addr, mac: [u8; 6]) -> Ipv6Addr {
    let prefix = &prefix.octets()[0..8];

    Ipv6Addr::from([
        prefix[0],
        prefix[1],
        prefix[2],
        prefix[3],
        prefix[4],
        prefix[5],
        prefix[6],
        prefix[7],
        mac[0] ^ 2,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ])
}

const MAX_INITIAL_RTR_ADVERT_INTERVAL: Duration = Duration::from_secs(16);
const MAX_INITIAL_RTR_ADVERTISEMENTS: u8 = 3;

const MAX_FINAL_RTR_ADVERTISEMENTS: u8 = 3;
const MAX_RA_DELAY_TIME: Duration = Duration::from_millis(500);

const MIN_DELAY_BETWEEN_RAS: Duration = Duration::from_secs(3);
const MAX_DELAY_BETWEEN_RAS: Duration = Duration::from_secs(1800);

#[derive(Copy, Clone, Debug)]
enum Command {
    SendRouterAdvertisement(SocketAddrV6),
    NewConfig,
}
