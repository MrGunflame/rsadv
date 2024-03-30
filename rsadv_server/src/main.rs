//! NDP: https://www.rfc-editor.org/rfc/rfc4861
//! NDP DNS: https://www.rfc-editor.org/rfc/rfc8106

mod config;
mod control;
mod linux;
mod ndp;

use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};

use config::Config;
use control::control_loop;
use linux::set_hop_limit;
use ndp::{
    Encode, IcmpContent, IcmpOption, IcmpType, LinkLayerAddress, PrefixInformation,
    RecursiveDnsServer, RouterAdvertisement, RouterSolicitation,
};
use rsadv_control::Lifetime;
use rtnetlink::new_connection;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;

use crate::ndp::{Decode, IcmpPacket};

const RADV_INTERVAL: Duration = Duration::from_secs(600);

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let file = std::fs::read_to_string("config.toml").unwrap();
    let config: Config = toml::from_str(&file).unwrap();

    let (conn, handle, _) = new_connection().unwrap();
    tokio::task::spawn(conn);

    let mac = linux::get_interface_mac(&handle, &config.interface)
        .await
        .unwrap();

    let addrs = linux::get_interface_addrs(&handle, &config.interface)
        .await
        .unwrap();
    let scope_id = linux::get_interface_scope(&handle, &config.interface)
        .await
        .unwrap();

    let Some(link_local) = addrs.into_iter().find(is_link_local) else {
        tracing::error!("no link local address");
        std::process::exit(1);
    };

    let local_addr = SocketAddrV6::new(link_local, 0, 0, scope_id);

    let socket = IcmpSocket::new(local_addr).unwrap();

    let packet = IcmpPacket {
        typ: IcmpType::RouterSolicitation,
        code: 0,
        checksum: 0,
        content: IcmpContent::RouterSolicitation(RouterSolicitation {
            source_link_layer_addr: Some(LinkLayerAddress(mac)),
        }),
    };

    let mut buf = Vec::new();
    packet.encode(&mut buf);

    let mut next_multicast_ra = Instant::now();

    let state = Arc::new(State::default());

    tokio::task::spawn(control_loop(state.clone()));

    loop {
        let addr = tokio::select! {
            res = socket.recv_from() => {
                let (packet, addr) = res.unwrap();

                if !router_solicit_is_valid(&packet) {
                    continue;
                }

                addr
            }
            _ = tokio::time::sleep_until(next_multicast_ra.into()) => {
                next_multicast_ra += RADV_INTERVAL;
                SocketAddrV6::new(Ipv6Addr::MULTICAST_ALL_NODES, 0, 0, scope_id)
            }
        };

        let mut options = vec![
            IcmpOption::Mtu(config.mtu),
            IcmpOption::RecursiveDnsServer(RecursiveDnsServer {
                addrs: vec![config.dns],
                lifetime: Duration::from_secs(3600),
            }),
            IcmpOption::SourceLinkLayerAddress(LinkLayerAddress(mac)),
        ];
        for prefix in &*state.prefixes.read() {
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
                router_lifetime: Duration::from_secs(1800),
                reachable_timer: None,
                retrans_timer: None,
                options,
            }),
        };

        socket.send_to(&packet, addr).await.unwrap();
    }
}

#[derive(Debug, Default)]
pub struct State {
    prefixes: parking_lot::RwLock<Vec<Prefix>>,
    mtu: u32,
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

        set_hop_limit(&socket, 255).unwrap();

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
                            tracing::error!("failed to decode packet from {:?}: {:?}", addr, err);
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
}

fn is_link_local(addr: &Ipv6Addr) -> bool {
    addr.octets().starts_with(&[0xfe, 0x80])
}

// https://www.rfc-editor.org/rfc/rfc4861#section-7.1.1
fn router_solicit_is_valid(packet: &IcmpPacket) -> bool {
    if packet.code != 0 {
        return false;
    }

    match &packet.content {
        IcmpContent::RouterSolicitation(sol) => true,
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
