use std::ffi::{c_int, c_void};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd};

use futures::TryStreamExt;
use libc::{setsockopt, socklen_t, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, IPV6_UNICAST_HOPS};
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::link::LinkAttribute;
use rtnetlink::Handle;
use socket2::Socket;

pub fn set_hop_limit(socket: &Socket, hop_limit: u8) -> io::Result<()> {
    let ttl: c_int = hop_limit as i32;

    unsafe {
        let res = setsockopt(
            socket.as_fd().as_raw_fd(),
            IPPROTO_IPV6,
            IPV6_MULTICAST_HOPS,
            &ttl as *const c_int as *const c_void,
            mem::size_of_val(&ttl) as socklen_t,
        );

        if res != 0 {
            return Err(io::Error::from_raw_os_error(res));
        }
    }

    unsafe {
        let res = setsockopt(
            socket.as_fd().as_raw_fd(),
            IPPROTO_IPV6,
            IPV6_UNICAST_HOPS,
            &ttl as *const c_int as *const c_void,
            mem::size_of_val(&ttl) as socklen_t,
        );

        if res != 0 {
            return Err(io::Error::from_raw_os_error(res));
        }
    }

    Ok(())
}

#[derive(Debug)]
pub enum Error {
    Rt(rtnetlink::Error),
    NoInterface,
    NoMac,
}

pub async fn get_interface_mac(handle: &Handle, name: &str) -> Result<[u8; 6], Error> {
    let mut links = handle.link().get().match_name(name.to_owned()).execute();
    if let Some(link) = links.try_next().await.map_err(Error::Rt)? {
        for attr in &link.attributes {
            match attr {
                LinkAttribute::Address(addr) => {
                    return match addr.as_slice().try_into() {
                        Ok(addr) => Ok(addr),
                        Err(_) => Err(Error::NoMac),
                    }
                }
                _ => (),
            }
        }
    }

    Err(Error::NoInterface)
}

pub async fn get_interface_addrs(handle: &Handle, name: &str) -> Result<Vec<Ipv6Addr>, Error> {
    let mut links = handle.link().get().match_name(name.to_owned()).execute();
    if let Some(link) = links.try_next().await.map_err(Error::Rt)? {
        let mut resp = handle
            .address()
            .get()
            .set_link_index_filter(link.header.index)
            .execute();

        let mut addrs = Vec::new();
        while let Some(a) = resp.try_next().await.map_err(Error::Rt)? {
            for attr in &a.attributes {
                match attr {
                    AddressAttribute::Address(addr) => match addr {
                        IpAddr::V6(addr) => {
                            addrs.push(*addr);
                        }
                        _ => (),
                    },
                    _ => (),
                }
            }
        }

        Ok(addrs)
    } else {
        Err(Error::NoInterface)
    }
}

pub async fn get_interface_scope(handle: &Handle, name: &str) -> Result<u32, Error> {
    let mut links = handle.link().get().match_name(name.to_owned()).execute();
    if let Some(link) = links.try_next().await.map_err(Error::Rt)? {
        Ok(link.header.index)
    } else {
        Err(Error::NoInterface)
    }
}
