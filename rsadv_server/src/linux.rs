use std::ffi::{c_int, c_void};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd};
use std::time::Duration;

use futures::TryStreamExt;
use libc::{setsockopt, socklen_t, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, IPV6_UNICAST_HOPS};
use netlink_packet_route::address::{AddressAttribute, CacheInfo};
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

#[derive(Clone, Debug)]
pub struct Interface {
    index: u32,
    handle: Handle,
}

impl Interface {
    pub async fn new(handle: &Handle, name: &str) -> Result<Self, Error> {
        let mut links = handle.link().get().match_name(name.to_owned()).execute();

        if let Some(link) = links.try_next().await.map_err(Error::Rt)? {
            Ok(Self {
                index: link.header.index,
                handle: handle.clone(),
            })
        } else {
            Err(Error::NoInterface)
        }
    }

    pub fn scope_id(&self) -> u32 {
        self.index
    }

    pub async fn mac(&self) -> Result<[u8; 6], Error> {
        let mut links = self.handle.link().get().match_index(self.index).execute();
        if let Some(link) = links.try_next().await.map_err(Error::Rt)? {
            for attr in &link.attributes {
                match attr {
                    LinkAttribute::Address(addr) => {
                        return match addr.as_slice().try_into() {
                            Ok(mac) => Ok(mac),
                            Err(_) => Err(Error::NoMac),
                        }
                    }
                    _ => (),
                }
            }
        }

        Err(Error::NoInterface)
    }

    pub async fn addrs(&self) -> Result<Vec<Ipv6Addr>, Error> {
        let mut links = self
            .handle
            .address()
            .get()
            .set_link_index_filter(self.index)
            .execute();

        let mut addrs = Vec::new();
        while let Some(link) = links.try_next().await.map_err(Error::Rt)? {
            for attr in &link.attributes {
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

        Err(Error::NoInterface)
    }

    pub async fn add_addr(
        &self,
        addr: IpAddr,
        prefix_len: u8,
        preferred: Option<Duration>,
        valid: Option<Duration>,
    ) -> Result<(), Error> {
        let mut msg = self
            .handle
            .address()
            .add(self.index, addr.into(), prefix_len)
            // Overwrite existing addresses, this means we're setting the
            // lifetime to a new value without changing the address.
            .replace();

        let mut cache_info = CacheInfo::default();
        cache_info.ifa_preferred = preferred
            .map(|dur| dur.as_secs().try_into().unwrap_or(u32::MAX))
            .unwrap_or(u32::MAX);
        cache_info.ifa_valid = valid
            .map(|dur| dur.as_secs().try_into().unwrap_or(u32::MAX))
            .unwrap_or(u32::MAX);
        msg.message_mut()
            .attributes
            .push(AddressAttribute::CacheInfo(cache_info));

        match msg.execute().await {
            Ok(()) => Ok(()),
            Err(err) => return Err(Error::Rt(err)),
        }
    }

    pub async fn del_addr(&self, addr: IpAddr) -> Result<(), Error> {
        let mut addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(self.index)
            .execute();

        while let Some(resp) = addrs.try_next().await.map_err(Error::Rt)? {
            for attr in &resp.attributes {
                match attr {
                    AddressAttribute::Address(a) => {
                        if *a == addr {
                            self.handle
                                .address()
                                .del(resp)
                                .execute()
                                .await
                                .map_err(Error::Rt)?;
                            return Ok(());
                        }
                    }
                    _ => (),
                }
            }
        }

        Ok(())
    }
}
