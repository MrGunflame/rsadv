use std::net::Ipv6Addr;
use std::time::Duration;

use bytes::{Buf, BufMut};

#[derive(Clone, Debug)]
pub enum Error {
    Eof,
    UnknownOptionCode,
    UnknownIcmpType,
}

#[derive(Clone, Debug)]
pub struct IcmpPacket {
    pub typ: IcmpType,
    pub code: u8,
    pub checksum: u16,
    pub content: IcmpContent,
}

impl Encode for IcmpPacket {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        self.typ.to_u8().encode(&mut buf);
        self.code.encode(&mut buf);
        self.checksum.encode(&mut buf);

        match &self.content {
            IcmpContent::RouterSolicitation(sol) => sol.encode(buf),
            IcmpContent::RouterAdvertisement(adv) => adv.encode(buf),
        }
    }
}

impl Decode for IcmpPacket {
    type Error = Error;

    fn decode<B>(mut buf: B) -> Result<Self, Self::Error>
    where
        B: Buf,
    {
        let typ = IcmpType::from_u8(u8::decode(&mut buf)?).ok_or(Error::UnknownIcmpType)?;
        let code = u8::decode(&mut buf)?;
        let checksum = u16::decode(&mut buf)?;

        let content = match typ {
            IcmpType::RouterSolicitation => {
                IcmpContent::RouterSolicitation(RouterSolicitation::decode(buf)?)
            }
            IcmpType::RouterAdvertisement => {
                IcmpContent::RouterAdvertisement(RouterAdvertisement::decode(buf)?)
            }
        };

        Ok(Self {
            typ,
            code,
            checksum,
            content,
        })
    }
}

#[derive(Clone, Debug)]
pub enum IcmpContent {
    RouterSolicitation(RouterSolicitation),
    RouterAdvertisement(RouterAdvertisement),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum IcmpType {
    RouterSolicitation,
    RouterAdvertisement,
}

impl IcmpType {
    fn to_u8(self) -> u8 {
        match self {
            Self::RouterSolicitation => 133,
            Self::RouterAdvertisement => 134,
        }
    }

    fn from_u8(typ: u8) -> Option<Self> {
        match typ {
            133 => Some(Self::RouterSolicitation),
            134 => Some(Self::RouterAdvertisement),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RouterAdvertisement {
    pub cur_hop_limit: u8,
    pub managed: bool,
    pub other: bool,
    pub router_lifetime: Duration,
    pub reachable_timer: Option<Duration>,
    pub retrans_timer: Option<Duration>,
    pub options: Vec<IcmpOption>,
}

impl Encode for RouterAdvertisement {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        self.cur_hop_limit.encode(&mut buf);

        let mut flags = 0u8;
        flags |= (self.managed as u8) << 7;
        flags |= (self.other as u8) << 6;
        flags.encode(&mut buf);

        (self.router_lifetime.as_secs() as u16).encode(&mut buf);

        if let Some(reachable_timer) = self.reachable_timer {
            (reachable_timer.as_secs() as u32).encode(&mut buf);
        } else {
            0u32.encode(&mut buf);
        }

        if let Some(retrans_timer) = self.retrans_timer {
            (retrans_timer.as_secs() as u32).encode(&mut buf);
        } else {
            0u32.encode(&mut buf);
        }

        for opt in &self.options {
            opt.encode(&mut buf);
        }
    }
}

impl Decode for RouterAdvertisement {
    type Error = Error;

    fn decode<B>(mut buf: B) -> Result<Self, Self::Error>
    where
        B: Buf,
    {
        let cur_hop_limit = u8::decode(&mut buf)?;
        let flags = u8::decode(&mut buf)?;
        let router_lifetime = u16::decode(&mut buf)?;

        let reachable_timer = match u32::decode(&mut buf)? {
            0 => None,
            val => Some(Duration::from_secs(val.into())),
        };
        let retrans_timer = match u32::decode(&mut buf)? {
            0 => None,
            val => Some(Duration::from_secs(val.into())),
        };

        let mut options = Vec::new();
        while buf.remaining() > 0 {
            if let Ok(opt) = IcmpOption::decode(&mut buf) {
                options.push(opt);
            }
        }

        Ok(Self {
            cur_hop_limit,
            managed: flags & (1 << 7) != 0,
            other: flags & (1 << 6) != 0,
            router_lifetime: Duration::from_secs(router_lifetime.into()),
            reachable_timer,
            retrans_timer,
            options,
        })
    }
}

#[derive(Clone, Debug)]
pub enum IcmpOption {
    SourceLinkLayerAddress(LinkLayerAddress),
    TargetLinkLayerAddress(LinkLayerAddress),
    PrefixInformation(PrefixInformation),
    Mtu(u32),
    RecursiveDnsServer(RecursiveDnsServer),
}

impl Encode for IcmpOption {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        match self {
            Self::SourceLinkLayerAddress(addr) => {
                OptionCode::SourceLinkLayerAddress.to_u8().encode(&mut buf);
                1u8.encode(&mut buf);
                addr.encode(&mut buf);
            }
            Self::TargetLinkLayerAddress(addr) => {
                OptionCode::TargetLinkLayerAddress.to_u8().encode(&mut buf);
                1u8.encode(&mut buf);
                addr.encode(&mut buf);
            }
            Self::PrefixInformation(opt) => {
                OptionCode::PrefixInformation.to_u8().encode(&mut buf);
                4u8.encode(&mut buf);

                opt.prefix_length.encode(&mut buf);
                let mut flags = 0u8;
                flags |= (opt.on_link as u8) << 7;
                flags |= (opt.autonomous as u8) << 6;
                flags.encode(&mut buf);

                (opt.valid_lifetime.as_secs() as u32).encode(&mut buf);
                (opt.preferred_lifetime.as_secs() as u32).encode(&mut buf);
                0u32.encode(&mut buf);
                buf.put_slice(&opt.prefix.octets());
            }
            Self::Mtu(mtu) => {
                OptionCode::Mtu.to_u8().encode(&mut buf);
                1u8.encode(&mut buf);

                buf.put_slice(&[0, 0]);
                mtu.encode(&mut buf);
            }
            Self::RecursiveDnsServer(opt) => {
                OptionCode::RecursiveDnsServer.to_u8().encode(&mut buf);
                (1 + opt.addrs.len() as u8 * 2).encode(&mut buf);

                buf.put_slice(&[0, 0]);
                (opt.lifetime.as_secs() as u32).encode(&mut buf);

                for addr in &opt.addrs {
                    buf.put_slice(&addr.octets());
                }
            }
        }
    }
}

impl Decode for IcmpOption {
    type Error = Error;

    fn decode<B>(mut buf: B) -> Result<Self, Self::Error>
    where
        B: Buf,
    {
        let code = u8::decode(&mut buf)?;
        let len = u8::decode(&mut buf)?;

        match OptionCode::from_u8(code) {
            Some(OptionCode::SourceLinkLayerAddress) => {
                let addr = LinkLayerAddress::decode(&mut buf)?;
                Ok(Self::SourceLinkLayerAddress(addr))
            }
            Some(OptionCode::TargetLinkLayerAddress) => {
                let addr = LinkLayerAddress::decode(&mut buf)?;
                Ok(Self::TargetLinkLayerAddress(addr))
            }
            Some(OptionCode::PrefixInformation) => {
                let prefix_length = u8::decode(&mut buf)?;
                let flags = u8::decode(&mut buf)?;
                let valid_lifetime = u32::decode(&mut buf)?;
                let preferred_lifetime = u32::decode(&mut buf)?;

                // Resv
                u32::decode(&mut buf)?;

                let mut prefix = [0; 16];
                for b in &mut prefix {
                    *b = u8::decode(&mut buf)?;
                }

                Ok(Self::PrefixInformation(PrefixInformation {
                    prefix_length,
                    on_link: flags & (1 << 7) != 0,
                    autonomous: flags & (1 << 6) != 0,
                    valid_lifetime: Duration::from_secs(valid_lifetime.into()),
                    preferred_lifetime: Duration::from_secs(preferred_lifetime.into()),
                    prefix: Ipv6Addr::from(prefix),
                }))
            }
            Some(OptionCode::RedirectedHeader) => {
                todo!()
            }
            Some(OptionCode::Mtu) => {
                for _ in 0..2 {
                    u8::decode(&mut buf)?;
                }

                let mtu = u32::decode(&mut buf)?;
                Ok(Self::Mtu(mtu))
            }
            Some(OptionCode::RecursiveDnsServer) => {
                for _ in 0..2 {
                    u8::decode(&mut buf)?;
                }

                let lifetime = Duration::from_secs(u32::decode(&mut buf)?.into());

                let mut addrs = Vec::new();

                let num_addrs = len.saturating_sub(1) / 2;
                for _ in 0..num_addrs {
                    let mut addr = [0; 16];
                    for b in &mut addr {
                        *b = u8::decode(&mut buf)?;
                    }

                    addrs.push(Ipv6Addr::from(addr));
                }

                Ok(Self::RecursiveDnsServer(RecursiveDnsServer {
                    lifetime,
                    addrs,
                }))
            }
            None => {
                // The length is given as factor of 8 bytes and includes
                // the header (option + len) with length of 2 which we already
                // consumed.
                let forward = len.saturating_mul(8).saturating_sub(2);

                for _ in 0..forward {
                    u8::decode(&mut buf)?;
                }

                Err(Error::UnknownOptionCode)
            }
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PrefixInformation {
    pub prefix_length: u8,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_lifetime: Duration,
    pub preferred_lifetime: Duration,
    pub prefix: Ipv6Addr,
}

#[derive(Copy, Clone, Debug)]
pub struct LinkLayerAddress(pub [u8; 6]);

impl Encode for LinkLayerAddress {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        buf.put_slice(&self.0);
    }
}

impl Decode for LinkLayerAddress {
    type Error = Error;

    fn decode<B>(mut buf: B) -> Result<Self, Self::Error>
    where
        B: Buf,
    {
        let mut bytes = [0; 6];
        for b in &mut bytes {
            *b = u8::decode(&mut buf)?;
        }

        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug)]
pub struct RouterSolicitation {
    pub source_link_layer_addr: Option<LinkLayerAddress>,
}

impl Encode for RouterSolicitation {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        // Reserved
        buf.put_slice(&[0, 0, 0, 0]);

        if let Some(opt) = self.source_link_layer_addr {
            OptionCode::SourceLinkLayerAddress.to_u8().encode(&mut buf);
            1u8.encode(&mut buf);
            opt.encode(&mut buf);
        }
    }
}

impl Decode for RouterSolicitation {
    type Error = Error;

    fn decode<B>(mut buf: B) -> Result<Self, Self::Error>
    where
        B: Buf,
    {
        let mut source_link_layer_addr = None;

        for _ in 0..4 {
            u8::decode(&mut buf)?;
        }

        if buf.remaining() > 0 {
            let code = OptionCode::from_u8(u8::decode(&mut buf)?).ok_or(Error::Eof)?;
            let _len = u8::decode(&mut buf)?;

            if code == OptionCode::SourceLinkLayerAddress {
                source_link_layer_addr = Some(LinkLayerAddress::decode(&mut buf)?);
            }
        }

        Ok(Self {
            source_link_layer_addr,
        })
    }
}

pub trait Encode {
    fn encode<B>(&self, buf: B)
    where
        B: BufMut;
}

pub trait Decode: Sized {
    type Error;

    fn decode<B>(buf: B) -> Result<Self, Self::Error>
    where
        B: Buf;
}

impl Encode for u8 {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        buf.put_u8(*self);
    }
}

impl Decode for u8 {
    type Error = Error;

    fn decode<B>(mut buf: B) -> Result<Self, Self::Error>
    where
        B: Buf,
    {
        if buf.remaining() < 1 {
            Err(Error::Eof)
        } else {
            Ok(buf.get_u8())
        }
    }
}

impl Encode for u16 {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        buf.put_u16(*self);
    }
}

impl Decode for u16 {
    type Error = Error;

    fn decode<B>(mut buf: B) -> Result<Self, Self::Error>
    where
        B: Buf,
    {
        if buf.remaining() < 2 {
            Err(Error::Eof)
        } else {
            Ok(buf.get_u16())
        }
    }
}

impl Encode for u32 {
    fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        buf.put_u32(*self);
    }
}

impl Decode for u32 {
    type Error = Error;

    fn decode<B>(mut buf: B) -> Result<Self, Self::Error>
    where
        B: Buf,
    {
        if buf.remaining() < 4 {
            Err(Error::Eof)
        } else {
            Ok(buf.get_u32())
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum OptionCode {
    SourceLinkLayerAddress,
    TargetLinkLayerAddress,
    PrefixInformation,
    RedirectedHeader,
    Mtu,
    RecursiveDnsServer,
}

impl OptionCode {
    fn from_u8(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::SourceLinkLayerAddress),
            2 => Some(Self::TargetLinkLayerAddress),
            3 => Some(Self::PrefixInformation),
            4 => Some(Self::RedirectedHeader),
            5 => Some(Self::Mtu),
            25 => Some(Self::RecursiveDnsServer),
            _ => None,
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Self::SourceLinkLayerAddress => 1,
            Self::TargetLinkLayerAddress => 2,
            Self::PrefixInformation => 3,
            Self::RedirectedHeader => 4,
            Self::Mtu => 5,
            Self::RecursiveDnsServer => 25,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RecursiveDnsServer {
    pub lifetime: Duration,
    pub addrs: Vec<Ipv6Addr>,
}
