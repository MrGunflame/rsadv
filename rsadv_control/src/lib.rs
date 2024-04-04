use std::io::{self, Read, Write};
use std::net::Ipv6Addr;
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime};

use bytes::{Buf, BufMut};

const CONTROL_SOCKET_ADDR: &str = "/run/rsadv.sock";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    AddPrefix(Prefix),
    RemovePrefix(Prefix),
    AddDnsServer(DnsServer),
    RemoveDnsServer(DnsServer),
}

impl Request {
    pub fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        match self {
            Self::AddPrefix(prefix) => {
                buf.put_u32_le(1);

                buf.put_slice(&prefix.prefix.octets());
                buf.put_u8(prefix.prefix_length);

                match prefix.preferred_lifetime {
                    Lifetime::Duration(dur) => {
                        buf.put_u8(1);
                        buf.put_u32_le(dur.as_secs() as u32);
                    }
                    Lifetime::Until(ts) => {
                        let dur = ts.duration_since(SystemTime::UNIX_EPOCH).unwrap();
                        buf.put_u8(2u8);
                        buf.put_u32_le(dur.as_secs() as u32);
                    }
                }

                match prefix.valid_lifetime {
                    Lifetime::Duration(dur) => {
                        buf.put_u8(1);
                        buf.put_u32_le(dur.as_secs() as u32);
                    }
                    Lifetime::Until(ts) => {
                        let dur = ts.duration_since(SystemTime::UNIX_EPOCH).unwrap();
                        buf.put_u8(2u8);
                        buf.put_u32_le(dur.as_secs() as u32);
                    }
                }
            }
            Self::RemovePrefix(prefix) => {
                buf.put_u32_le(2);

                buf.put_slice(&prefix.prefix.octets());
                buf.put_u8(prefix.prefix_length);

                match prefix.preferred_lifetime {
                    Lifetime::Duration(dur) => {
                        buf.put_u8(1);
                        buf.put_u32_le(dur.as_secs() as u32);
                    }
                    Lifetime::Until(ts) => {
                        let dur = ts.duration_since(SystemTime::UNIX_EPOCH).unwrap();
                        buf.put_u8(2u8);
                        buf.put_u32_le(dur.as_secs() as u32);
                    }
                }

                match prefix.valid_lifetime {
                    Lifetime::Duration(dur) => {
                        buf.put_u8(1);
                        buf.put_u32(dur.as_secs() as u32);
                    }
                    Lifetime::Until(ts) => {
                        let dur = ts.duration_since(SystemTime::UNIX_EPOCH).unwrap();
                        buf.put_u8(2u8);
                        buf.put_u32_le(dur.as_secs() as u32);
                    }
                }
            }
            Self::AddDnsServer(server) => {
                buf.put_u32_le(3);

                buf.put_slice(&server.addr.octets());

                match server.lifetime {
                    Lifetime::Duration(dur) => {
                        buf.put_u8(1);
                        buf.put_u32_le(dur.as_secs() as u32);
                    }
                    Lifetime::Until(ts) => {
                        let dur = ts.duration_since(SystemTime::UNIX_EPOCH).unwrap();
                        buf.put_u8(2u8);
                        buf.put_u32_le(dur.as_secs() as u32);
                    }
                }
            }
            Self::RemoveDnsServer(server) => {
                buf.put_u32_le(4);

                buf.put_slice(&server.addr.octets());

                match server.lifetime {
                    Lifetime::Duration(dur) => {
                        buf.put_u8(1);
                        buf.put_u32_le(dur.as_secs() as u32);
                    }
                    Lifetime::Until(ts) => {
                        let dur = ts.duration_since(SystemTime::UNIX_EPOCH).unwrap();
                        buf.put_u8(2u8);
                        buf.put_u32_le(dur.as_secs() as u32);
                    }
                }
            }
        };
    }

    pub fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        if buf.remaining() < 4 {
            return Err(Error::Eof);
        }

        match buf.get_u32_le() {
            1 => {
                if buf.remaining() < 16 + 1 + 1 + 4 + 1 + 4 {
                    return Err(Error::Eof);
                }

                let mut prefix = [0; 16];
                for index in 0..16 {
                    prefix[index] = buf.get_u8();
                }

                let prefix_length = buf.get_u8();

                let preferred_lifetime = match buf.get_u8() {
                    1 => Lifetime::Duration(Duration::from_secs(buf.get_u32_le().into())),
                    2 => Lifetime::Until(
                        SystemTime::UNIX_EPOCH + Duration::from_secs(buf.get_u32_le().into()),
                    ),
                    _ => return Err(Error::Eof),
                };

                let valid_lifetime = match buf.get_u8() {
                    1 => Lifetime::Duration(Duration::from_secs(buf.get_u32_le().into())),
                    2 => Lifetime::Until(
                        SystemTime::UNIX_EPOCH + Duration::from_secs(buf.get_u32_le().into()),
                    ),
                    _ => return Err(Error::Eof),
                };

                Ok(Self::AddPrefix(Prefix {
                    prefix: Ipv6Addr::from(prefix),
                    prefix_length,
                    preferred_lifetime,
                    valid_lifetime,
                }))
            }
            2 => {
                if buf.remaining() < 16 + 1 + 1 + 4 + 1 + 4 {
                    return Err(Error::Eof);
                }

                let mut prefix = [0; 16];
                for index in 0..16 {
                    prefix[index] = buf.get_u8();
                }

                let prefix_length = buf.get_u8();

                let preferred_lifetime = match buf.get_u8() {
                    1 => Lifetime::Duration(Duration::from_secs(buf.get_u32_le().into())),
                    2 => Lifetime::Until(
                        SystemTime::UNIX_EPOCH + Duration::from_secs(buf.get_u32_le().into()),
                    ),
                    _ => return Err(Error::Eof),
                };

                let valid_lifetime = match buf.get_u8() {
                    1 => Lifetime::Duration(Duration::from_secs(buf.get_u32_le().into())),
                    2 => Lifetime::Until(
                        SystemTime::UNIX_EPOCH + Duration::from_secs(buf.get_u32_le().into()),
                    ),
                    _ => return Err(Error::Eof),
                };

                Ok(Self::RemovePrefix(Prefix {
                    prefix: Ipv6Addr::from(prefix),
                    prefix_length,
                    preferred_lifetime,
                    valid_lifetime,
                }))
            }
            3 => {
                if buf.remaining() < 16 + 1 + 4 {
                    return Err(Error::Eof);
                }

                let mut addr = [0; 16];
                for index in 0..16 {
                    addr[index] = buf.get_u8();
                }

                let lifetime = match buf.get_u8() {
                    1 => Lifetime::Duration(Duration::from_secs(buf.get_u32_le().into())),
                    2 => Lifetime::Until(
                        SystemTime::UNIX_EPOCH + Duration::from_secs(buf.get_u32_le().into()),
                    ),
                    _ => return Err(Error::Eof),
                };

                Ok(Self::AddDnsServer(DnsServer {
                    addr: Ipv6Addr::from(addr),
                    lifetime,
                }))
            }
            4 => {
                if buf.remaining() < 16 + 1 + 4 {
                    return Err(Error::Eof);
                }

                let mut addr = [0; 16];
                for index in 0..16 {
                    addr[index] = buf.get_u8();
                }

                let lifetime = match buf.get_u8() {
                    1 => Lifetime::Duration(Duration::from_secs(buf.get_u32_le().into())),
                    2 => Lifetime::Until(
                        SystemTime::UNIX_EPOCH + Duration::from_secs(buf.get_u32_le().into()),
                    ),
                    _ => return Err(Error::Eof),
                };

                Ok(Self::RemoveDnsServer(DnsServer {
                    addr: Ipv6Addr::from(addr),
                    lifetime,
                }))
            }
            _ => Err(Error::Eof),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub prefix: Ipv6Addr,
    pub prefix_length: u8,
    pub preferred_lifetime: Lifetime,
    pub valid_lifetime: Lifetime,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DnsServer {
    pub addr: Ipv6Addr,
    pub lifetime: Lifetime,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Lifetime {
    Duration(Duration),
    Until(SystemTime),
}

impl Lifetime {
    pub fn duration(&self) -> Duration {
        match self {
            Self::Duration(dur) => *dur,
            Self::Until(ts) => ts
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Response {
    Ok,
}

impl Response {
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl Response {
    pub fn encode<B>(&self, mut buf: B)
    where
        B: BufMut,
    {
        match self {
            Self::Ok => {
                buf.put_u32_le(0);
            }
        }
    }

    pub fn decode<B>(mut buf: B) -> Result<Self, Error>
    where
        B: Buf,
    {
        if buf.remaining() < 4 {
            return Err(Error::Eof);
        }

        match buf.get_u32_le() {
            0 => Ok(Self::Ok),
            _ => Err(Error::Eof),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Eof,
    Io(io::Error),
}

pub struct Connection {
    stream: UnixStream,
}

impl Connection {
    pub fn new() -> Result<Self, io::Error> {
        let stream = UnixStream::connect(CONTROL_SOCKET_ADDR)?;

        Ok(Self { stream })
    }

    pub fn send(&mut self, req: Request) -> Result<Response, Error> {
        let mut buf = Vec::new();
        req.encode(&mut buf);

        let mut buf_with_len = Vec::new();
        buf_with_len.extend((buf.len() as u32).to_le_bytes());
        buf_with_len.extend(buf);

        self.stream.write_all(&buf_with_len).map_err(Error::Io)?;

        let mut len = [0; 4];
        self.stream.read_exact(&mut len).map_err(Error::Io)?;

        let len = u32::from_le_bytes(len);

        let mut buf = vec![0; len as usize];
        self.stream.read_exact(&mut buf).map_err(Error::Io)?;

        Response::decode(&buf[..])
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Duration;

    use crate::{Lifetime, Prefix, Request};

    #[test]
    fn encode_decode() {
        let req = Request::AddPrefix(Prefix {
            prefix: Ipv6Addr::UNSPECIFIED,
            prefix_length: 0,
            preferred_lifetime: Lifetime::Duration(Duration::from_secs(3600)),
            valid_lifetime: Lifetime::Duration(Duration::from_secs(3600)),
        });

        let mut buf = Vec::new();
        req.encode(&mut buf);

        let output = Request::decode(&buf[..]).unwrap();
        assert_eq!(req, output);
    }
}
