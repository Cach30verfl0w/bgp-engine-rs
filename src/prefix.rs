/*
 * Copyright 2026 Cedric Hammes
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::error::Error;
use std::{fmt, io, net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
}, str::FromStr};
use nom::{IResult, number::complete as number, bytes::complete as bytes};

/// Represents an IP network prefix (CIDR) consisting of a base address and a prefix length.
///
/// This structure is used to define a range of IP addresses. It supports both
/// IPv4 and IPv6 via the underlying `IpAddr` enum.
///
/// # Constraints
/// - For IPv4: `mask` must be between 0 and 32.
/// - For IPv6: `mask` must be between 0 and 128.
///
/// # Ordering
/// The struct derives `Ord` and `PartialOrd`. Sorting is performed first by
/// the IP address and then by the mask length. Note that `IpAddr` sorts
/// IPv4 addresses before IPv6 addresses.
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct IpPrefix {
    pub addr: IpAddr,
    pub mask: u8,
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.addr, self.mask)
    }
}

impl FromStr for IpPrefix {
    type Err = Error;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let parts = str.split('/').collect::<Vec<_>>();
        if parts.len() != 2 {
            return Err(Error::BadPrefix(str.into()));
        }

        let mask = parts[1].parse::<u8>().map_err(|_| Error::BadMask(parts[1].into()))?;
        let addr = parts[0].parse::<IpAddr>().map_err(|_| Error::BadAddr(parts[0].into()))?;
        match addr {
            IpAddr::V4(_) if mask > 32 => return Err(Error::BadMask(parts[1].into())),
            IpAddr::V6(_) if mask > 128 => return Err(Error::BadMask(parts[1].into())),
            _ => {}
        }

        Ok(Self { addr, mask })
    }
}

impl IpPrefix {
    #[inline(always)]
    pub fn new(addr: IpAddr, mask: u8) -> Self {
        Self { addr, mask }
    }

    /// Decodes an IP prefix from a BGP NLRI-formatted byte stream.
    ///
    /// According to RFC 4271, BGP prefixes are encoded as a 1-octet length field
    /// followed by a variable-length prefix field. The prefix field contains
    /// only the minimum number of octets required to hold the specified number of bits.
    ///
    /// # Arguments
    /// * `input` - The raw byte slice to parse.
    /// * `is_ipv4` - A boolean flag indicating the address family (AFI). If `true`,
    ///   the address is parsed as IPv4; otherwise, it is parsed as IPv6.
    pub fn decode(input: &[u8], is_ipv4: bool) -> IResult<&[u8], Self, Error> {
        let (input, length) = number::be_u8(input)?;
        let bytes_len = ((length as usize) + 7) / 8;

        let (input, bytes) = bytes::take(bytes_len)(input)?;
        Ok((input, Self {
            addr: if is_ipv4 {
                let mut octets = [0u8; 4];
                octets[..bytes_len].copy_from_slice(bytes);
                IpAddr::V4(Ipv4Addr::from_octets(octets))
            } else {
                let mut octets = [0u8; 16];
                octets[..bytes_len].copy_from_slice(bytes);
                IpAddr::V6(Ipv6Addr::from_octets(octets))
            },
            mask: length
        }))
    }

    /// Encodes the IP prefix into a BGP NLRI-formatted byte stream.
    ///
    /// This method writes the prefix to the provided writer using the variable-length
    /// encoding specified in RFC 4271. It consists of a single-octet length field
    /// (the mask in bits) followed by the minimum number of octets required to
    /// represent the address prefix.
    ///
    /// # Arguments
    /// * `writer` - Any type implementing `std::io::Write` (e.g., a `TcpStream`, `Vec<u8>`, or `File`).
    pub fn encode_in(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        let bytes_len = ((self.mask as usize) + 7) / 8;
        writer.write(&self.mask.to_be_bytes())?;
        match self.addr {
            IpAddr::V4(addr) => writer.write_all(&addr.octets()[..bytes_len])?,
            IpAddr::V6(addr) => writer.write_all(&addr.octets()[..bytes_len])?
        };
        Ok(())
    }

    /// Checks if another prefix is completely contained within this prefix.
    ///
    /// This is true if this prefix is a "supernet" of the other, meaning
    /// this prefix has a shorter or equal mask and covers the other's range.
    ///
    /// # Examples
    /// ```
    /// let supernet = "10.0.0.0/8".parse::<IpPrefix>().unwrap();
    /// let subnet = "10.1.2.0/24".parse::<IpPrefix>().unwrap();
    /// assert!(supernet.has_prefix(&subnet));
    /// ```
    pub fn has_prefix(&self, other: &IpPrefix) -> bool {
        // A smaller network (longer mask) cannot contain a larger one.
        if self.mask > other.mask {
            return false;
        }

        // If the families match and the other's base address is
        // within our network, the entire other prefix is contained.
        self.has_addr(&other.addr)
    }

    /// Checks if the given IP address is contained within this network prefix.
    ///
    /// This method determines inclusion by applying the network mask to both the
    /// prefix's base address and the provided address. If the resulting network
    /// portions are identical, the address belongs to the prefix.
    ///
    /// # Behavior
    /// - **Family Matching:** Returns `false` if the IP families do not match (e.g., checking an IPv6 address against an IPv4 prefix).
    /// - **Zero Mask:** A mask of `0` (e.g., `0.0.0.0/0` or `::/0`) always returns `true` for addresses of the same family, representing
    ///   "any" network.
    /// - **Validation:** Returns `false` if the mask length is invalid for the address family (e.g., > 32 for IPv4).
    ///
    /// # Logic
    /// The method performs a bitwise AND between the addresses and a bitmask
    /// generated from the CIDR prefix length.
    ///
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::IpAddr;
    /// let prefix = "10.0.0.0/8".parse::<IpPrefix>().unwrap();
    ///
    /// assert!(prefix.has_addr(&"10.1.2.3".parse().unwrap()));
    /// assert!(!prefix.has_addr(&"172.16.0.1".parse().unwrap()));
    /// ```
    pub fn has_addr(&self, addr: &IpAddr) -> bool {
        if self.mask == 0 {
            return match (self.addr, addr) {
                (IpAddr::V4(_), IpAddr::V4(_)) => true,
                (IpAddr::V6(_), IpAddr::V6(_)) => true,
                _ => false,
            };
        }

        match (self.addr, addr) {
            (IpAddr::V4(own_addr), IpAddr::V4(other_addr)) => {
                if self.mask > 32 {
                    return false;
                }

                let netmask = u32::MAX << (32 - self.mask);
                (own_addr.to_bits() & netmask) == (other_addr.to_bits() & netmask)
            }
            (IpAddr::V6(own_addr), IpAddr::V6(other_addr)) => {
                if self.mask > 128 {
                    return false;
                }

                let netmask = u128::MAX << (128 - self.mask);
                (own_addr.to_bits() & netmask) == (other_addr.to_bits() & netmask)
            }
            _ => false,
        }
    }

    /// Returns a canonical version of the prefix by zeroing out any host bits.
    ///
    /// A prefix is considered "canonical" when all bits beyond the specified `mask`
    /// length are set to zero. This ensures the prefix represents the start of the
    /// network range rather than a specific host within that range.
    ///
    /// # Logic
    /// The method applies a bitmask to the address. For example, a `/24` prefix
    /// creates a mask of 24 ones followed by 8 zeros (`0xFFFFFF00`).
    ///
    /// # Examples
    /// ```
    /// use bgp_engine_rs::prefix::IpPrefix;
    /// use std::str::FromStr;
    ///
    /// let prefix = IpPrefix::from_str("192.168.1.45/24").unwrap();
    /// let clean = prefix.canonical();
    /// assert_eq!(clean.to_string(), "192.168.1.0/24");
    ///
    /// let any = IpPrefix::from_str("1.2.3.4/0").unwrap();
    /// assert_eq!(any.canonical().to_string(), "0.0.0.0/0");
    /// ```
    pub fn canonical(&self) -> Self {
        if self.mask == 0 {
            return Self {
                addr: match self.addr {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                },
                mask: 0,
            };
        }

        match self.addr {
            IpAddr::V4(addr) => {
                Self {
                    addr: IpAddr::V4(Ipv4Addr::from_bits(addr.to_bits() & (u32::MAX << (32u8 - self.mask)))),
                    mask: self.mask,
                }
            }
            IpAddr::V6(addr) => {
                Self {
                    addr: IpAddr::V6(Ipv6Addr::from_bits(addr.to_bits() & (u128::MAX << (128u8 - self.mask)))),
                    mask: self.mask,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::prefix::IpPrefix;
    use std::{
        net::{
            IpAddr,
            Ipv4Addr,
        },
        str::FromStr,
    };

    #[test]
    fn test_has_prefix_logic() {
        let p10_8 = IpPrefix::from_str("10.0.0.0/8").unwrap();
        let p10_1_2_0_24 = IpPrefix::from_str("10.1.2.0/24").unwrap();
        let p10_1_2_0_25 = IpPrefix::from_str("10.1.2.0/25").unwrap();

        assert!(p10_8.has_prefix(&p10_8));
        assert!(p10_8.has_prefix(&p10_1_2_0_24));
        assert!(p10_1_2_0_24.has_prefix(&p10_1_2_0_25));
        assert!(!p10_1_2_0_24.has_prefix(&p10_8));
    }

    #[test]
    fn test_has_prefix_disjoint() {
        let net_a = IpPrefix::from_str("192.168.1.0/24").unwrap();
        let net_b = IpPrefix::from_str("192.168.2.0/24").unwrap();
        assert!(!net_a.has_prefix(&net_b));
    }

    #[test]
    fn test_has_prefix_mixed_families() {
        let v4_any = IpPrefix::from_str("0.0.0.0/0").unwrap();
        let v6_net = IpPrefix::from_str("2001:db8::/32").unwrap();
        assert!(!v4_any.has_prefix(&v6_net));
    }

    #[test]
    fn test_has_addr_ipv4() {
        let prefix = IpPrefix::from_str("192.168.1.0/24").unwrap();

        assert!(prefix.has_addr(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))));
        assert!(prefix.has_addr(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))));
        assert!(!prefix.has_addr(&IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
        assert!(!prefix.has_addr(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_has_addr_ipv6() {
        let prefix = IpPrefix::from_str("2001:db8::/32").unwrap();
        assert!(prefix.has_addr(&"2001:db8::1".parse().unwrap()));
        assert!(prefix.has_addr(&"2001:db8:ffff:ffff::".parse().unwrap()));
        assert!(!prefix.has_addr(&"2001:def::1".parse().unwrap()));
    }

    #[test]
    fn parse_ipv4_prefix() {
        let prefix = IpPrefix::from_str("10.0.0.0/8").unwrap();
        assert_eq!(IpPrefix::new("10.0.0.0".parse().unwrap(), 8), prefix);
    }

    #[test]
    fn parse_ipv6_prefix() {
        let prefix = IpPrefix::from_str("2001:db8::/32").unwrap();
        assert_eq!(IpPrefix::new("2001:db8::".parse().unwrap(), 32), prefix);
    }

    #[test]
    fn ipv4_prefix_canonical() {
        let prefix = IpPrefix::from_str("10.0.0.1/8").unwrap().canonical();
        assert_eq!("10.0.0.0/8", prefix.to_string());
    }

    #[test]
    fn ipv6_prefix_canonical() {
        let prefix = IpPrefix::from_str("2001:db8::1/32").unwrap().canonical();
        assert_eq!("2001:db8::/32", prefix.to_string());

        let prefix2 = IpPrefix::from_str("2001:db8:abcd:1234::/48").unwrap().canonical();
        assert_eq!("2001:db8:abcd::/48", prefix2.to_string());
    }

    #[test]
    fn parse_invalid_formats() {
        assert!("192.168.1.0".parse::<IpPrefix>().is_err());
        assert!("192.168.1.0/24/10".parse::<IpPrefix>().is_err());
        assert!("abc/24".parse::<IpPrefix>().is_err());
        assert!("1.1.1.1/33".parse::<IpPrefix>().is_err());
        assert!("::1/129".parse::<IpPrefix>().is_err());
    }
}
