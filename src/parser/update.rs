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

use crate::{
    error::Error,
    prefix::IpPrefix,
};
use bitflags::bitflags;
use nom::{
    IResult,
    Parser,
    bytes::complete as bytes,
    multi::many0,
    number::complete as number,
};
use std::{
    io,
    io::Write,
};

bitflags! {
    /// The flags of a BGP path attribute following RFC 4271, section 4.3. These flags are giving information about the attribute kind or
    /// processing of other routes or the serialization of the attribute.
    ///
    /// ## See also
    /// - [4.3. UPDATE Message Format, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
    #[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Hash)]
    pub struct PathAttributeFlags: u8 {
        /// When set, the attribute itself is optional. Otherwise, the attribute is well-known. Optional means, a BGP implementation is not
        /// required to interpret this attribute for the processing of the routes.
        const OPTIONAL = 0b1000_0000;

        /// When set, the attribute must be parsed along other BGP peers.
        const TRANSITIVE = 0b0100_0000;

        /// When set, the transitive attribute cant be processed by one of the BGP routers along that path.
        const PARTIAL = 0b0010_0000;

        /// When set, the length of the path attribute is serialized in 2 bytes.
        const EXT_LENGTH = 0b0001_0000;
    }
}

impl PathAttributeFlags {
    #[inline(always)]
    pub(crate) fn be_u8(input: &[u8]) -> IResult<&[u8], Self, Error> {
        let (input, flags) = number::be_u8(input)?;
        Ok((input, PathAttributeFlags::from_bits_truncate(flags)))
    }
}

/// ## See also
/// - [4.3. UPDATE Message Format, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug, Hash)]
pub struct PathAttribute {
    flags: PathAttributeFlags,
    data: PathAttributeData,
}

impl PathAttribute {
    pub fn decode(input: &[u8]) -> IResult<&[u8], Self, Error> {
        let (input, flags) = PathAttributeFlags::be_u8(input)?;
        let (input, kind) = number::be_u8(input)?;
        let (input, length) = match flags.contains(PathAttributeFlags::EXT_LENGTH) {
            false => number::be_u8(input).map(|(input, data)| (input, data as u16))?,
            true => number::be_u16(input)?,
        };

        let (input, data) = bytes::take(length)(input)?;
        let data = PathAttributeData::decode(data, kind)?;
        Ok((input, Self { flags, data }))
    }

    pub fn encode_in(&self, output: &mut impl Write) -> Result<(), io::Error> {
        let mut data = Vec::new();
        self.data.encode_in(&mut data)?;

        // Flags | Kind | Length | Data
        let mut flags = self.flags;
        let is_extended_length = data.len() > u8::MAX as usize;
        flags.set(PathAttributeFlags::EXT_LENGTH, is_extended_length);
        output.write(&flags.bits().to_be_bytes())?;
        output.write(&self.data.kind().to_be_bytes())?;
        match is_extended_length {
            true => output.write(&(data.len() as u16).to_be_bytes())?,
            false => output.write(&(data.len() as u8).to_be_bytes())?,
        };

        output.write(data.as_slice())?;
        Ok(())
    }
}

/// This enum represents the possible values for the BGP origin path attribute. It defines the origin of the path information in the update
/// message.
///
/// ## See also
/// - [4.3. UPDATE Message Format, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Hash)]
pub enum Origin {
    IGP,
    EGP,
    Incomplete,
    Other(u8),
}

impl From<Origin> for u8 {
    fn from(value: Origin) -> Self {
        match value {
            Origin::IGP => 0,
            Origin::EGP => 1,
            Origin::Incomplete => 2,
            Origin::Other(value) => value,
        }
    }
}

impl From<u8> for Origin {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::IGP,
            1 => Self::EGP,
            2 => Self::Incomplete,
            _ => Self::Other(value),
        }
    }
}

/// ## See also
/// - [4.3. UPDATE Message Format, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug, Hash)]
pub enum PathAttributeData {
    Origin(Origin),
    AtomicAggregate,
    Other { kind: u8, data: Vec<u8> },
}

impl PathAttributeData {
    #[rustfmt::skip]
    pub(crate) fn decode(input: &[u8], kind: u8) -> Result<Self, nom::Err<Error>> { // TODO: Check for remaining data
        Ok(match kind {
            1 => Self::Origin(Origin::from(number::be_u8(input)?.1)),
            6 => Self::AtomicAggregate,
            _ => Self::Other { kind, data: input.to_vec() }
        })
    }

    pub(crate) fn encode_in(&self, output: &mut impl Write) -> Result<(), io::Error> {
        match self {
            Self::Origin(origin) => output.write(&u8::from(*origin).to_be_bytes())?,
            Self::AtomicAggregate => 0,
            Self::Other { data, .. } => output.write(data)?,
        };
        Ok(())
    }

    #[inline(always)]
    pub fn kind(&self) -> u8 {
        match self {
            Self::Origin(_) => 1,
            Self::AtomicAggregate => 6,
            Self::Other { kind, .. } => *kind,
        }
    }
}

/// ## See also
/// - [4.3. UPDATE Message Format, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug, Hash)]
pub struct UpdateMessage {
    pub path_attrs: Vec<PathAttribute>,
    pub withdrawn_routes: Vec<IpPrefix>,
    pub announced_routes: Vec<IpPrefix>,
}

impl UpdateMessage {
    pub fn decode(input: &[u8]) -> IResult<&[u8], Self, Error> {
        let (input, withdrawn_routes_len) = number::be_u16(input)?;
        let (input, withdrawn_routes) = bytes::take(withdrawn_routes_len)(input)?;
        let (remaining, withdrawn_routes) = many0(|data| IpPrefix::decode(data, true)).parse(withdrawn_routes)?;
        if !remaining.is_empty() {
            todo!("Inform about invalid withdrawn routes len specified")
        }

        let (input, path_attributes_len) = number::be_u16(input)?;
        let (nlri, path_attrs) = bytes::take(path_attributes_len)(input)?;
        let (remaining, path_attrs) = many0(PathAttribute::decode).parse(path_attrs)?;
        if !remaining.is_empty() {
            todo!("Inform about invalid attributes len specified")
        }

        let (remaining, nlri) = many0(|data| IpPrefix::decode(data, true)).parse(nlri)?;
        if !remaining.is_empty() {
            todo!("Inform about invalid OPEN message len specified")
        }

        Ok((
            &[],
            Self {
                path_attrs,
                withdrawn_routes,
                announced_routes: nlri,
            },
        ))
    }

    pub fn encode_in(&self, output: &mut impl Write) -> Result<(), io::Error> {
        let mut withdrawn_routes = Vec::new();
        let mut announced_routes = Vec::new();
        let mut path_attrs = Vec::new();
        self.withdrawn_routes
            .iter()
            .map(|x| x.encode_in(&mut withdrawn_routes))
            .collect::<Result<(), _>>()?;
        self.announced_routes
            .iter()
            .map(|x| x.encode_in(&mut announced_routes))
            .collect::<Result<(), _>>()?;
        self.path_attrs
            .iter()
            .map(|x| x.encode_in(&mut path_attrs))
            .collect::<Result<(), _>>()?;

        output.write(&(withdrawn_routes.len() as u16).to_be_bytes())?; // TODO: Error when longer than an u16 allows?
        output.write(withdrawn_routes.as_slice())?;
        output.write(&(path_attrs.len() as u16).to_be_bytes())?; // TODO: Error when longer than an u16 allows?
        output.write(path_attrs.as_slice())?;
        output.write(announced_routes.as_slice())?;
        Ok(())
    }
}
