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
    net::Ipv4Addr,
};

/// This enum represents all possible optional parameters for the BGP open message. An open parameter is an extension point in the BGP open
/// message allowing for capabilities etc.
///
/// ## See also
/// - [4.2. OPEN Message Format, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4.2)
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug, Hash)]
pub enum OpenParameter {
    Other { kind: u8, data: Vec<u8> },
}

impl OpenParameter {
    pub fn decode(input: &[u8]) -> IResult<&[u8], Self, Error> {
        let (input, kind) = number::be_u8(input)?;
        let (input, length) = number::be_u8(input)?;
        let (input, data) = bytes::take(length)(input)?;
        Ok((
            input,
            match kind {
                _ => Self::Other { kind, data: data.to_vec() },
            },
        ))
    }

    pub fn encode_in(&self, output: &mut impl Write) -> Result<(), io::Error> {
        match self {
            Self::Other { kind, data } => {
                output.write(&kind.to_be_bytes())?;
                output.write(data.as_slice())?;
            }
        }
        Ok(())
    }
}

/// This struct implements the BGP open message indicating a BGP speaker and its capabilities to the neighbor router. It is being sent after
/// the TCP connection is established.
///
/// ## See also
/// - [4.2. OPEN Message Format, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4.2)
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug, Hash)]
pub struct OpenMessage {
    pub version: u8,
    pub as_number: u16,
    pub hold_time: u16,
    pub bgp_identifier: Ipv4Addr,
    pub parameters: Vec<OpenParameter>,
}

impl OpenMessage {
    /// This function decodes the BGP open message following the RFC and validates the parameters created by the parser. When valid, this
    /// function returns the open message.
    ///
    /// ## See also
    /// - [4.2. OPEN Message Format, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4.2)
    /// - [6.2. OPEN Message Error Handling, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-6.2)
    pub fn decode(input: &[u8]) -> IResult<&[u8], Self, Error> {
        let (input, version) = number::be_u8(input)?;
        if version != 4 {
            return Err(nom::Err::Error(Error::UnsupportedVersion(version)));
        }

        let (input, as_number) = number::be_u16(input)?;
        let (input, hold_time) = number::be_u16(input)?;
        let (input, bgp_identifier) = number::be_u32(input)?;
        let bgp_ident = Ipv4Addr::from_bits(bgp_identifier);
        if bgp_ident.is_unspecified() || bgp_ident.is_multicast() || bgp_ident.is_broadcast() || bgp_ident.is_loopback() {
            return Err(nom::Err::Error(Error::BadBgpIdentifier(bgp_ident)));
        }

        let (input, opt_params_len) = number::be_u8(input)?;
        let (input, opt_params) = bytes::take(opt_params_len)(input)?;
        let (remaining, parameters) = many0(OpenParameter::decode)
            .parse(opt_params)
            .map_err(|error| error.map(|_| Error::MalformedOptionalParameter))?;
        if !remaining.is_empty() {
            return Err(nom::Err::Error(Error::ParameterLength(remaining.len() as u8)));
        }

        Ok((
            input,
            Self {
                version,
                as_number,
                hold_time,
                bgp_identifier: bgp_ident,
                parameters,
            },
        ))
    }

    pub fn encode_in(&self, output: &mut impl Write) -> Result<(), io::Error> {
        output.write(&self.version.to_be_bytes())?;
        output.write(&self.as_number.to_be_bytes())?;
        output.write(&self.hold_time.to_be_bytes())?;
        output.write(&self.bgp_identifier.to_bits().to_be_bytes())?;

        let mut opt_params = Vec::new();
        self.parameters
            .iter()
            .map(|param| param.encode_in(&mut opt_params))
            .collect::<Result<(), _>>()?;
        output.write(&(opt_params.len() as u8).to_be_bytes())?; // TODO: Error when longer than an u8 allows?
        output.write(opt_params.as_slice())?;
        Ok(())
    }
}
