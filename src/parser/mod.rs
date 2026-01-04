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

pub mod open;

use crate::error::Error;
use nom::{
    IResult,
    bytes::complete as bytes,
    number::complete as number,
};
use std::{
    io,
    io::Write,
    ops::Range,
};

/// This enum contains all message kinds supported by this BGP parser. When the read message kind is not implemented, this message kind has
/// a fallback type contain the raw value.
///
/// ## See also
/// - [4. Message Formats, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4)
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Hash)]
pub enum MessageKind {
    Open,
    Update,
    Notification,
    KeepAlive,
    Other(u8),
}

impl From<u8> for MessageKind {
    fn from(raw: u8) -> Self {
        match raw {
            1 => Self::Open,
            2 => Self::Update,
            3 => Self::Notification,
            4 => Self::KeepAlive,
            raw => Self::Other(raw),
        }
    }
}

impl From<MessageKind> for u8 {
    fn from(kind: MessageKind) -> Self {
        match kind {
            MessageKind::Open => 1,
            MessageKind::Update => 2,
            MessageKind::Notification => 3,
            MessageKind::KeepAlive => 4,
            MessageKind::Other(raw) => raw,
        }
    }
}

impl MessageKind {
    #[inline(always)]
    pub fn decode(input: &[u8]) -> IResult<&[u8], Self, Error> {
        let (input, kind) = number::be_u8(input)?;
        Ok((input, MessageKind::from(kind)))
    }

    pub(crate) fn message_bounds(&self) -> Range<u16> {
        match self {
            Self::Open => 29..MessageHeader::MAX_LENGTH,
            Self::Update => 23..MessageHeader::MAX_LENGTH,
            Self::Notification => 21..MessageHeader::MAX_LENGTH,
            Self::KeepAlive => MessageHeader::MIN_LENGTH..MessageHeader::MIN_LENGTH,
            _ => MessageHeader::MIN_LENGTH..MessageHeader::MAX_LENGTH,
        }
    }
}

/// This struct represents the message header format as specified for BGP. It indicates the length and type of message. For compatibility
/// reasons the message header beings with a 16-byte marker field.
///
/// ## See also
/// - [4.1. Message Header Format, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4.1)
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Hash)]
pub struct MessageHeader {
    pub length: u16,
    pub kind: MessageKind,
}

impl MessageHeader {
    pub const MIN_LENGTH: u16 = 19;
    pub const MAX_LENGTH: u16 = 4096;

    /// This function decodes the BGP header from the specified byte slice and validates the generated output. When some of the requirements
    /// specified in the RFC are not matching for the message, this function returns an error.
    ///
    /// ## See also
    /// - [4.1. Message Header Format, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4.1)
    /// - [6.1. Message Header Error Handling, RFC 4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-6.1)
    pub fn decode(input: &[u8]) -> IResult<&[u8], Self, Error> {
        let (input, marker) = bytes::take(16usize)(input)?;
        if marker.iter().any(|marker_byte| *marker_byte != 0xF) {
            return Err(nom::Err::Error(Error::BadMessageMarker));
        }

        let (input, length) = number::be_u16(input)?;
        let (input, kind) = MessageKind::decode(input)?;
        let length_bounds = kind.message_bounds();
        if !length_bounds.contains(&length) {
            return Err(nom::Err::Error(Error::BadMessageLength(length, length_bounds.start, length_bounds.end)));
        }

        Ok((input, Self { length, kind }))
    }

    pub fn encode_in(&self, output: &mut impl Write) -> Result<(), io::Error> {
        output.write(&[0xFu8; 16])?; // the marker
        output.write(&self.length.to_be_bytes())?;
        output.write(&u8::from(self.kind).to_be_bytes())?;
        Ok(())
    }
}
