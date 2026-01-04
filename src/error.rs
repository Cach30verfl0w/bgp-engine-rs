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

use nom::error::{ErrorKind, ParseError};
use thiserror::Error;

/// This enum contains all errors which can happen by the engine and the parser implementation. Some of these errors can be converted into
/// a BGP notification message.
///
/// ## See also
/// - [6. BGP Error Handling, RFC4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-6)
#[derive(Error, Debug)]
pub enum Error {
    /// Following to section 4.1. of the Border Gateway Protocol RFC, the marker field MUST be set to all ones. When it's not the case, the
    /// parser returns this error to the caller.
    ///
    /// ## See also
    /// - [4.1. Message Header Format, RFC4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4.1)
    #[error("BGP Error => Message marker specified in header is illegal")]
    BadMessageMarker,
    
    /// Following to section 6.1. of the Border Gateway Protocol RFC, the length field has some constrains regarding the length based on the
    /// message type and some general assumptions.
    /// 
    /// ## See also
    /// - [6.1. Message Header Error Handling, RFC4271: A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271#section-4.1)
    #[error("BGP Error => Message length exceeds the expected bounds (Expected: {1} < {0} < {2})")]
    BadMessageLength(u16, u16, u16),

    #[error("Parse Error => Error while parsing ({0:?})")]
    Nom(ErrorKind)
}

impl<T> ParseError<T> for Error {
    fn from_error_kind(_input: T, kind: ErrorKind) -> Self {
        Error::Nom(kind)
    }

    fn append(_input: T, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}
