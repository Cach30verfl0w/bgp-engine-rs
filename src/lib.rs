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

//! This crate provides a modern BGP parser and engine with extra capabilities for running custom BGP solutions with additional support for
//! monitoring, metrics and other ways of tracing.
//!
//! ## RFC Support
//! BGP consists of different RFCs extending the base protocol. The table below shows the status of the implementations in the parser and
//! the engine itself. (Statuses: Not planned, not finished, partially finished and fully finished)
//!
//! | RFC                                                                                                  | Parser Impl    | Engine Impl  |
//! |------------------------------------------------------------------------------------------------------|----------------|--------------|
//! | [RFC1997: BGP Communities attribute](https://datatracker.ietf.org/doc/html/rfc1997)                  | Not finished   | Not finished |
//! | [RFC2918: Route Refresh Capability for BGP](https://datatracker.ietf.org/doc/html/rfc2918)           | Not finished   | Not finished |
//! | [RFC4271: A Border Gateway Protocol 4](https://datatracker.ietf.org/doc/html/rfc4271)                | Fully finished | Not finished |
//! | [RFC4360: BGP Extended Communities Attribute](https://datatracker.ietf.org/doc/html/rfc4360)         | Not finished   | Not finished |
//! | [RFC4760: Multiprotocol Extensions for BGP](https://www.rfc-editor.org/rfc/rfc4760)                  | Not finished   | Not finished |
//! | [RFC5492: Capabilities Advertisement with BGP](https://datatracker.ietf.org/doc/html/rfc5492)        | Fully finished | Not finished |
//! | [RFC6793: BGP Support for Four-Octet AS Number Space](https://datatracker.ietf.org/doc/html/rfc6793) | Not finished   | Not finished |
//! | [RFC7313: Enhanced Route Refresh Capability for BGP](https://datatracker.ietf.org/doc/html/rfc7313)  | Not finished   | Not finished |
//! | [RFC8092: BGP Large Communities Attribute](https://datatracker.ietf.org/doc/html/rfc8092)            | Not finished   | Not finished |

pub mod error;
pub mod parser;
