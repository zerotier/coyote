//! Coyote lets you make ACME servers, which are not guaranteed to not explode in
//! your face. You have to code that out yourself.
//!
//! coyote aims to solve a few problems (not all of these are solved yet; see "Task List" below):
//!
//! - Provide ACME with backing storage you prefer to use, by way of Rust's traits for storage implementation.
//! - Provide ACME in non-conforming scenarios (e.g., behind corporate firewalls)
//! - Provide ACME services with hooks into the validation system, so you can implement validations however you feel like.
//! - It's a library; make it as big or as small as you like. No need for multiple implementations.
//! - A FOSS alternative to the letsencrypt canonical implementation that is _also_ tested against LE's test suite.
//!
//! `acmed` comes as an example with coyote; it is a complete canonical implementation against PostgreSQL for backing storage. It (deliberately) allows all challenges through and is not meant for production usage.
//!
//! `coyote` is intended to let you build an ACME service without using `acmed` itself, leveraging the traits and tools available in this library for scaffolding. For example, work to implement a Redis based nonce validation system would just be a trait implementation, even though it is not available in this library.
//!

/// Core ACME implementation, including HTTP handlers, JOSE implementation and plenty of crypto
pub mod acme;
/// Errors and conversions between different Error types
pub mod errors;
/// Database types and traits
pub mod models;
pub(crate) mod test;
pub(crate) mod util;
