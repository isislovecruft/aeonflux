// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#![no_std]

#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", feature(doc_cfg))]

// Refuse to compile if documentation is missing, but only on nightly.
//
// This means that missing docs will still fail CI, but means we can use
// README.md as the crate documentation.
//#![cfg_attr(feature = "nightly", deny(missing_docs))]

#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]

// TODO Get rid of the syntax that uses the nightly-only try_trait.
#![feature(try_trait)]
// We denote group elements with capital and scalars with lowercased names.
#![allow(non_snake_case)]

#![cfg_attr(any(not(feature = "std"), feature = "alloc"), feature(alloc))]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;
#[cfg(any(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

extern crate curve25519_dalek;
#[cfg(test)]
extern crate rand;
extern crate rand_core;
extern crate serde;
extern crate sha2;
extern crate subtle;
extern crate zeroize;
extern crate zkp;

// The macros have to come first.
#[macro_use]
mod macros;

pub mod amacs;
pub mod credential;
pub mod encoding;
pub mod errors;
pub mod issuer;
pub mod nizk;
pub mod parameters;
pub mod prelude;
pub mod symmetric;
pub mod user;
