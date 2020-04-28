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
pub mod macros;

pub mod amacs;
pub mod credential;
pub mod errors;
//pub mod issuer;
pub mod nizk;
//pub mod nonces;
pub mod parameters;
//pub mod pedersen;
pub mod prelude;
pub mod symmetric;
//pub mod user;
