// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Centralised credential issuer and honest verifier.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use crate::amacs::Attribute;
use crate::amacs::SecretKey;
use crate::credential::AnonymousCredential;
use crate::parameters::IssuerParameters;
use crate::parameters::SystemParameters;

/// An anonymous credential issuer/verifier.
pub struct Issuer {
    system_parameters: SystemParameters,
    issuer_parameters: IssuerParameters,
    secret_key: SecretKey,
}

// XXX kill this stub
pub struct Proof {}

impl Issuer {
    pub fn issue(&self, attributes: Vec<Attribute>, proofs: Vec<Proof>) -> AnonymousCredential {
        unimplemented!()
    }
}
