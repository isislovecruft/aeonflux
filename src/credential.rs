// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Attribute-based anonymous credentials.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use rand_core::CryptoRng;
use rand_core::RngCore;

use crate::amacs::Amac;
use crate::amacs::Attribute;
use crate::errors::CredentialError;
use crate::parameters::IssuerParameters;
use crate::parameters::SystemParameters;
use crate::nizk::ProofOfValidCredential;
use crate::symmetric::Keypair as SymmetricKeypair;

/// An anonymous credential.
pub struct AnonymousCredential {
    pub(crate) amac: Amac,
    pub(crate) attributes: Vec<Attribute>,
}

impl AnonymousCredential {
    /// Present this credential to an issuer.
    pub fn show<C>(
        &self,
        system_parameters: &SystemParameters,
        issuer_parameters: &IssuerParameters,
        keypair: Option<&SymmetricKeypair>,
        csprng: &mut C,
    ) -> Result<ProofOfValidCredential, CredentialError>
    where
        C: CryptoRng + RngCore,
    {
        ProofOfValidCredential::prove(&system_parameters, &issuer_parameters, &self, keypair, csprng)
    }
}
