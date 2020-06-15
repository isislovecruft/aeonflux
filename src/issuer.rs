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

use rand_core::CryptoRng;
use rand_core::RngCore;

use crate::amacs::Amac;
use crate::amacs::Attribute;
use crate::amacs::SecretKey;
use crate::credential::AnonymousCredential;
use crate::errors::CredentialError;
use crate::parameters::IssuerParameters;
use crate::parameters::SystemParameters;

/// An anonymous credential issuer/verifier.
pub struct Issuer {
    pub system_parameters: SystemParameters,
    pub issuer_parameters: IssuerParameters,
    pub amacs_key: SecretKey,
}

impl Issuer {
    pub fn new(
        system_parameters: &SystemParameters,
        issuer_parameters: &IssuerParameters,
        amacs_key: &SecretKey
    ) -> Issuer
    {
        Issuer {
            system_parameters: system_parameters.clone(),
            issuer_parameters: issuer_parameters.clone(),
            amacs_key: amacs_key.clone(),
        }
    }

    /// Issue a new anonymous credential on a set of `attributes` in an
    /// unblinded manner.
    ///
    /// By "unblinded" we mean that all attributes are revealed (unencrypted)
    /// and the issuer is able to perform verification/validation on all of
    /// them.
    ///
    /// # Inputs
    ///
    /// * The set of `attributes` to include on the credential,
    /// * A `csprng`.
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is an [`AnonymousCredential`], otherwise a
    /// [`CredentialError`].
    pub fn issue<C>(
        &self,
        attributes: Vec<Attribute>,
        csprng: &mut C,
    ) -> Result<AnonymousCredential, CredentialError>
    where
        C: CryptoRng + RngCore,
    {
        match Amac::tag(csprng, &self.system_parameters, &self.amacs_key, &attributes) {
            Ok(amac) => Ok(AnonymousCredential { amac, attributes }),
            Err(x) => Err(x.into()),
        }
    }
}
