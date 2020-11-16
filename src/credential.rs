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
    pub fn show(
        &self,
        system_parameters: &SystemParameters,
        issuer_parameters: &IssuerParameters,
        keypair: Option<&SymmetricKeypair>,
        mut csprng: impl CryptoRng + RngCore,
    ) -> Result<ProofOfValidCredential, CredentialError>
    {
        ProofOfValidCredential::prove(&system_parameters, &issuer_parameters, &self, keypair, &mut csprng)
    }

    /// Change one of this credential's attributes to be revealed upon presentation.
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is an empty tuple, or a string describing the error.
    pub fn reveal_attribute(
        &mut self,
        index: usize,
    ) -> Result<(), &'static str>
    {
        let attribute = match self.attributes.get(index) {
            Some(x) => x,
            None => return Err("Could not find attribute"),
        };

        match attribute {
            Attribute::SecretScalar(x) => self.attributes[index] = Attribute::PublicScalar(*x),
            Attribute::SecretPoint(x)  => self.attributes[index] = Attribute::PublicPoint(x.M1),
            _ => return Ok(()),
        }

        Ok(())
    }

    /// Change one of this credential's attributes to be hidden upon presentation.
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is an empty tuple, or a string describing the error.
    pub fn hide_attribute(
        &mut self,
        index: usize,
    ) -> Result<(), &'static str>
    {
        let attribute = match self.attributes.get(index) {
            Some(x) => x,
            None => return Err("Could not find attribute"),
        };

        match attribute {
            Attribute::PublicScalar(x) => self.attributes[index] = Attribute::SecretScalar(*x),
            Attribute::EitherPoint(p)  => self.attributes[index] = Attribute::SecretPoint(p.clone()),
            Attribute::PublicPoint(_)  => return Err("Public point attributes cannot be converted \
                                                     to secret point attributes because this changes \
                                                     the number of attributes on the credential."),
            _ => return Ok(()),
        }

        Ok(())
    }
}
