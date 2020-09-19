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

use serde::de::Deserialize;
use serde::de::Deserializer;
use serde::de::Visitor;
use serde::ser::Serialize;
use serde::ser::Serializer;

use crate::amacs::sizeof_secret_key;
use crate::amacs::Amac;
use crate::amacs::Attribute;
use crate::amacs::SecretKey;
use crate::credential::AnonymousCredential;
use crate::errors::CredentialError;
use crate::parameters::sizeof_system_parameters;
use crate::parameters::IssuerParameters;
use crate::parameters::SystemParameters;

/// An anonymous credential issuer/verifier.
pub struct Issuer {
    pub system_parameters: SystemParameters,
    pub issuer_parameters: IssuerParameters,
    pub amacs_key: SecretKey,
}

impl Issuer {
    /// Create a new anonymous credential issuer and verifier.
    ///
    /// # Inputs
    ///
    /// * Some previously generated [`SystemParameters`].
    /// * A cryptographically secure PRNG.
    ///
    /// # Returns
    ///
    /// An new issuer.
    pub fn new<C>(
        system_parameters: &SystemParameters,
        csprng: &mut C,
    ) -> Issuer
    where
        C: CryptoRng + RngCore,
    {
        let amacs_key = SecretKey::generate(csprng, &system_parameters);
        let issuer_parameters = IssuerParameters::generate(&system_parameters, &amacs_key);

        Issuer {
            system_parameters: system_parameters.clone(),
            issuer_parameters: issuer_parameters,
            amacs_key: amacs_key,
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
    ) -> Result<(AnonymousCredential, ProofOfIssuance), CredentialError>
    where
        C: CryptoRng + RngCore,
    {
        let amac = Amac::tag(csprng, &self.system_parameters, &self.amacs_key, &attributes)?;
        let cred = AnonymousCredential { amac, attributes };
        let proof = ProofOfIssuance::prove(&self, &cred);

        Ok((cred, proof))
    }

    /// Verify a user's presentation of an anonymous credential.
    ///
    /// The user's presentation may reveal or hide any of the attributes, so
    /// long as the overall structure remains the same (e.g. a user cannot
    /// reorder a credential with attributes being a scalar then a group element
    /// to be instead a group element and then a scalar, nor can they add or
    /// remove attributes).
    ///
    /// # Inputs
    ///
    /// * A user's [`ProofOfValidCredential`].
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is empty, otherwise a `CredentialError`.
    pub fn verify(
        &self,
        presentation: &ProofOfValidCredential,
    ) -> Result<(), CredentialError>
    {
        presentation.verify(&self)
    }
}

impl Issuer {
    /// Create an [`Issuer`] from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Issuer, CredentialError> {
        let system_parameters = SystemParameters::from_bytes(&bytes)?;
        let offset = sizeof_system_parameters(system_parameters.NUMBER_OF_ATTRIBUTES);
        let issuer_parameters = IssuerParameters::from_bytes(&bytes[offset..offset+64])?;
        let amacs_key = SecretKey::from_bytes(&bytes[offset+64..])?;

        Ok(Issuer { system_parameters, issuer_parameters, amacs_key })
    }

    /// Serialise this [`Issuer`] to a byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = 64 +
            sizeof_system_parameters(self.system_parameters.NUMBER_OF_ATTRIBUTES) +
            sizeof_secret_key(self.system_parameters.NUMBER_OF_ATTRIBUTES);
            
        let mut bytes: Vec<u8> = Vec::with_capacity(size);

        bytes.extend(self.system_parameters.to_bytes());
        bytes.extend(self.issuer_parameters.to_bytes());
        bytes.extend(self.amacs_key.to_bytes());

        bytes
    }
}

impl_serde_with_to_bytes_and_from_bytes!(Issuer, "A valid byte sequence representing an Issuer");
