// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! A user of an anonymous credential.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

use crate::symmetric;
use crate::amacs::Attribute;
use crate::parameters::SystemParameters;
use crate::symmetric::Plaintext;

/// A constructor for creating a request for a new credential.
pub struct CredentialRequestConstructor {
    pub(crate) parameters: SystemParameters,
    pub(crate) attributes: Vec<Attribute>,
}

impl CredentialRequestConstructor {
    /// Begin a new [`CredentialRequest`].
    pub fn new(system_parameters: &SystemParameters) -> CredentialRequestConstructor {
        let attributes: Vec<Attribute> = Vec::with_capacity(system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        CredentialRequestConstructor { parameters: system_parameters.clone(), attributes }
    }

    /// Append a revealed-at-issuance scalar as an attribute in the eventual
    /// `AnonymousCredential`.
    // XXX check if we're overflowing the allotted attributes and return Result
    pub fn append_revealed_scalar(&mut self, scalar: Scalar) {
        self.attributes.push(Attribute::PublicScalar(scalar));
    }

    /// Append a revealed-at-issuance group element as an attribute in the
    /// eventual `AnonymousCredential`.
    // XXX check if we're overflowing the allotted attributes and return Result
    pub fn append_revealed_point(&mut self, point: RistrettoPoint) {
        self.attributes.push(Attribute::PublicPoint(point));
    }

    /// Append a message to be encoded as revealed plaintext into the
    /// `AnonymousCredential` attributes.
    ///
    /// This method is intended for appending arbitrary data to a
    /// credential, where the data is intended to be hidden upon credential
    /// presentation.  The user should store the returned [`Plaintext`]s for
    /// faster computation of the [`Ciphertext`]s later.
    ///
    /// # Warning
    ///
    /// The message is split up into 31-byte segments which are mapped to group
    /// elements.  Passing in a larger or smaller amount of data, resulting in
    /// more or fewer group elements, then results in a **different number of
    /// attributes** then may be allowed for by the configured
    /// [`SystemParameters`] for an instance of this protocol.
    // XXX check if we're overflowing the allotted attributes and return Result
    pub fn append_plaintext(&mut self, message: &Vec<u8>) -> Vec<symmetric::Plaintext> {
        let plaintexts = Plaintext::from_slice(&message[..]);

        for plaintext in plaintexts.iter() {
            self.attributes.push(Attribute::EitherPoint(plaintext.clone()));
        }

        plaintexts
    }

    /// Append a hidden-at-issuance scalar to the eventual `AnonymousCredential`
    /// attributes.
    ///
    /// # Returns
    ///
    /// The [`Ciphertext`] of the encrypted scalar.
    #[allow(unused_variables)]
    fn append_hidden_scalar(
        &mut self,
        scalar: Scalar,
        key: symmetric::Keypair,
    ) -> symmetric::Ciphertext
    {
       unimplemented!("Blinded issuance is not yet supported");
    }

    /// Append a hidden-at-issuance group element to the eventual
    /// `AnonymousCredential` attributes.
    ///
    /// # Returns
    ///
    /// The [`Ciphertext`] of the encrypted group element.
    #[allow(unused_variables)]
    fn append_hidden_point(
        &mut self,
        scalar: Scalar,
        key: symmetric::Keypair,
    ) -> symmetric::Ciphertext
    {
       unimplemented!("Blinded issuance is not yet supported");
    }

    /// Append a message to be encoded as ciphertext into the `AnonymousCredential` attributes.
    ///
    /// # Warning
    ///
    /// The message is split up into 31-byte segments which are mapped to group
    /// elements.  Passing in a larger or smaller amount of data, resulting in
    /// more or fewer group elements, then results in a **different number of
    /// attributes** then may be allowed for by the configured
    /// [`SystemParameters`] for an instance of this protocol.
    #[allow(unused_variables)]
    fn append_ciphertext(
        &mut self,
        message: &Vec<u8>,
        key: symmetric::Keypair,
    ) -> Vec<(symmetric::Plaintext, symmetric::Ciphertext)>
    {
       unimplemented!("Blinded issuance is not yet supported");
    }

    /// Finish creating this request for a [`Credential`].
    pub fn finish(self) -> CredentialRequest {
        CredentialRequest { attributes: self.attributes }
    }
}

/// A request for a new credential.
pub struct CredentialRequest {
    pub(crate) attributes: Vec<Attribute>,
}
