// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Symmetric-keyed verifiable encryption with unique ciphertexts.
//!
//! In order to facilitate credential presentation with hidden group element
//! attributes, we require a symmetric-keyed encryption scheme that:
//!
//! * has public verifiability, meaning that we can prove that a ciphertext is
//!   an encryption of a certified plaintext with a key that is consistent with
//!   some public parameters,
//!
//! * has unique ciphertexts, meaning that for every plaintext there is at most
//!   one ciphertext that will decrypt correctly, and
//!
//! * is correct under adversarially chosen keys, meaning that it is hard to
//!   find a key and a message that cause decryption to fail.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_core::CryptoRng;
use rand_core::RngCore;

use sha2::Sha512;

use crate::parameters::SystemParameters;

/// A secret key, used for hidden group element attributes during credential
/// presentation.
pub(crate) struct SecretKey {
    a: Scalar,
    a0: Scalar,
    a1: Scalar,
}

/// A public key, used for verification of a symmetrica encryption.
pub(crate) struct PublicKey {
    A: RistrettoPoint,
    A0: RistrettoPoint,
    A1: RistrettoPoint,
}

/// A keypair for encryption of hidden group element attributes.
pub struct Keypair {
    pub(crate) secret: SecretKey,
    pub(crate) public: PublicKey,
}

/// A master secret, which can be used with the [`Keypair::derive`] method to
/// produce a [`Keypair`].
pub type MasterSecret = [u8; 64];

impl Keypair {
    /// Derive this [`Keypair`] from a master secret.
    ///
    /// # Inputs
    ///
    /// * A [`MasterSecret`], and
    /// * some [`SystemParameters`]
    ///
    /// # Returns
    ///
    /// A `Keypair`.
    pub fn derive(
        master_secret: &MasterSecret,
        system_parameters: &SystemParameters
    ) -> Keypair
    {
        let a: Scalar = Scalar::hash_from_bytes::<Sha512>(&master_secret[..]);
        let a0: Scalar = Scalar::hash_from_bytes::<Sha512>(a.as_bytes());
        let a1: Scalar = Scalar::hash_from_bytes::<Sha512>(a0.as_bytes());

        let A: RistrettoPoint = system_parameters.G_a * a;
        let A0: RistrettoPoint = system_parameters.G_a0 * a0;
        let A1: RistrettoPoint = system_parameters.G_a1 * a1;

        Keypair {
            secret: SecretKey { a, a0, a1 },
            public: PublicKey { A, A0, A1 },
        }
    }

    /// Generate a new keypair.
    ///
    /// # Inputs
    ///
    /// * Some [`SystemParameters`], and
    /// * A cryptographically secure pseudo-random number generator.
    ///
    /// # Returns
    ///
    /// A newly generated [`Keypair`] and its associated [`MasterSecret].
    pub fn generate<R>(
        system_parameters: &SystemParameters,
        csprng: &mut R,
    ) -> (Keypair, MasterSecret)
    where
        R: RngCore + CryptoRng,
    {
        let mut master_secret: MasterSecret = [0u8; 64];

        csprng.fill_bytes(&mut master_secret);

        let keypair = Keypair::derive(&master_secret, system_parameters);

        (keypair, master_secret)
    }

    /// DOCDOC
    pub fn encrypt(
        message: &[u8],
    ) -> Ciphertext
    {
        // We let M1 = EncodeToG(m), M2 = HashToG(m), and m3 = HashToZZq(m).
        let M1: RistrettoPoint = encode_to_group(&message);
        let M2: RistrettoPoint = RistrettoPoint::hash_from_bytes(&message);
        let m3: Scalar = Scalar::hash_from_bytes::<Sha512>(&message);

        let E1: RistrettoPoint = M2 * (self.secret.a0 + self.secret.a1 * m3);
        let E2: RistrettoPoint = E1 * self.secret.a + M1;

        Ciphertext { E1, E2 }
    }

    pub fn decrypt(
        ciphertext: &Ciphertext,
    ) -> RistrettoPoint
    {
        unimplemented!()
    }
}

pub struct Ciphertext {
    E1: RistrettoPoint,
    E2: RistrettoPoint,
}
