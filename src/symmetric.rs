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

use crate::encoding::decode_from_group;
use crate::encoding::encode_to_group;
use crate::errors::CredentialError;
use crate::parameters::SystemParameters;

/// A secret key, used for hidden group element attributes during credential
/// presentation.
#[derive(Clone)]
pub(crate) struct SecretKey {
    pub(crate) a: Scalar,
    pub(crate) a0: Scalar,
    pub(crate) a1: Scalar,
}

// XXX impl Drop for SecretKey

/// A public key, used for verification of a symmetrica encryption.
#[derive(Clone, Copy)]
pub(crate) struct PublicKey {
    pub pk: RistrettoPoint,
}

/// A keypair for encryption of hidden group element attributes.
#[derive(Clone)]
pub struct Keypair {
    pub(crate) secret: SecretKey,
    pub(crate) public: PublicKey,
}

/// A master secret, which can be used with the [`Keypair::derive`] method to
/// produce a [`Keypair`].
pub type MasterSecret = [u8; 64];

// XXX impl Drop for MasterSecret

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

        let pk: RistrettoPoint =
            (system_parameters.G_a  * a) +
            (system_parameters.G_a0 * a0) +
            (system_parameters.G_a1 * a1);

        Keypair {
            secret: SecretKey { a, a0, a1 },
            public: PublicKey { pk },
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
        &self,
        message: &[u8],
    ) -> (Ciphertext, RistrettoPoint, RistrettoPoint, Scalar)
    {
        // We let M1 = EncodeToG(m), M2 = HashToG(m), and m3 = HashToZZq(m).
        let (M1, _) = encode_to_group(&message);
        let M2: RistrettoPoint = RistrettoPoint::hash_from_bytes::<Sha512>(&message);
        let m3: Scalar = Scalar::hash_from_bytes::<Sha512>(&message);

        let E1: RistrettoPoint = M2 * (self.secret.a0 + self.secret.a1 * m3);
        let E2: RistrettoPoint = E1 * self.secret.a + M1;

        (Ciphertext { E1, E2 }, M1, M2, m3)
    }

    /// DOCDOC
    // TODO return the counter
    pub fn decrypt(
        &self,
        ciphertext: &Ciphertext,
    ) -> Result<[u8; 30], CredentialError>
    {
        let (m_prime, _) = decode_from_group(&(ciphertext.E2 - (ciphertext.E1 * self.secret.a)));
        let m3_prime = Scalar::hash_from_bytes::<Sha512>(&m_prime);

        let M1_prime = RistrettoPoint::hash_from_bytes::<Sha512>(&m_prime);
        let E1_prime = M1_prime * (self.secret.a0 + self.secret.a1 * m3_prime);

        match ciphertext.E1 == E1_prime {
            true => Ok(m_prime),
            false => Err(CredentialError::UndecryptableAttribute),
        }
    }
}

/// DOCDOC
pub struct Ciphertext {
    pub E1: RistrettoPoint,
    pub E2: RistrettoPoint,
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::thread_rng;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut csprng = thread_rng();
        let system_parameters = SystemParameters::hash_and_pray(&mut csprng, 2).unwrap();
        let (keypair, master_secret) = Keypair::generate(&system_parameters, &mut csprng);
        let message = [0u8; 30];
        let (ciphertext, _, _, _) = keypair.encrypt(&message);
        let plaintext = keypair.decrypt(&ciphertext);

        assert!(plaintext.is_ok());
        assert_eq!(message, plaintext.unwrap());
    }
}
