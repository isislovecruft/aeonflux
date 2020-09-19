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
use curve25519_dalek::traits::Identity;

use rand_core::CryptoRng;
use rand_core::RngCore;

use sha2::Sha512;

use subtle::Choice;
use subtle::ConstantTimeEq;

use zeroize::Zeroize;

use crate::encoding::decode_from_group;
use crate::encoding::encode_to_group;
use crate::errors::CredentialError;
use crate::parameters::SystemParameters;

/// A secret key, used for hidden group element attributes during credential
/// presentation.
#[derive(Clone, Zeroize)]
pub(crate) struct SecretKey {
    pub(crate) a: Scalar,
    pub(crate) a0: Scalar,
    pub(crate) a1: Scalar,
}

/// Overwrite the secret key material with zeroes (and the identity element)
/// when it drops out of scope.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A public key, used for verification of a symmetrica encryption.
#[derive(Clone, Copy)]
pub struct PublicKey {
    pub pk: RistrettoPoint,
}

/// A keypair for encryption of hidden group element attributes.
#[derive(Clone)]
pub struct Keypair {
    /// The secret portion of this keypair.
    pub(crate) secret: SecretKey,
    /// The public portion of this keypair.
    pub public: PublicKey,
}

/// A master secret, which can be used with the [`Keypair::derive`] method to
/// produce a [`Keypair`].
pub type MasterSecret = [u8; 64];

// XXX impl Drop for MasterSecret

/// A plaintext encodes up to thrity bytes of information into a group element.
#[derive(Clone, Debug)]
pub struct Plaintext {
    /// M1 = EncodeToG(m).
    pub(crate) M1: RistrettoPoint,
    /// M2 = HashToG(m).
    pub(crate) M2: RistrettoPoint,
    /// m3 = HashToZZq(m).
    pub(crate) m3: Scalar,
}

// We can't derive this because generally in elliptic curve cryptography group
// elements aren't used as secrets, thus curve25519-dalek doesn't impl Zeroize
// for RistrettoPoint.
impl Zeroize for Plaintext {
    fn zeroize(&mut self) {
        self.M1 = RistrettoPoint::identity();
        self.M2 = RistrettoPoint::identity();
        self.m3.zeroize();
    }
}

/// Overwrite the plaintext with zeroes (and the identity element)
/// when it drops out of scope.
impl Drop for Plaintext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<&[u8; 30]> for Plaintext {
    fn from(source: &[u8; 30]) -> Plaintext {
        let (M1, _) = encode_to_group(source);
        let M2: RistrettoPoint = RistrettoPoint::hash_from_bytes::<Sha512>(source);
        let m3: Scalar = Scalar::hash_from_bytes::<Sha512>(source);

        Plaintext { M1, M2, m3 }
    }
}

// XXX TODO return attempt counter
impl From<&Plaintext> for [u8; 30] {
    fn from(source: &Plaintext) -> [u8; 30] {
        decode_from_group(&source.M1).0
    }
}

impl ConstantTimeEq for Plaintext {
    fn ct_eq(&self, other: &Plaintext) -> Choice {
        self.M1.compress().ct_eq(&other.M1.compress()) &
        self.M2.compress().ct_eq(&other.M2.compress()) &
        self.m3.ct_eq(&other.m3)
    }
}

impl PartialEq for Plaintext {
    fn eq(&self, other: &Plaintext) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Plaintext {}

/// A symmetrically encrypted verifiable ciphertext, corresponding to one unique
/// [`Plaintext`] and [`Keypair`].
pub struct Ciphertext {
    pub(crate) E1: RistrettoPoint,
    pub(crate) E2: RistrettoPoint,
}

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

    /// Use this key to encrypt a plaintext.
    ///
    /// # Inputs
    ///
    /// * The [`Plaintext`] to encrypt.
    ///
    /// # Returns
    ///
    /// The corresponding, unique ciphertext.
    pub fn encrypt(
        &self,
        plaintext: &Plaintext,
    ) -> Ciphertext
    {
        let E1: RistrettoPoint = plaintext.M2 * (self.secret.a0 + self.secret.a1 * plaintext.m3);
        let E2: RistrettoPoint = E1 * self.secret.a + plaintext.M1;

        Ciphertext { E1, E2 }
    }

    /// Use this key to decrypt a ciphertext.
    ///
    /// # Inputs
    ///
    /// * The [`Ciphertext`] to be decrypted.
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is the [`Plaintext`], otherwise a [`CredentialError`].
    // XXX TODO return the counter
    pub fn decrypt(
        &self,
        ciphertext: &Ciphertext,
    ) -> Result<Plaintext, CredentialError>
    {
        let M1_prime = ciphertext.E2 - (ciphertext.E1 * self.secret.a);
        let (m_prime, _) = decode_from_group(&M1_prime);
        let m3_prime = Scalar::hash_from_bytes::<Sha512>(&m_prime);

        let M2_prime = RistrettoPoint::hash_from_bytes::<Sha512>(&m_prime);
        let E1_prime = M2_prime * (self.secret.a0 + self.secret.a1 * m3_prime);

        match ciphertext.E1 == E1_prime {
            true => Ok(Plaintext { M1: M1_prime, M2: M2_prime, m3: m3_prime }),
            false => Err(CredentialError::UndecryptableAttribute),
        }
    }
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
        let plaintext: Plaintext = (&message).into();
        let ciphertext = keypair.encrypt(&plaintext);
        let decrypted = keypair.decrypt(&ciphertext);

        assert!(decrypted.is_ok());
        assert_eq!(plaintext, decrypted.unwrap());
    }
}
