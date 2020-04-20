// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Implementation of the MAC_GGM scheme in https://eprint.iacr.org/2019/1416.pdf.
//!
//! Algebraic Message Authentication Codes (or AMACs for short) are MACs with an
//! algebraic polynomial structure.  They are asymmetrically keyed, meaning the
//! keypair used to create an AMAC must also be the keypair used to verify its
//! correctness.  Due to the asymmetric setting and the algebraic structure, the
//! polynomial coefficients of a valid AMAC may be rerandomised by another
//! party, without requiring access to the key.  This is the underlying
//! primitive used for our anonymous credential scheme.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::traits::MultiscalarMul;

use rand_core::CryptoRng;
use rand_core::RngCore;

use serde::{self, Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Visitor;

use zeroize::Zeroize;

use crate::errors::MacError;
use crate::parameters::SystemParameters;

/// An AMAC secret key is \(( (w, w', x_0, x_1, \vec{y_{n}}, W ) \in \mathbb{Z}_q \))
/// where \(( W := G_w * w \)). (The \(( G_w \)) is one of the orthogonal generators
/// from the [`SystemParameters`].)
#[derive(Clone)]
pub struct SecretKey {
    pub(crate) w: Scalar,
    pub(crate) w_prime: Scalar,
    pub(crate) x_0: Scalar,
    pub(crate) x_1: Scalar,
    pub(crate) y: Vec<Scalar>,
    pub(crate) W: RistrettoPoint,
}

// We can't derive this because generally in elliptic curve cryptography group
// elements aren't used as secrets, thus curve25519-dalek doesn't impl Zeroize
// for RistrettoPoint.
impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.w.zeroize();
        self.w_prime.zeroize();
        self.x_0.zeroize();
        self.x_1.zeroize();
        self.y.zeroize();

        self.W = RistrettoPoint::identity();
    }
}

/// Overwrite the secret key material with zeroes (and the identity element)
/// when it drops out of scope.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SecretKey {
    /// Given the [`SystemParameters`], generate a secret key.
    ///
    /// The size of the secret key is linear in the size of the desired number
    /// of attributes for the anonymous credential.
    pub fn generate<R>(csprng: &mut R, system_parameters: &SystemParameters) -> SecretKey
    where
        R: RngCore + CryptoRng,
    {
        let w:       Scalar = Scalar::random(csprng);
        let w_prime: Scalar = Scalar::random(csprng);
        let x_0:     Scalar = Scalar::random(csprng);
        let x_1:     Scalar = Scalar::random(csprng);

        let mut y: Vec<Scalar> = Vec::with_capacity(system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        for _ in 0..system_parameters.NUMBER_OF_ATTRIBUTES {
            y.push(Scalar::random(csprng));
        }

        let W: RistrettoPoint = &system_parameters.G_w * &w;

        SecretKey { w, w_prime, x_0, x_1, y, W }
    }

    /// DOCDOC
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, MacError> {
        unimplemented!()
    }

    /// DOCDOC
    pub fn to_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }
}

impl_serde_with_to_bytes_and_from_bytes!(SecretKey, "A valid byte sequence representing an amacs::SecretKey");

/// Attributes may be either group elements \(( M_i \in \mathbb{G} \)) or
/// scalars \(( m_j \in \mathbb{Z}_q \)), written as \(( M_j = G_m_j * m_j \))
/// where \(( G_m_j \)) is taken from the [`SystemParameters`].
///
/// When a `Credential` is shown, its attributes may be either revealed or
/// hidden from the credential issuer.  These represent all the valid attribute
/// types.
pub enum Attribute {
    PublicScalar(Scalar),
    SecretScalar(Scalar),
    PublicPoint(RistrettoPoint),
    SecretPoint(RistrettoPoint),
}

/// Messages are computed from `Attribute`s by scalar multiplying the scalar
/// portions by their respective generator in `SystemParameters.G_m`.
pub struct Messages(pub(crate) Vec<RistrettoPoint>);

impl Messages {
    pub(crate) fn from_attributes(
        attributes: &Vec<Attribute>,
        system_parameters: &SystemParameters
    ) -> Messages
    {
        let mut messages: Vec<RistrettoPoint> = Vec::with_capacity(attributes.len());

        for (i, attribute) in attributes.iter().enumerate() {
            let M_i: RistrettoPoint = match attribute {
                Attribute::PublicScalar(m) => m * system_parameters.G_m[i],
                Attribute::SecretScalar(m) => m * system_parameters.G_m[i],
                Attribute::PublicPoint(M)  => *M,
                Attribute::SecretPoint(M)  => *M,
            };
            messages.push(M_i);
        }
        Messages(messages)
    }
}

/// An algebraic message authentication code, \(( (t,U,V) \in \mathbb{Z}_q \times \mathbb{G} \times \mathbb{G} \)).
pub struct Amac {
    pub t: Scalar,
    pub U: RistrettoPoint,
    pub V: RistrettoPoint,
}

impl Amac {
    /// Compute \(( V = W + (U (x_0 + x_1 t)) + \sigma{i=1}{n} M_i y_i \)).
    fn compute_V(
        system_parameters: &SystemParameters,
        secret_key: &SecretKey,
        attributes: &Vec<Attribute>,
        t: &Scalar,
        U: &RistrettoPoint,
    ) -> RistrettoPoint
    {
        let messages: Messages = Messages::from_attributes(attributes, system_parameters);

        // V = W + (U (x_0 + x_1 t))
        let mut V: RistrettoPoint = secret_key.W + (U * (secret_key.x_0 + (secret_key.x_1 * t)));

        // V = W + (U (x_0 + x_1 t)) + \sigma{i=1}{n} M_i y_i
        V += RistrettoPoint::multiscalar_mul(&secret_key.y[..], &messages.0[..]);
        V
    }

    /// Compute an algebraic message authentication code with a secret key for a
    /// vector of messages.
    pub fn tag<R>(
        csprng: &mut R,
        system_parameters: &SystemParameters,
        secret_key: &SecretKey,
        messages: &Vec<Attribute>,
    ) -> Result<Amac, MacError>
    where
        R: RngCore + CryptoRng,
    {
        if messages.len() > system_parameters.NUMBER_OF_ATTRIBUTES as usize {
            return Err(MacError::MessageLengthError{length: system_parameters.NUMBER_OF_ATTRIBUTES as usize});
        }

        let t: Scalar = Scalar::random(csprng);
        // XXX QUESTION are we okay with using the ristretto flavour or the elligator2 mapping here?
        let U: RistrettoPoint = RistrettoPoint::random(csprng);
        let V: RistrettoPoint = Amac::compute_V(system_parameters, secret_key, messages, &t, &U);

        Ok(Amac { t, U, V })
    }

    /// Verify this algebraic MAC w.r.t. a secret key and vector of messages.
    pub fn verify(
        &self,
        system_parameters: &SystemParameters,
        secret_key: &SecretKey,
        messages: &Vec<Attribute>,
    ) -> bool {
        let V_prime = Amac::compute_V(system_parameters, secret_key, messages, &self.t, &self.U);

        self.V == V_prime
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::thread_rng;

    #[test]
    fn secret_key_generate() {
        let mut rng = thread_rng();
        let params = SystemParameters::generate(&mut rng, 2).unwrap();
        let sk = SecretKey::generate(&mut rng, &params);

        assert!(sk.w != Scalar::zero());
    }

    #[test]
    fn amac_verification() {
        let mut rng = thread_rng();
        let params = SystemParameters::generate(&mut rng, 8).unwrap();
        let sk = SecretKey::generate(&mut rng, &params);
        let mut messages = Vec::new();

        messages.push(Attribute::PublicScalar(Scalar::random(&mut rng)));
        messages.push(Attribute::SecretPoint(RistrettoPoint::random(&mut rng)));
        messages.push(Attribute::PublicScalar(Scalar::random(&mut rng)));
        messages.push(Attribute::SecretPoint(RistrettoPoint::random(&mut rng)));
        messages.push(Attribute::SecretPoint(RistrettoPoint::random(&mut rng)));
        messages.push(Attribute::SecretScalar(Scalar::random(&mut rng)));
        messages.push(Attribute::PublicPoint(RistrettoPoint::random(&mut rng)));
        messages.push(Attribute::PublicScalar(Scalar::random(&mut rng)));

        let amac = Amac::tag(&mut rng, &params, &sk, &messages).unwrap();

        assert!(amac.verify(&params, &sk, &messages));
    }
}
