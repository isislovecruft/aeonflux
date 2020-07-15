// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use serde::{self, Serialize, Deserialize, Serializer, Deserializer};
use serde::de::Visitor;

use rand_core::CryptoRng;
use rand_core::RngCore;

use crate::amacs::SecretKey;
use crate::errors::CredentialError;

/// Given the `number_of_attributes`, calculate the size of a serialised
/// [`SystemParameters`], in bytes.
pub(crate) fn sizeof_system_parameters(number_of_attributes: u8) -> usize {
    // G_y is always at least three elements
    if number_of_attributes < 3 {
        // 32 * (5 + 3 + number_of_attributes as usize + 4) + 1
        385 + 32 * number_of_attributes as usize
    } else {
        // 32 * (5 + (2 * number_of_attributes as usize) + 4) + 1
        289 + 64 * number_of_attributes as usize
    }
}

/// The `SystemParameters` define the system-wide context in which the anonymous
/// credentials scheme and its proofs are constructed within.
///
/// They are defined as \\( \( \mathbb{G}, q, G, G_{w}, G_{w'}, G_{x_{0}}, G_{x_{1}},
/// G_{y_{0}}, \ldots G_{y_{n}}, G_{m_{0}}, \ldots, G_{m_{n}}, G_V \) \\)
///
/// where:
///
/// * \\( \mathbb{G} \\) is a group with order \\( q \\), where
///   `q` is a `k`-bit prime (`k = 255` in the case of using the Ristretto255
///   group),
/// * `G*` generators of `\\( \mathbb{G} \\)`,
/// * `\\( \log_G(G*) \\)` is unknown, that is, all generators `G*` are chosen
///   as a distinguished basepoint which is orthogonal to `g`.
/// * `n` is the [`NUMBER_OF_ATTRIBUTES`] in the message space.
///
/// Additionally, for the [`symmetric`]-key verifiable encryption scheme, we
/// require three more generators chosen orthogonally,
/// \\( (G_a, G_a0, G_a1) \in \mathbb{G} \\), chosen as detailed above.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemParameters {
    pub NUMBER_OF_ATTRIBUTES: u8,
    pub G:         RistrettoPoint,
    pub G_w:       RistrettoPoint,
    pub G_w_prime: RistrettoPoint,
    pub G_x_0:     RistrettoPoint,
    pub G_x_1:     RistrettoPoint,
    pub G_y:       Vec<RistrettoPoint>,
    pub G_m:       Vec<RistrettoPoint>,
    pub G_V:       RistrettoPoint,
    pub G_a:       RistrettoPoint,
    pub G_a0:      RistrettoPoint,
    pub G_a1:      RistrettoPoint,
}

macro_rules! try_deserialize {
    ($name:expr, $bytes:expr) => {{
        let bytes = $bytes;
        match CompressedRistretto::from_slice(&bytes).decompress() {
            Some(x) => x,
            None => {
                #[cfg(all(debug_assertions, feature = "std", feature = "debug-errors"))]
                eprintln!("Could not decode {:?} from bytes: {:?}", $name, bytes);
                return Err(CredentialError::PointDecompressionError);
            }
        }
    }}
}

impl SystemParameters {
    pub fn from_bytes(bytes: &[u8]) -> Result<SystemParameters, CredentialError> {
        let NUMBER_OF_ATTRIBUTES: u8 = bytes[0];
        let mut chunks = bytes[1..].chunks(32);

        if bytes.len() != sizeof_system_parameters(NUMBER_OF_ATTRIBUTES) {
            return Err(CredentialError::NoSystemParameters);
        }

        let G = try_deserialize!("G", &chunks.next().unwrap());
        let G_w = try_deserialize!("G_w", &chunks.next().unwrap());
        let G_w_prime = try_deserialize!("G_w_prime", &chunks.next().unwrap());
        let G_x_0 = try_deserialize!("G_x_0", &chunks.next().unwrap());
        let G_x_1 = try_deserialize!("G_x_1", &chunks.next().unwrap());

        let mut G_y: Vec<RistrettoPoint> = Vec::with_capacity(NUMBER_OF_ATTRIBUTES as usize);
        
        let number_of_G_y = core::cmp::max(3, NUMBER_OF_ATTRIBUTES);

        for _i in 0..number_of_G_y {
            G_y.push(try_deserialize!(format!("G_y_{}", _i), &chunks.next().unwrap()));
        }

        let mut G_m: Vec<RistrettoPoint> = Vec::with_capacity(NUMBER_OF_ATTRIBUTES as usize);
        
        for _i in 0..NUMBER_OF_ATTRIBUTES {
            G_m.push(try_deserialize!(format!("G_m_{}", _i), &chunks.next().unwrap()));
        }

        let G_V = try_deserialize!("G_V", &chunks.next().unwrap());
        let G_a = try_deserialize!("G_a", &chunks.next().unwrap());
        let G_a0 = try_deserialize!("G_a0", &chunks.next().unwrap());
        let G_a1 = try_deserialize!("G_a1", &chunks.next().unwrap());

        Ok(SystemParameters { NUMBER_OF_ATTRIBUTES, G, G_w, G_w_prime, G_x_0, G_x_1, G_y, G_m, G_V, G_a, G_a0, G_a1 })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(sizeof_system_parameters(self.NUMBER_OF_ATTRIBUTES));

        v.push(self.NUMBER_OF_ATTRIBUTES);

        v.extend(self.G.compress().to_bytes().iter());
        v.extend(self.G_w.compress().to_bytes().iter());
        v.extend(self.G_w_prime.compress().to_bytes().iter());
        v.extend(self.G_x_0.compress().to_bytes().iter());
        v.extend(self.G_x_1.compress().to_bytes().iter());

        let mut number_of_G_y = self.NUMBER_OF_ATTRIBUTES;

        if number_of_G_y < 3 {
            number_of_G_y = 3;
        }

        for i in 0..number_of_G_y as usize {
            v.extend(self.G_y[i].compress().to_bytes().iter());
        }

        for i in 0..self.NUMBER_OF_ATTRIBUTES as usize {
            v.extend(self.G_m[i].compress().to_bytes().iter());
        }

        v.extend(self.G_V.compress().to_bytes().iter());
        v.extend(self.G_a.compress().to_bytes().iter());
        v.extend(self.G_a0.compress().to_bytes().iter());
        v.extend(self.G_a1.compress().to_bytes().iter());
        v
    }
}

impl_serde_with_to_bytes_and_from_bytes!(SystemParameters,
                                         "A valid byte sequence representing a SystemParameters");

impl SystemParameters {
    /// Generate the [`SystemParameters`] randomly via an RNG.
    ///
    /// In order to never have a secret scalar in memory for generating the
    /// orthogonal basepoint, this method can be used to obtain bytes from the
    /// `csprng` and attempt to decompress them into a basepoint.
    pub fn hash_and_pray<R>(
        csprng: &mut R,
        number_of_attributes: u8,
    ) -> Result<SystemParameters, CredentialError>
    where
        R: RngCore + CryptoRng,
    {
        let G_w = RistrettoPoint::random(csprng);
        let G_w_prime = RistrettoPoint::random(csprng);
        let G_x_0 = RistrettoPoint::random(csprng);
        let G_x_1 = RistrettoPoint::random(csprng);
        let mut G_y: Vec<RistrettoPoint> = Vec::with_capacity(number_of_attributes as usize);
        let mut G_m: Vec<RistrettoPoint> = Vec::with_capacity(number_of_attributes as usize);
        let G_V = RistrettoPoint::random(csprng);
        let G_a = RistrettoPoint::random(csprng);
        let G_a0 = RistrettoPoint::random(csprng);
        let G_a1 = RistrettoPoint::random(csprng);

        // The number of elements in G_y must always be at least three in order
        // to support encrypted group element attributes.
        let number_of_G_y = core::cmp::max(3, number_of_attributes as usize);

        G_y.resize_with(number_of_G_y, || RistrettoPoint::random(csprng));
        G_m.resize_with(number_of_attributes as usize, || RistrettoPoint::random(csprng));

        let NUMBER_OF_ATTRIBUTES = number_of_attributes;
        let G = RISTRETTO_BASEPOINT_POINT;

        // Safety check: all generators should be generators (i.e. not the
        // identity element) and be unique.  While the chances of this happening
        // with a CSPRNG are miniscule, we might have been handed a bad RNG.
        let mut generators: Vec<CompressedRistretto> = Vec::new();

        generators.push(RistrettoPoint::identity().compress());
        generators.push(RISTRETTO_BASEPOINT_COMPRESSED);
        generators.push(G_w.compress());
        generators.push(G_w_prime.compress());
        generators.push(G_x_0.compress());
        generators.push(G_x_1.compress());
        generators.push(G_V.compress());
        generators.push(G_a.compress());
        generators.push(G_a0.compress());
        generators.push(G_a1.compress());

        for i in 0..NUMBER_OF_ATTRIBUTES as usize {
            generators.push(G_y[i].compress());
            generators.push(G_m[i].compress());
        }

        while generators.len() >= 2 {
            let x = generators.pop().unwrap();

            for y in &generators {
                if x == *y {
                    return Err(CredentialError::NoSystemParameters);
                }
            }
        }

        Ok(SystemParameters { NUMBER_OF_ATTRIBUTES, G, G_w, G_w_prime, G_x_0, G_x_1, G_y, G_m, G_V, G_a, G_a0, G_a1 })
    }

    /// Generate new system parameters using the
    /// [`hash_and_pray`](SystemParameters::hash_and_pray) algorithm.
    pub fn generate<R>(csprng: &mut R, number_of_attributes: u8)
        -> Result<SystemParameters, CredentialError> 
    where
        R: RngCore + CryptoRng,
    {
        SystemParameters::hash_and_pray(csprng, number_of_attributes)
    }
}

/// DOCDOC
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerParameters {
    pub C_W: RistrettoPoint,
    pub I: RistrettoPoint,
}

/// DOCDOC
impl IssuerParameters {
    /// DOCDOC
    pub fn generate(system_parameters: &SystemParameters, secret_key: &SecretKey) -> IssuerParameters {
        let C_W: RistrettoPoint = (system_parameters.G_w * secret_key.w) +
                                  (system_parameters.G_w_prime * secret_key.w_prime);

        let mut I: RistrettoPoint = (-system_parameters.G_V * Scalar::one()) +
                                    (system_parameters.G_x_0 * secret_key.x_0) +
                                    (system_parameters.G_x_1 * secret_key.x_1);

        for i in 0..system_parameters.NUMBER_OF_ATTRIBUTES as usize {
            I += system_parameters.G_y[i] * secret_key.y[i];
        }

        IssuerParameters { C_W, I }
    }

    /// DOCDOC
    pub fn from_bytes(_bytes: &[u8]) -> Result<IssuerParameters, CredentialError> {
        unimplemented!();
    }

    /// DOCDOC
    pub fn to_bytes(&self) -> Vec<u8> {
        unimplemented!();
    }
}

impl_serde_with_to_bytes_and_from_bytes!(IssuerParameters, "A valid byte sequence representing IssuerParameters");

#[cfg(test)]
mod test {
    use super::*;

    use rand::thread_rng;

    #[test]
    fn system_parameters_serialize_deserialize() {
        let mut rng = thread_rng();
        let system_parameters: SystemParameters = SystemParameters::hash_and_pray(&mut rng, 2).unwrap();

        let serialized = system_parameters.to_bytes();
        let deserialized = SystemParameters::from_bytes(&serialized).unwrap();

        assert!(system_parameters == deserialized);
    }

    #[test]
    fn hash_and_pray() {
        let mut rng = thread_rng();

        SystemParameters::hash_and_pray(&mut rng, 2).unwrap();
    }

    #[test]
    fn issuer_parameters_generate() {
        let mut rng = thread_rng();
        let system_parameters: SystemParameters = SystemParameters::hash_and_pray(&mut rng, 2).unwrap();
        let sk: SecretKey = SecretKey::generate(&mut rng, &system_parameters);
        let issuer_params: IssuerParameters = IssuerParameters::generate(&system_parameters, &sk);

        assert!(issuer_params.C_W != RistrettoPoint::identity());
    }
}
