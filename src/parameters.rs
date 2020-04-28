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
    32 * (5 + (2 * number_of_attributes as usize) + 4) + 1
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

macro_rules! try_deserialise {
    ($name:expr, $bytes:expr) => {
        match CompressedRistretto($bytes).decompress() {
            Some(x)  => x,
            None     => {
                #[cfg(feature = "std")]
                println!("Could not decode {:?} from bytes: {:?}", $name, $bytes);
                return Err(CredentialError::PointDecompressionError);
            },
        }
    }
}

impl SystemParameters {
    pub fn from_bytes(bytes: &[u8]) -> Result<SystemParameters, CredentialError> {
        let mut index: usize = 0;
        let mut chunk = [0u8; 32];

        let NUMBER_OF_ATTRIBUTES: u8 = bytes[0]; index += 1;

        if bytes.len() != sizeof_system_parameters(NUMBER_OF_ATTRIBUTES) {
            return Err(CredentialError::NoSystemParameters);
        }

        chunk.copy_from_slice(&bytes[index..index+32]); index += 32;
        let G: RistrettoPoint = try_deserialise!("G", chunk);

        chunk.copy_from_slice(&bytes[index..index+32]); index += 32;
        let G_w: RistrettoPoint = try_deserialise!("G_w", chunk);

        chunk.copy_from_slice(&bytes[index..index+32]); index += 32;
        let G_w_prime: RistrettoPoint = try_deserialise!("G_w_prime", chunk);

        chunk.copy_from_slice(&bytes[index..index+32]); index += 32;
        let G_x_0: RistrettoPoint = try_deserialise!("G_x_0", chunk);

        chunk.copy_from_slice(&bytes[index..index+32]); index += 32;
        let G_x_1: RistrettoPoint = try_deserialise!("G_x_1", chunk);

        let mut G_y: Vec<RistrettoPoint> = Vec::with_capacity(NUMBER_OF_ATTRIBUTES as usize);
        
        for i in 0..NUMBER_OF_ATTRIBUTES {
            chunk.copy_from_slice(&bytes[index..index+32]); index += 32;
            G_y.push(try_deserialise!(format!("G_y_{}", i), chunk));
        }

        let mut G_m: Vec<RistrettoPoint> = Vec::with_capacity(NUMBER_OF_ATTRIBUTES as usize);
        
        for i in 0..NUMBER_OF_ATTRIBUTES {
            chunk.copy_from_slice(&bytes[index..index+32]); index += 32;
            G_m.push(try_deserialise!(format!("G_m_{}", i), chunk));
        }

        chunk.copy_from_slice(&bytes[index..index+32]); index += 32;
        let G_V: RistrettoPoint = try_deserialise!("G_V", chunk);

        chunk.copy_from_slice(&bytes[index..index+32]); index += 32;
        let G_a: RistrettoPoint = try_deserialise!("G_a", chunk);

        chunk.copy_from_slice(&bytes[index..index+32]); index += 32;
        let G_a0: RistrettoPoint = try_deserialise!("G_a0", chunk);

        chunk.copy_from_slice(&bytes[index..index+32]);
        let G_a1: RistrettoPoint = try_deserialise!("G_a1", chunk);

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

        for i in 0..self.NUMBER_OF_ATTRIBUTES as usize {
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
        let mut tmp: [u8; 32] = [0u8; 32];
        let mut G_w: Option<RistrettoPoint> = None;
        let mut G_w_prime: Option<RistrettoPoint> = None;
        let mut G_x_0: Option<RistrettoPoint> = None;
        let mut G_x_1: Option<RistrettoPoint> = None;
        let mut G_y: Vec<RistrettoPoint> = Vec::with_capacity(number_of_attributes as usize);
        let mut G_m: Vec<RistrettoPoint> = Vec::with_capacity(number_of_attributes as usize);
        let mut G_V: Option<RistrettoPoint> = None;
        let mut G_a: Option<RistrettoPoint> = None;
        let mut G_a0: Option<RistrettoPoint> = None;
        let mut G_a1: Option<RistrettoPoint> = None;

        while G_w.is_none() {
            csprng.fill_bytes(&mut tmp);
            G_w = CompressedRistretto(tmp).decompress();
        }

        while G_w_prime.is_none() {
            csprng.fill_bytes(&mut tmp);
            G_w_prime = CompressedRistretto(tmp).decompress();
        }

        while G_x_0.is_none() {
            csprng.fill_bytes(&mut tmp);
            G_x_0 = CompressedRistretto(tmp).decompress();
        }

        while G_x_1.is_none() {
            csprng.fill_bytes(&mut tmp);
            G_x_1 = CompressedRistretto(tmp).decompress();
        }

        for _ in 0..number_of_attributes {
            let mut G_y_i: Option<RistrettoPoint> = None;

            while G_y_i.is_none() {
                csprng.fill_bytes(&mut tmp);
                G_y_i = CompressedRistretto(tmp).decompress();
            }
            G_y.push(G_y_i.unwrap());
        }

        for _ in 0..number_of_attributes {
            let mut G_m_i: Option<RistrettoPoint> = None;

            while G_m_i.is_none() {
                csprng.fill_bytes(&mut tmp);
                G_m_i = CompressedRistretto(tmp).decompress();
            }
            G_m.push(G_m_i.unwrap());
        }

        while G_V.is_none() {
            csprng.fill_bytes(&mut tmp);
            G_V = CompressedRistretto(tmp).decompress();
        }

        while G_a.is_none() {
            csprng.fill_bytes(&mut tmp);
            G_a = CompressedRistretto(tmp).decompress();
        }

        while G_a0.is_none() {
            csprng.fill_bytes(&mut tmp);
            G_a0 = CompressedRistretto(tmp).decompress();
        }

        while G_a1.is_none() {
            csprng.fill_bytes(&mut tmp);
            G_a1 = CompressedRistretto(tmp).decompress();
        }

        let NUMBER_OF_ATTRIBUTES = number_of_attributes;
        let G = RISTRETTO_BASEPOINT_POINT;
        let G_w = G_w.unwrap();
        let G_w_prime = G_w_prime.unwrap();
        let G_x_0 = G_x_0.unwrap();
        let G_x_1 = G_x_1.unwrap();
        let G_V = G_V.unwrap();
        let G_a = G_a.unwrap();
        let G_a0 = G_a0.unwrap();
        let G_a1 = G_a1.unwrap();

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

            for i in 0 .. generators.len()-1 {
                if x == generators[i] {
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

        let mut I: RistrettoPoint = system_parameters.G_V -
                                   (system_parameters.G_x_0 * secret_key.x_0) +
                                   (system_parameters.G_x_1 * secret_key.x_1);

        for i in 0..system_parameters.NUMBER_OF_ATTRIBUTES as usize {
            I += system_parameters.G_y[i] * secret_key.y[i];
        }

        IssuerParameters { C_W, I }
    }

    /// DOCDOC
    pub fn from_bytes(bytes: &[u8]) -> Result<IssuerParameters, CredentialError> {
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
