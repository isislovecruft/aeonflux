// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Non-interactive zero-knowledge proofs (NIPKs).

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use curve25519_dalek::scalar::Scalar;

use zkp::CompactProof;
use zkp::Transcript;
// XXX do we want/need batch proof verification?
// use zkp::toolbox::batch_verifier::BatchVerifier;
use zkp::toolbox::SchnorrCS;
use zkp::toolbox::prover::Prover;
use zkp::toolbox::verifier::Verifier;

use crate::amacs::Messages;
use crate::credential::AnonymousCredential;
use crate::errors::CredentialError;
use crate::issuer::Issuer;
use crate::parameters::{IssuerParameters, SystemParameters};

/// A non-interactive zero-knowledge proof demonstrating knowledge of the
/// issuer's secret key, and that an [`AnonymousCredential`] was computed
/// correctly w.r.t. the pubilshed system and issuer parameters.
pub struct ProofOfIssuance(CompactProof);

impl ProofOfIssuance {
    /// Create a [`ProofOfIssuance`].
    pub(crate) fn prove(
        issuer: &Issuer,
        credential: &AnonymousCredential,
    ) -> ProofOfIssuance
    {
        use zkp::toolbox::prover::PointVar;
        use zkp::toolbox::prover::ScalarVar;

        let mut transcript = Transcript::new(b"2019/1416 anonymous credential");
        let mut prover = Prover::new(b"2019/1416 issuance proof", &mut transcript);

        // Commit the names of the Camenisch-Stadler secrets to the protocol transcript.
        let w       = prover.allocate_scalar(b"w",   issuer.amacs_key.w);
        let w_prime = prover.allocate_scalar(b"w'",  issuer.amacs_key.w_prime);
        let x_0     = prover.allocate_scalar(b"x_0", issuer.amacs_key.x_0);
        let x_1     = prover.allocate_scalar(b"x_1", issuer.amacs_key.x_1);

        let mut y: Vec<ScalarVar> = Vec::with_capacity(issuer.system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        for (_i, y_i) in issuer.amacs_key.y.iter().enumerate() {
            // XXX fix the zkp crate to take Strings
            //y.push(prover.allocate_scalar(format!("y_{}", _i), y_i));
            y.push(prover.allocate_scalar(b"y", *y_i));
        }

        // We also have to commit to the multiplicative identity since one of the
        // zero-knowledge statements requires the inverse of the G_V generator
        // without multiplying by any scalar.
        let one = prover.allocate_scalar(b"1", Scalar::one());

        let t = prover.allocate_scalar(b"t", credential.amac.t);

        // Commit to the values and names of the Camenisch-Stadler publics.
        let (G_V, _)       = prover.allocate_point(b"G_V",       issuer.system_parameters.G_V);
        let (G_w, _)       = prover.allocate_point(b"G_w",       issuer.system_parameters.G_w);
        let (G_w_prime, _) = prover.allocate_point(b"G_w_prime", issuer.system_parameters.G_w_prime);
        let (neg_G_x_0, _) = prover.allocate_point(b"-G_x_0",   -issuer.system_parameters.G_x_0);
        let (neg_G_x_1, _) = prover.allocate_point(b"-G_x_1",   -issuer.system_parameters.G_x_1);

        let mut neg_G_y: Vec<PointVar> = Vec::with_capacity(issuer.system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        for (_i, G_y_i) in issuer.system_parameters.G_y.iter().enumerate() {
            // XXX fix the zkp crate to take Strings
            //let (G_y_x, _) = prover.allocate_point(format!("G_y_{}", _i), G_y_i);
            let (neg_G_y_x, _) = prover.allocate_point(b"-G_y", -G_y_i);

            neg_G_y.push(neg_G_y_x);
        }

        let (C_W, _) = prover.allocate_point(b"C_W", issuer.issuer_parameters.C_W);
        let (I, _)   = prover.allocate_point(b"I",   issuer.issuer_parameters.I);
        let (U, _)   = prover.allocate_point(b"U", credential.amac.U);
        let (V, _)   = prover.allocate_point(b"V", credential.amac.V);

        let mut M: Vec<PointVar> = Vec::with_capacity(issuer.system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        let messages: Messages = Messages::from_attributes(&credential.attributes, &issuer.system_parameters);

        for (_i, M_i) in messages.0.iter().enumerate() {
            // XXX fix the zkp crate to take Strings
            //let (M_x, _) = prover.allocate_point(format!("M_{}", _i), M_i);
            let (M_x, _) = prover.allocate_point(b"M", *M_i);

            M.push(M_x);
        }

        // Constraint #1: C_W = G_w * w + G_w' * w'
        prover.constrain(C_W, vec![(w, G_w), (w_prime, G_w_prime)]);

        // Constraint #2: I = G_V - (G_x_0 * x_0 + G_x_1 * x_1 + G_y_1 * y_1 + ... + G_y_n * y_n)
        let mut rhs: Vec<(ScalarVar, PointVar)> = Vec::with_capacity(3 + issuer.system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        rhs.push((one, G_V));
        rhs.push((x_0, neg_G_x_0));
        rhs.push((x_1, neg_G_x_1));
        rhs.extend(y.iter().copied().zip(neg_G_y.iter().copied()));

        prover.constrain(I, rhs);

        // Constraint #3: V = G_w * w + U * x_0 + U * x_1 + U * t + \sigma{i=1}{n} M_i * y_i
        let mut rhs: Vec<(ScalarVar, PointVar)> = Vec::with_capacity(4 + issuer.system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        rhs.push((w, G_w));
        rhs.push((x_0, U));
        rhs.push((x_1, U));
        rhs.push((t, U));
        rhs.extend(y.iter().copied().zip(M.iter().copied()));

        prover.constrain(V, rhs);

        ProofOfIssuance(prover.prove_compact())
    }

    /// Verify a [`ProofOfIssuance`].
    pub fn verify(
        &self,
        system_parameters: &SystemParameters,
        issuer_parameters: &IssuerParameters,
        credential: &AnonymousCredential,
    ) -> Result<(), CredentialError>
    {
        use zkp::toolbox::verifier::PointVar;
        use zkp::toolbox::verifier::ScalarVar;

        let mut transcript = Transcript::new(b"2019/1416 anonymous credential");
        let mut verifier = Verifier::new(b"2019/1416 issuance proof", &mut transcript);

        // Commit the names of the Camenisch-Stadler secrets to the protocol transcript.
        let w       = verifier.allocate_scalar(b"w");
        let w_prime = verifier.allocate_scalar(b"w'");
        let x_0     = verifier.allocate_scalar(b"x_0");
        let x_1     = verifier.allocate_scalar(b"x_1");

        let mut y: Vec<ScalarVar> = Vec::with_capacity(system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        for _i in 0..system_parameters.NUMBER_OF_ATTRIBUTES as usize {
            // XXX fix the zkp crate to take Strings
            //y.push(verifier.allocate_scalar(format!("y_{}", _i)));
            y.push(verifier.allocate_scalar(b"y"));
        }

        let one = verifier.allocate_scalar(b"1");
        let t   = verifier.allocate_scalar(b"t");

        // Commit to the values and names of the Camenisch-Stadler publics.
        let G_V       = verifier.allocate_point(b"G_V",       system_parameters.G_V.compress())?;
        let G_w       = verifier.allocate_point(b"G_w",       system_parameters.G_w.compress())?;
        let G_w_prime = verifier.allocate_point(b"G_w_prime", system_parameters.G_w_prime.compress())?;
        let neg_G_x_0 = verifier.allocate_point(b"-G_x_0",   (-system_parameters.G_x_0).compress())?;
        let neg_G_x_1 = verifier.allocate_point(b"-G_x_1",   (-system_parameters.G_x_1).compress())?;

        let mut neg_G_y: Vec<PointVar> = Vec::with_capacity(system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        for (_i, G_y_i) in system_parameters.G_y.iter().enumerate() {
            // XXX fix the zkp crate to take Strings
            //G_y.push(verifier.allocate_point(format!("G_y_{}", _i), G_y_i)?);
            neg_G_y.push(verifier.allocate_point(b"-G_y", (-G_y_i).compress())?);
        }

        let C_W = verifier.allocate_point(b"C_W", issuer_parameters.C_W.compress())?;
        let I   = verifier.allocate_point(b"I",   issuer_parameters.I.compress())?;
        let U   = verifier.allocate_point(b"U", credential.amac.U.compress())?;
        let V   = verifier.allocate_point(b"V", credential.amac.V.compress())?;

        let mut M: Vec<PointVar> = Vec::with_capacity(system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        let messages: Messages = Messages::from_attributes(&credential.attributes, system_parameters);

        for (_i, M_i) in messages.0.iter().enumerate() {
            // XXX fix the zkp crate to take Strings
            //let (M_x, _) = verifier.allocate_point(format!("M_{}", _i), M_i);
            let M_x = verifier.allocate_point(b"M", M_i.compress())?;

            M.push(M_x);
        }

        // Constraint #1: C_W = G_w * w + G_w' * w'
        verifier.constrain(C_W, vec![(w, G_w), (w_prime, G_w_prime)]);

        // Constraint #2: I = G_V - (G_x_0 * x_0 + G_x_1 * x_1 + G_y_1 * y_1 + ... + G_y_n * y_n)
        let mut rhs: Vec<(ScalarVar, PointVar)> = Vec::with_capacity(3 + system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        rhs.push((one, G_V));
        rhs.push((x_0, neg_G_x_0));
        rhs.push((x_1, neg_G_x_1));
        rhs.extend(y.iter().copied().zip(neg_G_y.iter().copied()));

        verifier.constrain(I, rhs);

        // Constraint #3: V = G_w * w + U * x_0 + U * x_1 + U * t + \sigma{i=1}{n} M_i * y_i
        let mut rhs: Vec<(ScalarVar, PointVar)> = Vec::with_capacity(4 + system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        rhs.push((w, G_w));
        rhs.push((x_0, U));
        rhs.push((x_1, U));
        rhs.push((t, U));
        rhs.extend(y.iter().copied().zip(M.iter().copied()));

        verifier.constrain(V, rhs);

        verifier.verify_compact(&self.0).or(Err(CredentialError::VerificationFailure))
    }
}

#[cfg(test)]
mod test {
    use std::string::String;
    use std::vec::Vec;

    use super::*;

    use crate::user::CredentialRequestConstructor;

    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::traits::IsIdentity;

    use rand::thread_rng;

    #[test]
    fn issuance_proof() {
        let mut rng = thread_rng();
        let system_parameters = SystemParameters::generate(&mut rng, 7).unwrap();
        let issuer = Issuer::new(&system_parameters, &mut rng);
        let message: Vec<u8> = vec![1u8];
        let mut request = CredentialRequestConstructor::new(&system_parameters);

        request.append_revealed_scalar(Scalar::random(&mut rng));
        request.append_revealed_scalar(Scalar::random(&mut rng));
        request.append_revealed_point(RistrettoPoint::random(&mut rng));
        let _plaintext = request.append_plaintext(&message);
        request.append_revealed_scalar(Scalar::random(&mut rng));

        let credential_request = request.finish();
        let issuance = issuer.issue(credential_request, &mut rng).unwrap();
        let credential = issuance.verify(&system_parameters, &issuer.issuer_parameters);

        assert!(credential.is_ok());
    }

    /// An issuance proof with a plaintext equal to the identity element will fail.
    #[test]
    #[should_panic(expected = "assertion failed: credential.is_ok()")]
    fn issuance_proof_identity_plaintext() {
        let mut rng = thread_rng();
        let system_parameters = SystemParameters::generate(&mut rng, 8).unwrap();
        let issuer = Issuer::new(&system_parameters, &mut rng);
        let message: Vec<u8> = vec![0u8; 30];
        let mut request = CredentialRequestConstructor::new(&system_parameters);
        let plaintext = request.append_plaintext(&message);

        assert!(plaintext[0].M1.is_identity());

        request.append_revealed_scalar(Scalar::random(&mut rng));
        request.append_revealed_scalar(Scalar::random(&mut rng));
        request.append_revealed_point(RistrettoPoint::random(&mut rng));
        request.append_revealed_point(RistrettoPoint::random(&mut rng));
        request.append_revealed_scalar(Scalar::random(&mut rng));

        let credential_request = request.finish();
        let issuance = issuer.issue(credential_request, &mut rng).unwrap();
        let credential = issuance.verify(&system_parameters, &issuer.issuer_parameters);

        assert!(credential.is_ok());
    }
}
