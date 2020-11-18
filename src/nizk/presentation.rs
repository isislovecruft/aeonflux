// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Non-interactive zero-knowledge proofs (NIZKs) of credential presentation.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
use core::ops::Index;
#[cfg(feature = "std")]
use std::ops::Index;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

use rand_core::CryptoRng;
use rand_core::RngCore;

use zkp::CompactProof;
use zkp::Transcript;
// XXX do we want/need batch proof verification?
// use zkp::toolbox::batch_verifier::BatchVerifier;
use zkp::toolbox::SchnorrCS;
use zkp::toolbox::prover::Prover;
use zkp::toolbox::prover::PointVar as ProverPointVar;
use zkp::toolbox::prover::ScalarVar as ProverScalarVar;
use zkp::toolbox::verifier::Verifier;
use zkp::toolbox::verifier::PointVar as VerifierPointVar;
use zkp::toolbox::verifier::ScalarVar as VerifierScalarVar;

use crate::amacs::Attribute;
use crate::amacs::EncryptedAttribute;
use crate::credential::AnonymousCredential;
use crate::errors::CredentialError;
use crate::issuer::Issuer;
use crate::nizk::encryption::ProofOfEncryption;
use crate::parameters::{IssuerParameters, SystemParameters};
use crate::symmetric::Keypair as SymmetricKeypair;

/// An incredibly shitty and inelegant hashmap-like structure to store/"index"
/// hidden scalar attributes during construction of a [`ProofOfValidCredential`].
struct ProverHiddenScalars(Vec<(usize, ProverScalarVar)>);

/// An incredibly shitty and inelegant hashmap-like structure to store/"index"
/// corresponding hidden scalar basepoints during construction of a
/// [`ProofOfValidCredential`].
struct ProverHiddenScalarBasepoints(Vec<(usize, ProverPointVar)>);

/// An incredibly shitty and inelegant hashmap-like structure to store/"index"
/// hidden scalar attributes during verification of a [`ProofOfValidCredential`].
struct VerifierHiddenScalars(Vec<(usize, VerifierScalarVar)>);

/// An incredibly shitty and inelegant hashmap-like structure to store/"index"
/// corresponding hidden scalar basepoints during verification of a
/// [`ProofOfValidCredential`].
struct VerifierHiddenScalarBasepoints(Vec<(usize, VerifierPointVar)>);

macro_rules! construct_hidden_scalar_variant {
    ($scalar_type: ty, $basepoint_type: ty, $scalar_var: ty, $basepoint_var: ty) => {
        impl Index<usize> for $scalar_type {
            type Output = $scalar_var;

            fn index(&self, i: usize) -> &Self::Output {
                for (index, scalar) in self.0.iter() {
                    if *index == i {
                        return scalar;
                    }
                }
                panic!()
            }
        }

        impl $scalar_type {
            pub(crate) fn push(&mut self, item: (usize, $scalar_var)) {
                self.0.push(item);
            }
        }

        impl Index<usize> for $basepoint_type {
            type Output = $basepoint_var;

            fn index(&self, i: usize) -> &Self::Output {
                for (index, scalar) in self.0.iter() {
                    if *index == i {
                        return scalar;
                    }
                }
                panic!()
            }
        }

        impl $basepoint_type {
            pub(crate) fn push(&mut self, item: (usize, $basepoint_var)) {
                self.0.push(item);
            }
        }
    }
}

construct_hidden_scalar_variant!(ProverHiddenScalars, ProverHiddenScalarBasepoints, ProverScalarVar, ProverPointVar);
construct_hidden_scalar_variant!(VerifierHiddenScalars, VerifierHiddenScalarBasepoints, VerifierScalarVar, VerifierPointVar);

/// A proof-of-knowledge of a valid `Credential` and its attributes,
/// which may be either hidden or revealed.
// XXX the commitments should be compressed
pub struct ProofOfValidCredential {
    proof: CompactProof,
    proofs_of_encryption: Vec<(u16, ProofOfEncryption)>,
    encrypted_attributes: Vec<EncryptedAttribute>,
    hidden_scalar_indices: Vec<u16>,
    C_x_0: RistrettoPoint,
    C_x_1: RistrettoPoint,
    C_V:   RistrettoPoint,
    C_y: Vec<RistrettoPoint>,
}

impl ProofOfValidCredential {
    /// Create a [`ProofOfValidCredential`].
    ///
    /// # Warning
    ///
    /// If there are any [`EitherPoint`]s in the `credential`'s attributes, they
    /// will be treated as if they are meant to be publicly revealed rather than
    /// encrypted.  If you need them to be encrypted for this credential
    /// presentation, you *must* call `credential.hide_attribute()` with their
    /// indices *before* creating this proof.
    pub(crate) fn prove<C>(
        system_parameters: &SystemParameters,
        issuer_parameters: &IssuerParameters,
        credential: &AnonymousCredential,
        keypair: Option<&SymmetricKeypair>,
        csprng: &mut C,
    ) -> Result<ProofOfValidCredential, CredentialError>
    where
        C: RngCore + CryptoRng,
    {
        // If a keypair was not supplied and we have encrypted group element attributes, bail early.
        if keypair.is_none() {
            for attribute in credential.attributes.iter() {
                match attribute {
                    Attribute::SecretPoint(_) => return Err(CredentialError::NoSymmetricKey),
                    _ => continue,
                }
            }
        }

        let NUMBER_OF_ATTRIBUTES = system_parameters.NUMBER_OF_ATTRIBUTES as usize;

        // Choose a nonce for the commitments.
        let z_:   Scalar = Scalar::random(csprng);
        let z_0_: Scalar = (-credential.amac.t * z_).reduce();

        // Commit to the credential attributes, and store the hidden scalar attributes in H_s.
        let mut C_y_: Vec<RistrettoPoint> = Vec::with_capacity(NUMBER_OF_ATTRIBUTES);
        let mut H_s_: Vec<(usize, RistrettoPoint, Scalar)> = Vec::new();

        for (i, attribute) in credential.attributes.iter().enumerate() {
            match attribute {
                Attribute::PublicPoint(_)  =>   C_y_.push(system_parameters.G_y[i] * z_),
                Attribute::EitherPoint(_)  =>   C_y_.push(system_parameters.G_y[i] * z_),
                Attribute::SecretPoint(p)  =>   C_y_.push(system_parameters.G_y[i] * z_ + p.M1),
                Attribute::PublicScalar(_) =>   C_y_.push(system_parameters.G_y[i] * z_),
                Attribute::SecretScalar(m) => { C_y_.push(system_parameters.G_y[i] * z_ + system_parameters.G_m[i] * *m);
                                                H_s_.push((i, system_parameters.G_m[i], *m)); },
            };
        }
        let C_x_0_: RistrettoPoint = (system_parameters.G_x_0 * z_) +  credential.amac.U;
        let C_x_1_: RistrettoPoint = (system_parameters.G_x_1 * z_) + (credential.amac.U * credential.amac.t);
        let C_V_:   RistrettoPoint = (system_parameters.G_V   * z_) +  credential.amac.V;
        let Z_:     RistrettoPoint =  issuer_parameters.I     * z_;

        // Create a transcript and prover.
        let mut transcript = Transcript::new(b"2019/1416 anonymous credential");
        let mut prover = Prover::new(b"2019/1416 presentation proof", &mut transcript);

        // Feed the domain separators for the Camenisch-Stadler secrets into the protocol transcript.
        let z   = prover.allocate_scalar(b"z", z_);
        let z_0 = prover.allocate_scalar(b"z_0", z_0_);
        let t   = prover.allocate_scalar(b"t", credential.amac.t);

        let mut H_s = ProverHiddenScalars(Vec::with_capacity(H_s_.len()));
        let mut hidden_scalar_indices: Vec<u16> = Vec::new();
        // XXX assert number of attributes is less than 2^16-1

        for (i, _basepoint, scalar) in H_s_.iter() {
            // XXX Fix zkp crate to take Strings
            //H_s.push(prover.allocate_scalar(format!(b"H_s_{}", i), scalar));
            H_s.push((*i, prover.allocate_scalar(b"m", *scalar)));
            hidden_scalar_indices.push(*i as u16);
        }

        // Feed in the domain separators and values for the publics into the transcript.
        let (I, _)     = prover.allocate_point(b"I", issuer_parameters.I);
        let (C_x_1, _) = prover.allocate_point(b"C_x_1", C_x_1_);
        let (C_x_0, _) = prover.allocate_point(b"C_x_0", C_x_0_);
        let (G_x_0, _) = prover.allocate_point(b"G_x_0", system_parameters.G_x_0);
        let (G_x_1, _) = prover.allocate_point(b"G_x_1", system_parameters.G_x_1);

        let mut C_y: Vec<ProverPointVar> = Vec::with_capacity(NUMBER_OF_ATTRIBUTES);
        let mut G_y: Vec<ProverPointVar> = Vec::with_capacity(NUMBER_OF_ATTRIBUTES);

        // We only prove knowledge of commitment openings for hidden scalar
        // attributes and all revealed attributes; for hidden group element
        // attributes we use proofs of encryption.
        for (i, commitment) in C_y_.iter().enumerate() {
            match credential.attributes[i] {
                Attribute::SecretPoint { .. } => continue,
                _ => {
                    // XXX Fix zkp crate to take Strings
                    //let (C_y_i, _) = prover.allocate_point(format!(b"C_y_{}", i), commitment);
                    let (C_y_i, _) = prover.allocate_point(b"C_y", *commitment);

                    C_y.push(C_y_i);
                },
            };
        }

        for (_i, basepoint) in system_parameters.G_y.iter().enumerate() {
            // XXX Fix zkp crate to take Strings
            // let (G_y_i, _) = prover.allocate_point(format!(b"G_y_{}", _i), basepoint);
            let (G_y_i, _) = prover.allocate_point(b"G_y", *basepoint);

            G_y.push(G_y_i);
        }

        let mut G_m = ProverHiddenScalarBasepoints(Vec::with_capacity(H_s_.len()));

        for (i, basepoint, _scalar) in H_s_.iter() {
            // XXX Fix zkp crate to take Strings
            // let (G_m_i, _) = prover.allocate_point(format!(b"G_m_{}", i), basepoint);
            let (G_m_i, _) = prover.allocate_point(b"G_m", *basepoint);

            G_m.push((*i, G_m_i));
        }

        // Put the calculation of Z last so that we can use merlin's
        // "debug-transcript" feature to detect if anything else was different.
        let (Z, _) = prover.allocate_point(b"Z", Z_);

        // Constraint #1: Prove knowledge of the nonce, z, and the correctness of the AMAC with Z.
        //                Z = I * z
        prover.constrain(Z, vec![(z, I)]);

        // Constraint #2: Prove correctness of t and U.
        //                C_x_1 = C_x_0 * t          + G_x_0 * z_0 + G_x_1 * z
        //    G_x_1 * z + U * t = G_x_0 * zt + U * t + G_x_0 * -tz + G_x_1 * z
        //    G_x_1 * z + U * t =              U * t +               G_x_1 * z
        prover.constrain(C_x_1, vec![(t, C_x_0), (z_0, G_x_0), (z, G_x_1)]);

        // Constraint #3: Prove correctness/validation of attributes.
        //        C_y_i = { G_y_i * z + G_m_i * m_i          if i is a hidden scalar attribute
        //                { G_y_i * z                        if i is a revealed attribute
        for (i, C_y_i) in C_y.iter().enumerate() {
            match credential.attributes[i] {
                Attribute::SecretPoint(_)  => continue,
                Attribute::SecretScalar(_) => prover.constrain(*C_y_i, vec![(z, G_y[i]), (H_s[i], G_m[i])]),
                _                          => prover.constrain(*C_y_i, vec![(z, G_y[i])]),
            }
        }
        // Notes:
        //
        // 1. Prover recalculates Z', so it is not sent.
        // 2. C_V, the commitment to the actual AMAC (recall that the t and U
        //    values in the AMAC are nonces), is sent, but V is kept private to
        //    provide anonymity, so we do not prove anything about it.
        // 3; That z_0 actually equals -tz (mod \ell) is never proven, but this
        //    should not matter as we prove knowledge of t and z, and constraint
        //    #2 would never pass verification if either were other than the
        //    values used to compute z_0.
        let proof = prover.prove_compact();

        // Construct proofs of correct encryptions for the hidden group attributes.
        let mut proofs_of_encryption: Vec<(u16, ProofOfEncryption)> = Vec::new();

        // Rebuild the attributes for our credential to send to the verifier.
        let mut encrypted_attributes: Vec<EncryptedAttribute> = Vec::with_capacity(system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        // XXX don't we also need DLEQ between the plaintext here and that in the commitments above?
        for (i, attribute) in credential.attributes.iter().enumerate() {
            match attribute {
                Attribute::PublicScalar(x) => encrypted_attributes.push(EncryptedAttribute::PublicScalar(*x)),
                Attribute::SecretScalar(_) => encrypted_attributes.push(EncryptedAttribute::SecretScalar),
                Attribute::PublicPoint(x)  => encrypted_attributes.push(EncryptedAttribute::PublicPoint(*x)),
                Attribute::EitherPoint(x)  => encrypted_attributes.push(EncryptedAttribute::PublicPoint(x.M1)),
                Attribute::SecretPoint(pt) => {
                    // The .unwrap() here can never panic because we check above that the key isn't
                    // None if we have encrypted group element attributes.
                    proofs_of_encryption.push((i as u16, ProofOfEncryption::prove(&system_parameters, &pt, i as u16, &keypair.unwrap(), &z_)));
                    encrypted_attributes.push(EncryptedAttribute::SecretPoint);
                },
            }
        }

        println!("Z is {:?}", Z_.compress());

        Ok(ProofOfValidCredential {
            proof: proof,
            proofs_of_encryption: proofs_of_encryption,
            encrypted_attributes: encrypted_attributes,
            hidden_scalar_indices: hidden_scalar_indices,
            C_x_0: C_x_0_,
            C_x_1: C_x_1_,
            C_V: C_V_,
            C_y: C_y_,
        })
    }

    /// Verify a `ProofOfValidCredential`.
    pub(crate) fn verify(
        &self,
        issuer: &Issuer,
    ) -> Result<(), CredentialError>
    {
        let NUMBER_OF_ATTRIBUTES = issuer.system_parameters.NUMBER_OF_ATTRIBUTES as usize;

        // Recompute the prover's Z value.
        //
        // Let \mathcal{H} denote the set of hidden attributes, both those which are group elements
        // and those which are scalars.
        //
        // Let M_i be a revealed group element attribute, if so, and otherwise if a revealed scalar
        // attribute, m_i, then let M_i be G_m_i * m_i.
        //
        // Z = C_V - (W + C_x0 * x0 + C_x1 * x1 +
        //            \sigma_{i \in \mathcal{H}}{C_y_i * y_i} +
        //            \sigma_{i \notin \mathcal{H}}{(C_y_i + M_i) * y_i})
        let mut Z_ = self.C_V - issuer.amacs_key.W - (self.C_x_0 * issuer.amacs_key.x_0) - (self.C_x_1 * issuer.amacs_key.x_1);

        for (i, attribute) in self.encrypted_attributes.iter().enumerate() {
            match attribute {
                EncryptedAttribute::PublicScalar(m_i) => Z_ -= issuer.amacs_key.y[i] * (self.C_y[i] + (issuer.system_parameters.G_m[i] * m_i)),
                EncryptedAttribute::SecretScalar      => Z_ -= issuer.amacs_key.y[i] *  self.C_y[i],
                EncryptedAttribute::PublicPoint(M_i)  => Z_ -= issuer.amacs_key.y[i] * (self.C_y[i] + M_i),
                EncryptedAttribute::SecretPoint       => Z_ -= issuer.amacs_key.y[i] *  self.C_y[i],
            }
        }

        println!("Z recalculated is {:?}", Z_.compress());

        // Create a transcript and verifier.
        let mut transcript = Transcript::new(b"2019/1416 anonymous credential");
        let mut verifier = Verifier::new(b"2019/1416 presentation proof", &mut transcript);

        // Feed the domain separators for the Camenisch-Stadler secrets into the protocol transcript.
        let z   = verifier.allocate_scalar(b"z");
        let z_0 = verifier.allocate_scalar(b"z_0");
        let t   = verifier.allocate_scalar(b"t");

        let mut H_s = VerifierHiddenScalars(Vec::new());

        // XXX fixme this struct won't work here
        for i in self.hidden_scalar_indices.iter() {
            // XXX Fix zkp crate to take Strings
            //H_s.push(*i, verifier.allocate_scalar(format!(b"H_s_{}", i)));
            H_s.push((*i as usize, verifier.allocate_scalar(b"m")));
        }

        // Feed in the domain separators and values for the publics into the transcript.
        let I     = verifier.allocate_point(b"I", issuer.issuer_parameters.I.compress())?;
        let C_x_1 = verifier.allocate_point(b"C_x_1", self.C_x_1.compress())?;
        let C_x_0 = verifier.allocate_point(b"C_x_0", self.C_x_0.compress())?;
        let G_x_0 = verifier.allocate_point(b"G_x_0", issuer.system_parameters.G_x_0.compress())?;
        let G_x_1 = verifier.allocate_point(b"G_x_1", issuer.system_parameters.G_x_1.compress())?;

        let mut C_y: Vec<VerifierPointVar> = Vec::with_capacity(NUMBER_OF_ATTRIBUTES);
        let mut G_y: Vec<VerifierPointVar> = Vec::with_capacity(NUMBER_OF_ATTRIBUTES);

        // We only prove knowledge of commitment openings for hidden scalar
        // attributes and all revealed attributes; for hidden group element
        // attributes we use proofs of encryption.
        for (i, commitment) in self.C_y.iter().enumerate() {
            match self.encrypted_attributes[i] {
                EncryptedAttribute::SecretPoint { .. } => continue,
                _ => {
                    // XXX Fix zkp crate to take Strings
                    // C_y.push(verifier.allocate_point(format!(b"C_y_{}", i), commitment.compress())?);
                    C_y.push(verifier.allocate_point(b"C_y", commitment.compress())?);
                },
            };
        }

        for (_i, basepoint) in issuer.system_parameters.G_y.iter().enumerate() {
            // XXX Fix zkp crate to take Strings
            // G_y.push(verifier.allocate_point(format!(b"G_y_{}", _i), basepoint.compress())?);
            G_y.push(verifier.allocate_point(b"G_y", basepoint.compress())?);
        }

        let mut G_m = VerifierHiddenScalarBasepoints(Vec::with_capacity(H_s.0.len()));

        for (i, _) in H_s.0.iter() {
            // XXX Fix zkp crate to take Strings
            // G_m.push(verifier.allocate_point(format!(b"G_m_{}", i), issuer.system_parameters.G_m[i].compress())?);
            G_m.push((*i, verifier.allocate_point(b"G_m", issuer.system_parameters.G_m[*i].compress())?));
        }

        // Put the recalculation of Z last so that we can use merlin's
        // "debug-transcript" feature to detect if anything else was different.
        let Z = verifier.allocate_point(b"Z", Z_.compress())?;

        // Constraint #1: Prove knowledge of the nonce, z, and the correctness of the AMAC with Z.
        //                Z = I * z
        verifier.constrain(Z, vec![(z, I)]);

        // Constraint #2: Prove correctness of t and U.
        //                C_x_1 = C_x_0 * t          + G_x_0 * z_0 + G_x_1 * z
        //    G_x_1 * z + U * t = G_x_0 * zt + U * t + G_x_0 * -tz + G_x_1 * z
        //    G_x_1 * z + U * t =              U * t +               G_x_1 * z
        verifier.constrain(C_x_1, vec![(t, C_x_0), (z_0, G_x_0), (z, G_x_1)]);

        // Constraint #3: Prove correctness/validation of attributes.
        //        C_y_i = { G_y_i * z + G_m_i * m_i          if i is a hidden scalar attribute
        //                { G_y_i * z                        if i is a revealed attribute
        for (i, C_y_i) in C_y.iter().enumerate() {
            match self.encrypted_attributes[i] {
                EncryptedAttribute::SecretPoint  => continue,
                EncryptedAttribute::SecretScalar => verifier.constrain(*C_y_i, vec![(z, G_y[i]), (H_s[i], G_m[i])]),
                _                                => verifier.constrain(*C_y_i, vec![(z, G_y[i])]),
            }
        }

        println!("before");
        verifier.verify_compact(&self.proof).or(Err(CredentialError::VerificationFailure))?;
        println!("after");

        // Check the proofs of correct encryptions and fail if any cannot be verified.
        for (_i, proof_of_encryption) in self.proofs_of_encryption.iter() {
            proof_of_encryption.verify(&issuer.system_parameters)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::string::String;

    use super::*;

    use crate::symmetric::Plaintext;
    use crate::user::CredentialRequestConstructor;

    use rand::thread_rng;

    #[test]
    fn credential_proof_10_attributes() {
        let mut rng = thread_rng();
        let system_parameters = SystemParameters::generate(&mut rng, 10).unwrap();
        let issuer = Issuer::new(&system_parameters, &mut rng);
        let mut request = CredentialRequestConstructor::new(&system_parameters);
        let message = String::from("This is a tsunami alert test..").into_bytes();
        // Each plaintext takes up three attributes;
        let _plaintext = request.append_plaintext(&message);

        request.append_revealed_scalar(Scalar::random(&mut rng));
        request.append_revealed_scalar(Scalar::random(&mut rng));
        request.append_revealed_scalar(Scalar::random(&mut rng));
        request.append_revealed_point(RistrettoPoint::random(&mut rng));
        request.append_revealed_scalar(Scalar::random(&mut rng));
        request.append_revealed_scalar(Scalar::random(&mut rng));
        request.append_revealed_point(RistrettoPoint::random(&mut rng));

        let credential_request = request.finish();
        let issuance = issuer.issue(credential_request, &mut rng).unwrap();
        let credential = issuance.verify(&system_parameters, &issuer.issuer_parameters).unwrap();
        let (keypair, _) = SymmetricKeypair::generate(&system_parameters, &mut rng);
        let proof = ProofOfValidCredential::prove(&system_parameters, &issuer.issuer_parameters, &credential, Some(&keypair), &mut rng);

        assert!(proof.is_ok());

        let verification = proof.unwrap().verify(&issuer);

        assert!(verification.is_ok());
    }

    #[test]
    fn credential_proof_1_plaintext() {
        let mut rng = thread_rng();
        let system_parameters = SystemParameters::generate(&mut rng, 3).unwrap();
        let issuer = Issuer::new(&system_parameters, &mut rng);
        let mut request = CredentialRequestConstructor::new(&system_parameters);
        let message = String::from("This is a tsunami alert test..").into_bytes();
        let _plaintext = request.append_plaintext(&message);
        let credential_request = request.finish();
        let issuance = issuer.issue(credential_request, &mut rng).unwrap();
        let credential = issuance.verify(&system_parameters, &issuer.issuer_parameters).unwrap();
        let (keypair, _) = SymmetricKeypair::generate(&system_parameters, &mut rng);
        let proof = ProofOfValidCredential::prove(&system_parameters, &issuer.issuer_parameters, &credential, Some(&keypair), &mut rng);

        assert!(proof.is_ok());

        let verification = proof.unwrap().verify(&issuer);

        assert!(verification.is_ok());
    }

    #[test]
    fn credential_proof_1_scalar_revealed() {
        let mut rng = thread_rng();
        let system_parameters = SystemParameters::generate(&mut rng, 1).unwrap();
        let issuer = Issuer::new(&system_parameters, &mut rng);
        let mut request = CredentialRequestConstructor::new(&system_parameters);

        request.append_revealed_scalar(Scalar::random(&mut rng));

        let credential_request = request.finish();
        let issuance = issuer.issue(credential_request, &mut rng).unwrap();
        let credential = issuance.verify(&system_parameters, &issuer.issuer_parameters).unwrap();
        let presentation = ProofOfValidCredential::prove(&system_parameters, &issuer.issuer_parameters, &credential, None, &mut rng).unwrap();
        let verification = issuer.verify(&presentation);

        assert!(verification.is_ok());
    }

    #[test]
    #[should_panic(expected = "assertion failed: verification.is_ok()")]
    fn bad_credential_proof_1_scalar_revealed() {
        let mut rng = thread_rng();
        let system_parameters = SystemParameters::generate(&mut rng, 1).unwrap();
        let issuer = Issuer::new(&system_parameters, &mut rng);
        let mut request = CredentialRequestConstructor::new(&system_parameters);

        request.append_revealed_scalar(Scalar::random(&mut rng));

        let credential_request = request.finish();
        let issuance = issuer.issue(credential_request, &mut rng).unwrap();
        let mut credential = issuance.verify(&system_parameters, &issuer.issuer_parameters).unwrap();

        credential.attributes[0] = Attribute::PublicScalar(Scalar::random(&mut rng));

        let presentation = ProofOfValidCredential::prove(&system_parameters, &issuer.issuer_parameters, &credential, None, &mut rng).unwrap();
        let verification = issuer.verify(&presentation);

        assert!(verification.is_ok());
    }
}
