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
use crate::amacs::Messages;
use crate::credential::AnonymousCredential;
use crate::errors::CredentialError;
use crate::issuer::Issuer;
use crate::parameters::{IssuerParameters, SystemParameters};
use crate::symmetric::Ciphertext;
use crate::symmetric::Keypair as SymmetricKeypair;
use crate::symmetric::Plaintext;
use crate::symmetric::PublicKey as SymmetricPublicKey; // XXX rename this to something more sensical

pub struct ProofOfIssuance(CompactProof);

/// A non-interactive zero-knowledge proof demonstrating knowledge of the
/// issuer's secret key, and that an [`AnonymousCredential`] was computed
/// correctly w.r.t. the pubilshed system and issuer parameters.
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
        let (neg_G_V, _)   = prover.allocate_point(b"-G_V",     -issuer.system_parameters.G_V);
        let (G_w, _)       = prover.allocate_point(b"G_w",       issuer.system_parameters.G_w);
        let (G_w_prime, _) = prover.allocate_point(b"G_w_prime", issuer.system_parameters.G_w_prime);
        let (G_x_0, _)     = prover.allocate_point(b"G_x_0",     issuer.system_parameters.G_x_0);
        let (G_x_1, _)     = prover.allocate_point(b"G_x_1",     issuer.system_parameters.G_x_1);

        let mut G_y: Vec<PointVar> = Vec::with_capacity(issuer.system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        for (_i, G_y_i) in issuer.system_parameters.G_y.iter().enumerate() {
            // XXX fix the zkp crate to take Strings
            //let (G_y_x, _) = prover.allocate_point(format!("G_y_{}", _i), G_y_i);
            let (G_y_x, _) = prover.allocate_point(b"G_y", *G_y_i);

            G_y.push(G_y_x);
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

        // Constraint #2: I = -G_V + G_x_0 * x_0 + G_x_1 * x_1 + G_y_1 * y_1 + ... + G_y_n * y_n
        let mut rhs: Vec<(ScalarVar, PointVar)> = Vec::with_capacity(3 + issuer.system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        rhs.push((one, neg_G_V));
        rhs.push((x_0, G_x_0));
        rhs.push((x_1, G_x_1));
        rhs.extend(y.iter().copied().zip(G_y.iter().copied()));

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
        let neg_G_V   = verifier.allocate_point(b"-G_V",    (-system_parameters.G_V).compress())?;
        let G_w       = verifier.allocate_point(b"G_w",       system_parameters.G_w.compress())?;
        let G_w_prime = verifier.allocate_point(b"G_w_prime", system_parameters.G_w_prime.compress())?;
        let G_x_0     = verifier.allocate_point(b"G_x_0",     system_parameters.G_x_0.compress())?;
        let G_x_1     = verifier.allocate_point(b"G_x_1",     system_parameters.G_x_1.compress())?;

        let mut G_y: Vec<PointVar> = Vec::with_capacity(system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        for (_i, G_y_i) in system_parameters.G_y.iter().enumerate() {
            // XXX fix the zkp crate to take Strings
            //G_y.push(verifier.allocate_point(format!("G_y_{}", _i), G_y_i)?);
            G_y.push(verifier.allocate_point(b"G_y", G_y_i.compress())?);
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

        // Constraint #2: I = -G_V + G_x_0 * x_0 + G_x_1 * x_1 + G_y_1 * y_1 + ... + G_y_n * y_n
        let mut rhs: Vec<(ScalarVar, PointVar)> = Vec::with_capacity(3 + system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        rhs.push((one, neg_G_V));
        rhs.push((x_0, G_x_0));
        rhs.push((x_1, G_x_1));
        rhs.extend(y.iter().copied().zip(G_y.iter().copied()));

        verifier.constrain(I, rhs);

        // Constraint #3: V = G_w * w + U * x_0 + U * x_1 + U * t + \sigma{i=1}{n} M_i * y_i
        let mut rhs: Vec<(ScalarVar, PointVar)> = Vec::with_capacity(4 + system_parameters.NUMBER_OF_ATTRIBUTES as usize);

        rhs.push((w, G_w));
        rhs.push((x_0, U));
        rhs.push((x_1, U));
        rhs.push((t, U));
        rhs.extend(y.iter().copied().zip(M.iter().copied()));

        verifier.constrain(V, rhs);

        verifier.verify_compact(&self.0).or_else(|_| Err(CredentialError::VerificationFailure))
    }
}

/// A proof-of-knowledge that a ciphertext encrypts a plaintext
/// committed to in a list of commitments.
pub struct ProofOfEncryption {
    proof: CompactProof,
    public_key: SymmetricPublicKey,
    ciphertext: Ciphertext,
    index: u16,
    C_y_1: RistrettoPoint,
    C_y_2: RistrettoPoint,
    C_y_3: RistrettoPoint,
    C_y_2_prime: RistrettoPoint,
}

impl ProofOfEncryption {
    /// Prove in zero-knowledge that a ciphertext is a verifiable encryption of
    /// a plaintext w.r.t. a valid commitment to a secret symmetric key.
    ///
    /// # Inputs
    ///
    /// * The [`SystemParameters`] for this anonymous credential instantiation,
    /// * A `plaintext` of up to thirty bytes.
    /// * The `index` of the attribute to be encrypted.
    /// * A symmetric "keypair",
    /// * The nonce, `z`, must be reused from the outer-lying [`ProofOfValidCredential`].
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is empty, otherwise a [`CredentialError`].
    pub(crate) fn prove(
        system_parameters: &SystemParameters,
        plaintext: &Plaintext,
        index: u16,
        keypair: &SymmetricKeypair,
        z: &Scalar,
    ) -> ProofOfEncryption
    {
        // Encrypt the plaintext.
        let ciphertext_ = keypair.encrypt(&plaintext);

        // Compute the vector C of commitments to the plaintext.
        let C_y_1_ = (system_parameters.G_y[0] * z) + plaintext.M1;
        let C_y_2_ = (system_parameters.G_y[1] * z) + plaintext.M2;
        let C_y_3_ = (system_parameters.G_y[2] * z) + (system_parameters.G_m[index as usize] * plaintext.m3);

        // Compute C_y_2' = C_y_2 * a1.
        let C_y_2_prime_ = C_y_2_ * keypair.secret.a1;

        // Calculate z1 = -z(a0 + a1 * m3).
        let z1_ = -z * (keypair.secret.a0 + keypair.secret.a1 * plaintext.m3);

        // Construct a protocol transcript and prover.
        let mut transcript = Transcript::new(b"2019/1416 anonymous credentials");
        let mut prover = Prover::new(b"2019/1416 proof of encryption", &mut transcript);

        // Commit the names of the Camenisch-Stadler secrets to the protocol transcript.
        let a  = prover.allocate_scalar(b"a",  keypair.secret.a);
        let a0 = prover.allocate_scalar(b"a0", keypair.secret.a0);
        let a1 = prover.allocate_scalar(b"a1", keypair.secret.a1);
        let m3 = prover.allocate_scalar(b"m3", plaintext.m3);
        let z  = prover.allocate_scalar(b"z",  *z);
        let z1 = prover.allocate_scalar(b"z1", z1_);

        // Commit to the values and names of the Camenisch-Stadler publics.
        let (pk, _)             = prover.allocate_point(b"pk",       keypair.public.pk);
        let (G_a, _)            = prover.allocate_point(b"G_a",      system_parameters.G_a);
        let (G_a_0, _)          = prover.allocate_point(b"G_a_0",    system_parameters.G_a0);
        let (G_a_1, _)          = prover.allocate_point(b"G_a_1",    system_parameters.G_a1);
        let (G_y_1, _)          = prover.allocate_point(b"G_y_1",    system_parameters.G_y[0]);
        let (G_y_2, _)          = prover.allocate_point(b"G_y_2",    system_parameters.G_y[1]);
        let (G_y_3, _)          = prover.allocate_point(b"G_y_3",    system_parameters.G_y[2]);
        let (G_m_3, _)          = prover.allocate_point(b"G_m_3",    system_parameters.G_m[index as usize]);
        let (C_y_2, _)          = prover.allocate_point(b"C_y_2",    C_y_2_);
        let (C_y_3, _)          = prover.allocate_point(b"C_y_3",    C_y_3_);
        let (C_y_2_prime, _)    = prover.allocate_point(b"C_y_2'",   C_y_2_prime_);
        let (C_y_1_minus_E2, _) = prover.allocate_point(b"C_y_1-E2", C_y_1_ - ciphertext_.E2);
        let (E1, _)             = prover.allocate_point(b"E1",       ciphertext_.E1);
        let (minus_E1, _)       = prover.allocate_point(b"-E1",      -ciphertext_.E1);

        // Constraint #1: Prove knowledge of the secret portions of the symmetric key.
        //                pk = G_a * a + G_a0 * a0 + G_a1 * a1
        prover.constrain(pk, vec![(a, G_a), (a0, G_a_0), (a1, G_a_1)]);

        // Constraint #2: The plaintext of this encryption is the message.
        //                C_y_1 - E2 = G_y_1 * z - E_1 * a
        prover.constrain(C_y_1_minus_E2, vec![(z, G_y_1), (a, minus_E1)]);

        // Constraint #3: The encryption C_y_2' of the commitment C_y_2 is formed correctly w.r.t. the secret key.
        //                C_y_2' = C_y_2 * a1
        prover.constrain(C_y_2_prime, vec![(a1, C_y_2)]);

        // Constraint #4: The encryption E1 is well formed.
        //                  E1 = C_y_2            * a0 + C_y_2'                * m3    + G_y_2 * z1
        // M2 * (a0 + a1 * m3) = (M2 + G_y_2 * z) * a0 + (M2 + G_y_2 * z) * a1 * m3    + G_y_2 * -z (a0 + a1 * m3)
        // M2(a0) + M2(a1)(m3) = M2(a0) + G_y_2(z)(a0) + M2(a1)(m3) + G_y_2(z)(a1)(m3) + G_y_2(-z)(a0) + G_y_2(-z)(a1)(m3)
        // M2(a0) + M2(a1)(m3) = M2(a0)                + M2(a1)(m3)
        prover.constrain(E1, vec![(a0, C_y_2), (m3, C_y_2_prime), (z1, G_y_2)]);

        // Constraint #5: The commitment to the hash m3 is a correct hash of the message commited to.
        prover.constrain(C_y_3, vec![(z, G_y_3), (m3, G_m_3)]);

        let proof = prover.prove_compact();

        ProofOfEncryption {
            proof: proof,
            public_key: keypair.public,
            ciphertext: ciphertext_,
            index: index,
            C_y_1: C_y_1_,
            C_y_2: C_y_2_,
            C_y_3: C_y_3_,
            C_y_2_prime: C_y_2_prime_,
        }
    }

    /// Verify that this [`ProofOfEncryption`] proves that a `ciphertext` is a
    /// correct encryption of a verifiably-encrypted plaintext.
    ///
    /// # Inputs
    ///
    /// * The [`SystemParameters`] for this anonymous credential instantiation,
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is empty, otherwise a [`CredentialError`].
    pub(crate) fn verify(
        &self,
        system_parameters: &SystemParameters,
    ) -> Result<(), CredentialError>
    {
        // Construct a protocol transcript and verifier.
        let mut transcript = Transcript::new(b"2019/1416 anonymous credentials");
        let mut verifier = Verifier::new(b"2019/1416 proof of encryption", &mut transcript);

        // Commit the names of the Camenisch-Stadler secrets to the protocol transcript.
        let a  = verifier.allocate_scalar(b"a");
        let a0 = verifier.allocate_scalar(b"a0");
        let a1 = verifier.allocate_scalar(b"a1");
        let m3 = verifier.allocate_scalar(b"m3");
        let z  = verifier.allocate_scalar(b"z");
        let z1 = verifier.allocate_scalar(b"z1");

        // Commit to the values and names of the Camenisch-Stadler publics.
        let pk             = verifier.allocate_point(b"pk",       self.public_key.pk.compress())?;
        let G_a            = verifier.allocate_point(b"G_a",      system_parameters.G_a.compress())?;
        let G_a_0          = verifier.allocate_point(b"G_a_0",    system_parameters.G_a0.compress())?;
        let G_a_1          = verifier.allocate_point(b"G_a_1",    system_parameters.G_a1.compress())?;
        let G_y_1          = verifier.allocate_point(b"G_y_1",    system_parameters.G_y[0].compress())?;
        let G_y_2          = verifier.allocate_point(b"G_y_2",    system_parameters.G_y[1].compress())?;
        let G_y_3          = verifier.allocate_point(b"G_y_3",    system_parameters.G_y[2].compress())?;
        let G_m_3          = verifier.allocate_point(b"G_m_3",    system_parameters.G_m[self.index as usize].compress())?;
        let C_y_2          = verifier.allocate_point(b"C_y_2",    self.C_y_2.compress())?;
        let C_y_3          = verifier.allocate_point(b"C_y_3",    self.C_y_3.compress())?;
        let C_y_2_prime    = verifier.allocate_point(b"C_y_2'",   self.C_y_2_prime.compress())?;
        let C_y_1_minus_E2 = verifier.allocate_point(b"C_y_1-E2", (self.C_y_1 - self.ciphertext.E2).compress())?;
        let E1             = verifier.allocate_point(b"E1",       self.ciphertext.E1.compress())?;
        let minus_E1       = verifier.allocate_point(b"-E1",      (-self.ciphertext.E1).compress())?;

        // Constraint #1: Prove knowledge of the secret portions of the symmetric key.
        //                pk = G_a * a + G_a0 * a0 + G_a1 * a1
        verifier.constrain(pk, vec![(a, G_a), (a0, G_a_0), (a1, G_a_1)]);

        // Constraint #2: The plaintext of this encryption is the message.
        //                C_y_1 - E2 = G_y_1 * z - E_1 * a
        verifier.constrain(C_y_1_minus_E2, vec![(z, G_y_1), (a, minus_E1)]);

        // Constraint #3: The encryption C_y_2' of the commitment C_y_2 is formed correctly w.r.t. the secret key.
        //                C_y_2' = C_y_2 * a1
        verifier.constrain(C_y_2_prime, vec![(a1, C_y_2)]);

        // Constraint #4: The encryption E1 is well formed.
        //                  E1 = C_y_2            * a0 + C_y_2'                * m3    + G_y_2 * z1
        // M2 * (a0 + a1 * m3) = (M2 + G_y_2 * z) * a0 + (M2 + G_y_2 * z) * a1 * m3    + G_y_2 * -z (a0 + a1 * m3)
        // M2(a0) + M2(a1)(m3) = M2(a0) + G_y_2(z)(a0) + M2(a1)(m3) + G_y_2(z)(a1)(m3) + G_y_2(-z)(a0) + G_y_2(-z)(a1)(m3)
        // M2(a0) + M2(a1)(m3) = M2(a0)                + M2(a1)(m3)
        verifier.constrain(E1, vec![(a0, C_y_2), (m3, C_y_2_prime), (z1, G_y_2)]);

        // Constraint #5: The commitment to the hash m3 is a correct hash of the message commited to.
        verifier.constrain(C_y_3, vec![(z, G_y_3), (m3, G_m_3)]);

        verifier.verify_compact(&self.proof).or_else(|_| Err(CredentialError::VerificationFailure))
    }
}

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
        let (Z, _)     = prover.allocate_point(b"Z", Z_);
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
                Attribute::SecretPoint(pt) => {
                    // The .unwrap() here can never panic because we check above that the key isn't
                    // None if we have encrypted group element attributes.
                    proofs_of_encryption.push((i as u16, ProofOfEncryption::prove(&system_parameters, &pt, i as u16, &keypair.unwrap(), &z_)));
                    encrypted_attributes.push(EncryptedAttribute::SecretPoint);
                },
            }
        }

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
        let mut Z_ = self.C_V - (issuer.amacs_key.W + self.C_x_0 * issuer.amacs_key.x_0 + self.C_x_1 * issuer.amacs_key.x_1);

        for (i, attribute) in self.encrypted_attributes.iter().enumerate() {
            match attribute {
                EncryptedAttribute::PublicScalar(m_i) => Z_ -= (self.C_y[i] + (issuer.system_parameters.G_m[i] * m_i)) * issuer.amacs_key.y[i],
                EncryptedAttribute::SecretScalar      => Z_ -=  self.C_y[i]                                            * issuer.amacs_key.y[i],
                EncryptedAttribute::PublicPoint(M_i)  => Z_ -= (self.C_y[i] + M_i)                                     * issuer.amacs_key.y[i],
                EncryptedAttribute::SecretPoint       => Z_ -=  self.C_y[i]                                            * issuer.amacs_key.y[i],
            }
        }

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
        let Z     = verifier.allocate_point(b"Z", Z_.compress())?;
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

        verifier.verify_compact(&self.proof).or_else(|_| return Err(CredentialError::VerificationFailure));

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
    use std::vec::Vec;

    use super::*;

    use crate::user::CredentialRequestConstructor;

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

    #[test]
    fn encryption_proof() {
        let mut rng = thread_rng();
        let system_parameters = SystemParameters::generate(&mut rng, 5).unwrap();
        let (keypair, _) = SymmetricKeypair::generate(&system_parameters, &mut rng);
        let z = Scalar::random(&mut rng);
        let message1: &[u8; 30] = b"This is a tsunami alert test..";
        let plaintext: Plaintext = message1.into();

        let proof = ProofOfEncryption::prove(&system_parameters, &plaintext, 1u16, &keypair, &z);
        let decryption = keypair.decrypt(&proof.ciphertext).unwrap();

        assert!(decryption.M1 == plaintext.M1);
        assert!(decryption.M2 == plaintext.M2);
        assert!(decryption.m3 == plaintext.m3);

        let message2: [u8; 30] = (&decryption).into();

        assert!(message1 == &message2);

        let verification = proof.verify(&system_parameters);

        assert!(verification.is_ok());
    }

    #[test]
    fn credential_proof_10_attributes() {
        let mut rng = thread_rng();
        let system_parameters = SystemParameters::generate(&mut rng, 10).unwrap();
        let issuer = Issuer::new(&system_parameters, &mut rng);
        let mut request = CredentialRequestConstructor::new(&system_parameters);
        let message = String::from("This is a tsunami alert test..").into_bytes();
        // Each plaintext takes up three attributes;
        let plaintext = request.append_plaintext(&message);

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
