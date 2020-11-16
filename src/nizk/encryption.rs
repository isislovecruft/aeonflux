// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Non-interactive zero-knowledge proofs (NIZKs) of correct encryption under a given key.

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

use zkp::CompactProof;
use zkp::Transcript;
// XXX do we want/need batch proof verification?
// use zkp::toolbox::batch_verifier::BatchVerifier;
use zkp::toolbox::SchnorrCS;
use zkp::toolbox::prover::Prover;
use zkp::toolbox::verifier::Verifier;

use crate::errors::CredentialError;
use crate::parameters::SystemParameters;
use crate::symmetric::Ciphertext;
use crate::symmetric::Keypair as SymmetricKeypair;
use crate::symmetric::Plaintext;
use crate::symmetric::PublicKey as SymmetricPublicKey; // XXX rename this to something more sensical

/// A proof-of-knowledge that a ciphertext encrypts a plaintext
/// committed to in a list of commitments.
pub struct ProofOfEncryption {
    proof: CompactProof,
    public_key: SymmetricPublicKey,
    pub(crate) ciphertext: Ciphertext,
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

        verifier.verify_compact(&self.proof).or(Err(CredentialError::VerificationFailure))
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
}
