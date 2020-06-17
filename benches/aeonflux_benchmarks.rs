
use std::vec::Vec;

extern crate rand;

use rand::thread_rng;

#[macro_use]
extern crate criterion;

use criterion::Criterion;

extern crate aeonflux;

use aeonflux::amacs::Attribute;
use aeonflux::amacs::SecretKey;
use aeonflux::issuer::Issuer;
use aeonflux::nizk::ProofOfValidCredential;
use aeonflux::parameters::IssuerParameters;
use aeonflux::parameters::SystemParameters;
use aeonflux::symmetric::Plaintext;
use aeonflux::symmetric::Keypair as SymmetricKeypair;

extern crate curve25519_dalek;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

mod proof_of_credential_benches {
    use super::*;

    fn creation_1(c: &mut Criterion) {
        let mut rng = thread_rng();
        let system_parameters = SystemParameters::generate(&mut rng, 1).unwrap();
        let amacs_key = SecretKey::generate(&mut rng, &system_parameters);
        let issuer_parameters = IssuerParameters::generate(&system_parameters, &amacs_key);
        let issuer = Issuer::new(&system_parameters, &issuer_parameters, &amacs_key);
        let plaintext: Plaintext = b"This is a tsunami alert test..".into();

        let mut attributes = Vec::new();

        attributes.push(Attribute::SecretPoint(plaintext));

        let credential = issuer.issue(attributes, &mut rng).unwrap();
        let (keypair, _) = SymmetricKeypair::generate(&system_parameters, &mut rng);

        c.bench_function("Proof-of-Valid-Credential with 1 attribute Creation", |b| {
            b.iter(|| ProofOfValidCredential::prove(&system_parameters, &issuer_parameters, &credential, Some(&keypair), &mut rng));
        });
    }

    fn verification_1(c: &mut Criterion) {
        let mut rng = thread_rng();
        let system_parameters = SystemParameters::generate(&mut rng, 1).unwrap();
        let amacs_key = SecretKey::generate(&mut rng, &system_parameters);
        let issuer_parameters = IssuerParameters::generate(&system_parameters, &amacs_key);
        let issuer = Issuer::new(&system_parameters, &issuer_parameters, &amacs_key);
        let plaintext: Plaintext = b"This is a tsunami alert test..".into();

        let mut attributes = Vec::new();

        attributes.push(Attribute::SecretPoint(plaintext));

        let credential = issuer.issue(attributes, &mut rng).unwrap();
        let (keypair, _) = SymmetricKeypair::generate(&system_parameters, &mut rng);
        let proof = ProofOfValidCredential::prove(&system_parameters, &issuer_parameters, &credential, Some(&keypair), &mut rng).unwrap();

        c.bench_function("Proof-of-Valid-Credential with 1 attribute Verification", |b| {
            b.iter(|| proof.verify(&issuer, &credential));
        });
    }

    fn creation_8(c: &mut Criterion) {
        let mut rng = thread_rng();
        let system_parameters = SystemParameters::generate(&mut rng, 8).unwrap();
        let amacs_key = SecretKey::generate(&mut rng, &system_parameters);
        let issuer_parameters = IssuerParameters::generate(&system_parameters, &amacs_key);
        let issuer = Issuer::new(&system_parameters, &issuer_parameters, &amacs_key);
        let plaintext: Plaintext = b"This is a tsunami alert test..".into();

        let mut attributes = Vec::new();

        attributes.push(Attribute::SecretPoint(plaintext));
        attributes.push(Attribute::SecretScalar(Scalar::random(&mut rng)));
        attributes.push(Attribute::SecretScalar(Scalar::random(&mut rng)));
        attributes.push(Attribute::PublicScalar(Scalar::random(&mut rng)));
        attributes.push(Attribute::PublicPoint(RistrettoPoint::random(&mut rng)));
        attributes.push(Attribute::SecretScalar(Scalar::random(&mut rng)));
        attributes.push(Attribute::PublicScalar(Scalar::random(&mut rng)));
        attributes.push(Attribute::PublicPoint(RistrettoPoint::random(&mut rng)));

        let credential = issuer.issue(attributes, &mut rng).unwrap();
        let (keypair, _) = SymmetricKeypair::generate(&system_parameters, &mut rng);

        c.bench_function("Proof-of-Valid-Credential with 8 attributes Creation", |b| {
            b.iter(|| ProofOfValidCredential::prove(&system_parameters, &issuer_parameters, &credential, Some(&keypair), &mut rng));
        });
    }

    fn verification_8(c: &mut Criterion) {
        let mut rng = thread_rng();
        let system_parameters = SystemParameters::generate(&mut rng, 8).unwrap();
        let amacs_key = SecretKey::generate(&mut rng, &system_parameters);
        let issuer_parameters = IssuerParameters::generate(&system_parameters, &amacs_key);
        let issuer = Issuer::new(&system_parameters, &issuer_parameters, &amacs_key);
        let plaintext: Plaintext = b"This is a tsunami alert test..".into();

        let mut attributes = Vec::new();

        attributes.push(Attribute::SecretPoint(plaintext));
        attributes.push(Attribute::SecretScalar(Scalar::random(&mut rng)));
        attributes.push(Attribute::SecretScalar(Scalar::random(&mut rng)));
        attributes.push(Attribute::PublicScalar(Scalar::random(&mut rng)));
        attributes.push(Attribute::PublicPoint(RistrettoPoint::random(&mut rng)));
        attributes.push(Attribute::SecretScalar(Scalar::random(&mut rng)));
        attributes.push(Attribute::PublicScalar(Scalar::random(&mut rng)));
        attributes.push(Attribute::PublicPoint(RistrettoPoint::random(&mut rng)));

        let credential = issuer.issue(attributes, &mut rng).unwrap();
        let (keypair, _) = SymmetricKeypair::generate(&system_parameters, &mut rng);
        let proof = ProofOfValidCredential::prove(&system_parameters, &issuer_parameters, &credential, Some(&keypair), &mut rng).unwrap();

        c.bench_function("Proof-of-Valid-Credential with 8 attributes Verification", |b| {
            b.iter(|| proof.verify(&issuer, &credential));
        });
    }

    criterion_group! {
        name = proof_of_credential_benches;
        config = Criterion::default();
        targets =
            creation_1,
            verification_1,
            creation_8,
            verification_8,
    }
}

criterion_main!(
    proof_of_credential_benches::proof_of_credential_benches,
);
