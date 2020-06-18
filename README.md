
==========
 aeonflux
==========

Composable, lightweight, fast attribute-based anonymous credentials with
infinite (aeon) rerandomised (flux) presentations using algebraic message
authentication codes (aMACs), symmetric verifiable encryption, and
non-interactive zero-knowledge proofs.

These are largely based on the credentials in
[2019/1416](https://eprint.iacr.org/2019/1416).

 Features
----------

Currently, we only support revealed credential issuance; that is, a user reveals
all the attributes on their credentials to the issuer when requesting a new
credential.  When presenting said credential afterwards, attributes may be
either hidden or revealed.

Credentials may be either scalars (integers modulo the group order, a large
prime) or group elements.  This library provides a way to encode arbitrary byte
arrays to group elements---which may then be encrypted and decrypted---in an
invertible manner, such that arbitrary strings can be stored as attributes.

Group element attributes which are hidden upon credential presentation are
symmetrically encrypted, such that the user can prove to the issuer their
correctness in zero-knowledge, while sharing the symmetric decryption key with
other third parties.  This allows for uses such as the issuer performing some
external verification of personally identifiable information, such as an email
address or a phone number, when the user requests a new credential, without
the issuer being able to track this data afterwards; however the user can still
share the data with other users.  Another example use case is storing a shared
key, in a way that all users who have access to the key can prove knowledge of
it in zero-knowledge later, thus allowing for arbitrary namespacing and/or
access control lists.

 Obligatory Warning
--------------------

While this library was created by a cryptographer, it hasn't yet been reviewed
by any other cryptographers.  Additionally, while I may be _a_ cryptographer,
I'm likely not _your_ cryptographer.  Use at your own risk.

 Usage
-------

```rust
extern crate aeonflux;
extern crate curve25519_dalek;
extern crate rand;

use aeonflux::amacs::Attribute;
use aeonflux::issuer::Issuer;
use aeonflux::parameters::IssuerParameters;
use aeonflux::parameters::SystemParameters;
use aeonflux::symmetric::Plaintext;
use aeonflux::symmetric::Keypair as SymmetricKeypair;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::thread_rng;

// First we set up an anonymous credential issuer.  We have to specify
// the number of attributes the credentials will have (here, eight),
// but not their type.
let mut rng = thread_rng();
let system_parameters = SystemParameters::generate(&mut rng, 8).unwrap();
let issuer = Issuer::new(&system_parameters, &mut rng);

// Our user creates a request for a new credential with some revealed
// attributes and sends it to the issuer.
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

// Optionally, upon showing the credential, the user can create a
// keypair and encrypt some or all of the attributes.  The master secret
// can be stored to regenerate the full keypair later on.  Encryption
// keys can be rotated to rerandomise the encrypted attributes.
let (keypair, master_secret) = SymmetricKeypair::generate(&system_parameters, &mut rng);
let proof = credential.show(&system_parameters, &issuer.issuer_parameters, Some(&keypair), &mut rng);

assert!(proof.is_ok());

let verification = proof.unwrap().verify(&issuer, &credential);

assert!(verification.is_ok());
```
