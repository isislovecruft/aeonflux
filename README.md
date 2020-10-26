
# aeonflux

Composable, lightweight, fast attribute-based anonymous credentials with
infinite (aeon) rerandomised (flux) presentations using algebraic message
authentication codes (aMACs), symmetric verifiable encryption, and
non-interactive zero-knowledge proofs.

These are largely based on the credentials in
[2019/1416](https://eprint.iacr.org/2019/1416).

## Features

Currently, we only support revealed credential issuance; that is, a user reveals
all the attributes on their credentials to the issuer when requesting a new
credential.  When presenting said credential afterwards, attributes may be
either hidden or revealed.

Credential attributes may be either scalars (integers modulo the group order, a large
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

## Warning

While this library was created by a cryptographer, it hasn't yet been reviewed
by any other cryptographers.  Additionally, while I may be _a_ cryptographer,
I'm likely not _your_ cryptographer.  Use at your own risk.

## Usage

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
use aeonflux::user::CredentialRequestConstructor;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::thread_rng;

// First we set up an anonymous credential issuer.  We have to specify
// the number of attributes the credentials will have (here, 6),
// but not their type.  Note that their type, while not specified, must
// be fixed, e.g. a 2-attribute credential could have a scalar and then
// a point attributes, but *not* a point and then a scalar.
let mut rng = thread_rng();
let system_parameters = SystemParameters::generate(&mut rng, 6).unwrap();
let issuer = Issuer::new(&system_parameters, &mut rng);

// The issuer then publishes the `system_parameters` and the
// `issuer.issuer_parameters` somewhere publicly where users may obtain them.
let issuer_parameters = issuer.issuer_parameters.clone();

// A user creates a request for a new credential with some revealed
// attributes and sends it to the issuer.
let mut request = CredentialRequestConstructor::new(&system_parameters);

// Every 30 bytes of plaintext uses two point attributes and a scalar
// attribute.  This plaintext message is exactly 30 bytes, so it accounts
// for three attributes total on the credential.  If it were one byte
// longer, it would account for six attributes.
let plaintexts = request.append_plaintext(&String::from("This is a tsunami alert test..").into_bytes());

// Revealed scalars and revealed points count for one attribute each.
request.append_revealed_scalar(Scalar::random(&mut rng));         // 4th attribute
request.append_revealed_scalar(Scalar::random(&mut rng));         // 5th attribute
request.append_revealed_point(RistrettoPoint::random(&mut rng));  // 6th attribute

// Hence we have 6 total attributes, as specified in the generation of the
// `system_parameters` above.
let credential_request = request.finish();

// The user now sends `credential_request` to the issuer, who may issue the
// credential, if seen fit to do so.
let issuance = issuer.issue(credential_request, &mut rng).unwrap();

// The issuer sends the `credential_issuance` to the user, who verifies the
// contained proof of correct issuance.
let mut credential = issuance.verify(&system_parameters, &issuer_parameters).unwrap();

// Optionally, upon showing the credential, the user can create a
// keypair and encrypt some or all of the attributes.  The master secret
// can be stored to regenerate the full keypair later on.  Encryption
// keys can be rotated to rerandomise the encrypted attributes.
let (keypair, master_secret) = SymmetricKeypair::generate(&system_parameters, &mut rng);

// For this presentation, we're going to mark the 5th attribute, a scalar, as being
// hidden.
credential.hide_attribute(5);

// The user now creates a presentation of the credential to give to the issuer.
let presentation = credential.show(&system_parameters, &issuer_parameters, Some(&keypair), &mut rng).unwrap();

// The user then sends this presentation to the issuer, who verifies it.
let verification = issuer.verify(&presentation);

assert!(verification.is_ok());
```
