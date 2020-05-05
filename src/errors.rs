// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#[cfg(feature = "std")]
use std::convert::From;
#[cfg(feature = "std")]
use std::fmt;
#[cfg(feature = "std")]
use std::fmt::Display;
#[cfg(feature = "std")]
use std::option::NoneError;

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(not(feature = "std"))]
use core::convert::From;
#[cfg(not(feature = "std"))]
use core::fmt;
#[cfg(not(feature = "std"))]
use core::fmt::Display;
#[cfg(not(feature = "std"))]
use core::option::NoneError;

use zkp::ProofError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum MacError {
    KeypairDeserialisation,
    PointDecompressionError,
    ScalarFormatError,
    /// An error in the length of bytes handed to a constructor.
    ///
    /// To use this, pass the `length` in bytes which its constructor expects.
    MessageLengthError{ length: usize },
    /// The MAC could not be authenticated.
    AuthenticationError,
}

impl Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MacError::KeypairDeserialisation
                => write!(f, "Cannot deserialise keypair"),
            MacError::PointDecompressionError
                => write!(f, "Cannot decompress Ristretto point"),
            MacError::ScalarFormatError
                => write!(f, "Cannot use scalar with high-bit set"),
            MacError::MessageLengthError{ length: l }
                => write!(f, "Messages can only have up to {} attributes", l),
            MacError::AuthenticationError
                => write!(f, "MAC could not be authenticated"),
        }
    }
}

impl From<NoneError> for MacError {
    fn from(_source: NoneError) -> MacError {
        MacError::PointDecompressionError
    }
}

#[cfg(feature = "std")]
impl Error for MacError { }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CredentialError {
    BadAttribute,
    CredentialIssuance,
    MacCreation,
    MacVerification,
    MissingData,
    NoIssuerKey,
    NoIssuerParameters,
    NoSystemParameters,
    PointDecompressionError,
    ScalarFormatError,
    UndecryptableAttribute,
    VerificationFailure,
    WrongNumberOfAttributes,
    WrongNumberOfBytes,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CredentialError::BadAttribute
                => write!(f, "An attribute was unacceptable"),
            CredentialError::CredentialIssuance
                => write!(f, "Failed to get a credential issued"),
            CredentialError::MacCreation
                => write!(f, "Could not create a MAC"),
            CredentialError::MacVerification
                => write!(f, "Could not verify a MAC"),
            CredentialError::MissingData
                => write!(f, "Some data, such as a key or zkproof, was missing"),
            CredentialError::NoIssuerKey
                => write!(f, "The issuer was not initialised properly and has no secret key"),
            CredentialError::NoIssuerParameters
                => write!(f, "The issuer was not initialised properly and has no parameters"),
            CredentialError::NoSystemParameters
                => write!(f, "The system parameters were not initialised"),
            CredentialError::PointDecompressionError
                => write!(f, "Cannot decompress Ristretto point"),
            CredentialError::ScalarFormatError
                => write!(f, "Cannot use scalar with high-bit set"),
            CredentialError::UndecryptableAttribute
                => write!(f, "A hidden group attribute could not be decrypted"),
            CredentialError::VerificationFailure
                => write!(f, "The proof could not be verified"),
            CredentialError::WrongNumberOfAttributes
                => write!(f, "The credential did not have the correct number of attributes"),
            CredentialError::WrongNumberOfBytes
                => write!(f, "The credential could not be deserialised because it was not a multiple of 32 bytes"),
        }
    }
}

impl From<NoneError> for CredentialError {
    fn from(_source: NoneError) -> CredentialError {
        CredentialError::MissingData
    }
}

impl From<MacError> for CredentialError {
    fn from(source: MacError) -> CredentialError {
        match source {
            MacError::KeypairDeserialisation
                => CredentialError::NoIssuerKey,
            MacError::PointDecompressionError
                => CredentialError::NoIssuerParameters,
            MacError::ScalarFormatError
                => CredentialError::ScalarFormatError,
            MacError::MessageLengthError{ length: _ }
                => CredentialError::MacCreation,
            MacError::AuthenticationError
                => CredentialError::MacVerification,
        }
    }
}

#[cfg(feature = "std")]
impl Error for CredentialError { }

impl From<ProofError> for CredentialError {
    fn from(_source: ProofError) -> CredentialError {
        CredentialError::VerificationFailure
    }
}
