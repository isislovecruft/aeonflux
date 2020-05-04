// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Attribute-based anonymous credentials.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "alloc"), feature = "std"))]
use std::vec::Vec;

use crate::amacs::Amac;
use crate::amacs::Attribute;

pub struct AnonymousCredential {
    pub(crate) amac: Amac,
    pub(crate) attributes: Vec<Attribute>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn credential_issuance() {

    }
}
