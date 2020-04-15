// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Non-interactive zero-knowledge proofs (NIPKs).

use zkp::toolbox::{batch_verifier::BatchVerifier, prover::Prover, verifier::Verifier, SchnorrCS};
use zkp::Transcript;

fn okamoto_statement<CS: SchnorrCS>(
    cs: &mut CS,
    w: CS::ScalarVar,
    w_prime: CS::ScalarVar,
    G_w: CS::PointVar,
    G_w_prime: CS::PointVar,
    C_W: CS::PointVar,
) {
    cs.contrain()
}
