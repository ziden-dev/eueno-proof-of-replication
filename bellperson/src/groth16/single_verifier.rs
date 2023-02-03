use std::ops::{AddAssign, Mul};

use ff::PrimeField;
use group::{prime::PrimeCurveAffine, Curve, Group};
use pairing::{Engine, MillerLoopResult, MultiMillerLoop};

use super::{SinglePreparedVerifyingKey, Proof, VerifyingKey};
use crate::SynthesisError;


fn multiscalar_naive<G: PrimeCurveAffine>(
    points: &[G::Curve],
    scalars: &[G::Scalar],
) -> G::Curve
{
    let mut acc = G::Curve::identity();
    for (scalar, point) in scalars.iter().zip(points.iter()) {
        acc.add_assign(&point.mul(scalar));
    }
    acc
}

/// Generate a prepared verifying key, required to verify a proofs.
pub fn prepare_single_verifying_key<E: Engine + MultiMillerLoop>(
    vk: &VerifyingKey<E>,
) -> SinglePreparedVerifyingKey<E>
where
    E: MultiMillerLoop,
{
    let neg_gamma = -vk.gamma_g2;
    let neg_delta = -vk.delta_g2;


    SinglePreparedVerifyingKey {
        alpha_g1_beta_g2: E::pairing(&vk.alpha_g1, &vk.beta_g2),
        neg_gamma_g2: neg_gamma.into(),
        neg_delta_g2: neg_delta.into(),
        ic: vk.ic.clone(),
        ic_projective: vk.ic.iter().map(|i| i.to_curve()).collect(),
    }
}
/// Verify a single Proof.
pub fn verify_proof_single_thread<'a, E>(
    pvk: &'a SinglePreparedVerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::Fr],
) -> Result<bool, SynthesisError>
where
    E: MultiMillerLoop,
    <<E as Engine>::Fr as PrimeField>::Repr: Sync,
{

    if (public_inputs.len() + 1) != pvk.ic.len() {
        return Err(SynthesisError::MalformedVerifyingKey);
    }

    // The original verification equation is:
    // A * B = alpha * beta + inputs * gamma + C * delta
    // ... however, we rearrange it so that it is:
    // A * B - inputs * gamma - C * delta = alpha * beta
    // or equivalently:
    // A * B + inputs * (-gamma) + C * (-delta) = alpha * beta
    // which allows us to do a single final exponentiation.

    // - Calculate ML alpha * beta
    let ml_a_b = E::multi_miller_loop(&[(&proof.a, &proof.b.into())]);

    // - Calculate ML C * (-delta)
    let mut ml_all = E::multi_miller_loop(&[(&proof.c, &pvk.neg_delta_g2)]);

    // - Accumulate inputs (on the current thread)

    let mut acc = multiscalar_naive::<E::G1Affine>(&pvk.ic_projective[1..], &public_inputs);

    acc.add_assign(&pvk.ic_projective[0]);

    // Calculate ML inputs * (-gamma)
    let acc_aff = acc.to_affine();
    let ml_acc = E::multi_miller_loop(&[(&acc_aff, &pvk.neg_gamma_g2)]);
    // Wait for the threaded miller loops to finish

    // Combine the results.
    ml_all += ml_a_b;
    ml_all += ml_acc;

    // Calculate the final exponentiation
    let actual = ml_all.final_exponentiation();

    Ok(actual == pvk.alpha_g1_beta_g2)
}