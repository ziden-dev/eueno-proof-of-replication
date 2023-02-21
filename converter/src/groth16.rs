use ark_bls12_381::{Bls12_381, Fr as Fr_ark, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_ff::{FromBytes, PrimeField as ArkPrimeField};
use ark_groth16::{VerifyingKey as ArkVerifyingKey, Proof as ArkProof};
use blstrs::{Bls12, G1Affine, G2Affine, Scalar as Fr};

use bellperson::groth16::{VerifyingKey, Proof};

pub fn convert_fr(scalar: Fr) -> Fr_ark {
    let scalar_le = scalar.to_bytes_le();
    Fr_ark::from_le_bytes_mod_order(&scalar_le)
}

pub fn convert_g1(point: G1Affine) -> Result<ArkG1Affine, String> {
    let x = point.x();
    let y = point.y();

    let x_le = x.to_bytes_le();
    let y_le = y.to_bytes_le();

    let mut p_le = Vec::new();
    p_le.extend_from_slice(&x_le);
    p_le.extend_from_slice(&y_le);
    p_le.push(0);

    ArkG1Affine::read(p_le.as_slice()).map_err(|_e| String::from("Failed to convert BLS G1Affine"))
}

pub fn convert_g2(point: G2Affine) -> Result<ArkG2Affine, String> {
    let ax = point.x();
    let ay = point.y();

    let ax_le_0 = ax.c0().to_bytes_le();
    let ax_le_1 = ax.c1().to_bytes_le();
    let ay_le_0 = ay.c0().to_bytes_le();
    let ay_le_1 = ay.c1().to_bytes_le();

    let mut pa_le = Vec::new();
    pa_le.extend_from_slice(&ax_le_0);
    pa_le.extend_from_slice(&ax_le_1);
    pa_le.extend_from_slice(&ay_le_0);
    pa_le.extend_from_slice(&ay_le_1);
    pa_le.push(0);

    ArkG2Affine::read(pa_le.as_slice()).map_err(|_e| String::from("Failed to convert BLS G2Affine"))
}

pub fn convert_verifying_key(
    vk: &VerifyingKey<Bls12>,
) -> Result<ArkVerifyingKey<Bls12_381>, String> {
    let alpha_g1 = convert_g1(vk.alpha_g1.clone())?;
    let beta_g2 = convert_g2(vk.beta_g2.clone())?;
    let gamma_g2 = convert_g2(vk.gamma_g2.clone())?;
    let delta_g2 = convert_g2(vk.delta_g2.clone())?;
    let mut gamma_abc_g1 = Vec::new();
    for i in 0..vk.ic.len(){
        let new_ic = convert_g1(vk.ic[i].clone())?;
        gamma_abc_g1.push(new_ic);
    }
    Ok(ArkVerifyingKey::<Bls12_381> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

pub fn convert_proof(
    proof: &Proof<Bls12>
) -> Result<ArkProof<Bls12_381>, String>{
    let a = convert_g1(proof.a.clone())?;
    let b = convert_g2(proof.b.clone())?;
    let c = convert_g1(proof.c.clone())?;
    Ok(ArkProof::<Bls12_381>{
        a, b, c
    })
}