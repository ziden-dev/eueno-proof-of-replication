use ark_bls12_381::{Bls12_381, Fr as Fr_ark, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_ff::{FromBytes, PrimeField as ArkPrimeField};
use ark_groth16::{VerifyingKey as ArkVerifyingKey, Proof as ArkProof};
const G1_LEN: usize = 48 * 2 + 1;
const G2_LEN: usize = 48 * 4 + 1;

pub fn deserialize_fr(scalar_le: Vec<u8>) -> Fr_ark {
    
    Fr_ark::from_le_bytes_mod_order(&scalar_le)
}

pub fn deserialize_g1(p_le: &[u8]) -> Result<ArkG1Affine, String> {
    ArkG1Affine::read(p_le).map_err(|_e| String::from("Failed to convert BLS G1Affine"))
}

pub fn deserialize_g2(p_le: &[u8]) -> Result<ArkG2Affine, String> {
    ArkG2Affine::read(p_le).map_err(|_e| String::from("Failed to convert BLS G2Affine"))
}

pub fn deserialize_verifying_key(
    vk_le: &Vec<u8>,
) -> Result<ArkVerifyingKey<Bls12_381>, String> {
    let mut pointer = 0;
    let alpha_g1 = deserialize_g1(&vk_le[pointer..pointer + G1_LEN])?;
    pointer = pointer + G1_LEN;
    let beta_g2 = deserialize_g2(&vk_le[pointer..pointer + G2_LEN])?;
    pointer = pointer + G2_LEN;
    let gamma_g2 = deserialize_g2(&vk_le[pointer..pointer + G2_LEN])?;
    pointer = pointer + G2_LEN;
    let delta_g2 = deserialize_g2(&vk_le[pointer..pointer + G2_LEN])?;
    pointer = pointer + G2_LEN;
    let mut gamma_abc_g1 = Vec::new();
    let ic_len = (vk_le.len() - pointer) / G1_LEN;
    for _ in 0..ic_len{
        let new_ic = deserialize_g1(&vk_le[pointer..pointer + G1_LEN])?;
        pointer = pointer + G1_LEN;
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

pub fn deserialize_proof(
    proof_le: &Vec<u8>
) -> Result<ArkProof<Bls12_381>, String>{
    
    let mut pointer = 0;
    let a = deserialize_g1(&proof_le[pointer..pointer + G1_LEN])?;
    pointer = pointer + G1_LEN;
    let b = deserialize_g2(&proof_le[pointer..pointer + G2_LEN])?;
    pointer = pointer + G2_LEN;
    let c = deserialize_g1(&proof_le[pointer..pointer + G1_LEN])?;
    Ok(ArkProof::<Bls12_381>{
        a, b, c
    })
}