use blstrs::{Bls12, G1Affine, G2Affine, Scalar as Fr};

use bellperson::groth16::{VerifyingKey, Proof};



pub fn serialize_fr(scalar: Fr) -> Vec<u8> {
    scalar.to_bytes_le().to_vec()
}

pub fn serialize_g1(point: G1Affine) -> Vec<u8> {
    let x = point.x();
    let y = point.y();

    let x_le = x.to_bytes_le();
    let y_le = y.to_bytes_le();

    let mut p_le = Vec::new();
    p_le.extend_from_slice(&x_le);
    p_le.extend_from_slice(&y_le);
    p_le.push(0);

    p_le
}

pub fn serialize_g2(point: G2Affine) -> Vec<u8> {
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

    pa_le
}

pub fn serialize_verifying_key(
    vk: &VerifyingKey<Bls12>,
) -> Vec<u8> {
    let mut vk_le = Vec::new();
    vk_le.extend(serialize_g1(vk.alpha_g1.clone()));
    vk_le.extend(serialize_g2(vk.beta_g2.clone()));
    vk_le.extend(serialize_g2(vk.gamma_g2.clone()));
    vk_le.extend(serialize_g2(vk.delta_g2.clone()));
    
    for i in 0..vk.ic.len(){
        vk_le.extend(serialize_g1(vk.ic[i].clone()));
    }
    vk_le
}

pub fn serialize_proof(
    proof: &Proof<Bls12>
) -> Vec<u8>{
    let mut proof_le = Vec::new();
    proof_le.extend(serialize_g1(proof.a.clone()));
    proof_le.extend(serialize_g2(proof.b.clone()));
    proof_le.extend(serialize_g1(proof.c.clone()));
    
    proof_le
}