use contract_auxiliaries::{drg::stacked::{VerifierSetupParams, verifier_params::PublicInputs}, domain::{poseidon::PoseidonDomain, sha256::Sha256Domain}};
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum ExecuteMsg {
    SetSetupParams {setup_params: VerifierSetupParams}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]

pub enum QueryMsg {
    // GetCount returns the current count as a json-encoded number
    VerifyProofJson {vk_raw: Vec<u8>, proof_raw: Vec<u8>, public_inputs: PublicInputs<PoseidonDomain, Sha256Domain>}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum StateQueryMsg {

}
