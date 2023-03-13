use contract_auxiliaries::{
    domain::{poseidon::PoseidonDomain, sha256::Sha256Domain},
    drg::stacked::{verifier_params::PublicInputs, VerifierSetupParams},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum ExecuteMsg {
    SetSetupParams { setup_params: VerifierSetupParams },
    SetVkRaw { vk_raw: Vec<u8> },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]

pub enum QueryMsg {
    // GetCount returns the current count as a json-encoded number
    VerifyProofJson {
        proof_raw: Vec<u8>,
        public_inputs: PublicInputs<PoseidonDomain, Sha256Domain>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum StateQueryMsg {}
