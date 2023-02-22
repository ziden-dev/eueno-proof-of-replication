use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum ExecuteMsg {
    SetSetupParams {setup_params_json: String}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]

pub enum QueryMsg {
    // GetCount returns the current count as a json-encoded number
    VerifyProofJson {vk_raw: Vec<u8>, proof_raw: Vec<u8>, public_inputs_json: String}
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum StateQueryMsg {

}
