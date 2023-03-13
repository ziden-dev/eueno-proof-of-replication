#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{OWNER, SETUP_PARAMS};
use contract_auxiliaries::deserializer::{deserialize_proof, deserialize_verifying_key};
use contract_auxiliaries::domain::{poseidon::PoseidonDomain, sha256::Sha256Domain};
use contract_auxiliaries::drg::stacked::VerifierStackedDrg;

// version info for migration info
const CONTRACT_NAME: &str = "stacked-drg";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    OWNER.save(deps.storage, &info.sender)?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::SetSetupParams { setup_params } => {
            execute::set_setup_params(deps, info, setup_params)
        }
        ExecuteMsg::SetVkRaw { vk_raw } => {
            execute::set_vk_raw(deps, info, vk_raw)
        },
    }
}

pub mod execute {

    use contract_auxiliaries::drg::stacked::VerifierSetupParams;

    use crate::state::VK_RAW;

    use super::*;
    pub fn set_setup_params(
        deps: DepsMut,
        info: MessageInfo,
        setup_params: VerifierSetupParams,
    ) -> Result<Response, ContractError> {
        if info.sender == OWNER.load(deps.storage).unwrap() {
            SETUP_PARAMS.save(deps.storage, &setup_params)?;
            Ok(Response::default())
        } else {
            Err(ContractError::Unauthorized {})
        }
    }

    pub fn set_vk_raw(
        deps: DepsMut,
        info: MessageInfo,
        vk_raw: Vec<u8>,
    ) -> Result<Response, ContractError> {
        if info.sender == OWNER.load(deps.storage).unwrap() {
            VK_RAW.save(deps.storage, &vk_raw)?;
            Ok(Response::default())
        } else {
            Err(ContractError::Unauthorized {})
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::VerifyProofJson {
            proof_raw,
            public_inputs,
        } => to_binary(&query::verify_proof_json(
            deps,
            proof_raw,
            public_inputs,
        )?),
    }
}

pub mod query {

    use contract_auxiliaries::drg::stacked::verifier_params::PublicInputs;

    use crate::state::VK_RAW;

    use super::*;
    pub fn verify_proof_json(
        deps: Deps,
        proof_raw: Vec<u8>,
        public_inputs: PublicInputs<PoseidonDomain, Sha256Domain>,
    ) -> StdResult<bool> {
        let vk_raw = VK_RAW.load(deps.storage).unwrap();
        let vk = deserialize_verifying_key(&vk_raw).unwrap();
        let proof = deserialize_proof(&proof_raw).unwrap();
        let setup_params = SETUP_PARAMS.load(deps.storage).unwrap();
        let public_params =
            VerifierStackedDrg::<PoseidonDomain, Sha256Domain>::setup(&setup_params).unwrap();
        let verifier = VerifierStackedDrg::<PoseidonDomain, Sha256Domain>::new(&vk);
        let verified = verifier
            .verify(
                &public_params,
                &public_inputs,
                &proof,
                &contract_auxiliaries::drg::stacked::challenges::ChallengeRequirements {
                    minimum_challenges: 1,
                },
            )
            .unwrap();
        Ok(verified)
    }
}
