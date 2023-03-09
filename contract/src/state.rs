
use contract_auxiliaries::drg::stacked::VerifierSetupParams;
use cw_storage_plus::Item;

use cosmwasm_std::Addr;

pub const OWNER: Item<Addr> = Item::new("OWNER");
pub const SETUP_PARAMS: Item<VerifierSetupParams> = Item::new("SETUP_PARAMS");
