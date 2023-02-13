
use cw_storage_plus::Item;

use cosmwasm_std::{Uint256, Addr};
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

use crate::contract::SetupParams;

pub const OWNER: Item<Addr> = Item::new("OWNER");
pub const SETUP_PARAMS: Item<String> = Item::new("SETUP_PARAMS");
