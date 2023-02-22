const { oraiTestnetChain } = require("./chain.ts");
const { Cosm } = require("./cosm-lib.ts");
const message = require("./index");
const CONFIG = require("../config.json");
require("dotenv").config();
const MNEMONIC1 = process.env.MNEMONIC1;

async function main() {
    let cosm = await Cosm.init(oraiTestnetChain, MNEMONIC1);
    console.log(cosm.address);

    const state = (await cosm.initContract(message.initStackedDrg())).contractAddress;
    console.log(state)
    
}

main();
