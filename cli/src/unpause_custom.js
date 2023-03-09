const { oraiTestnetChain } = require("./chain.ts");
const { Cosm } = require("./cosm-lib.ts");
const message = require("./index");

require("dotenv").config();
const MNEMONIC1 = process.env.MNEMONIC1;
const CONFIG = require("../testnet-config.json");
async function main() {
    let cosm = await Cosm.init(oraiTestnetChain, MNEMONIC1);
    console.log(cosm.address);

    const pauser = "orai1rserfkzday606809hqc6xh0kpzmhwejrkkt7weysxwhzeyhgrppqnr4ahd";
    const pauseAll = await cosm.execute(message.executeUnpauseContracts(pauser, true, true, false, true, true, true, true, true, true)); // pause all contracts

    console.log("USDT :", pauseAll);
}

main();
