const { oraiTestnetChain } = require("./chain.ts");
const { Cosm } = require("./cosm-lib.ts");
const message = require("./index");

require("dotenv").config();
const MNEMONIC1 = process.env.MNEMONIC1;

async function main() {
    let cosm = await Cosm.init(oraiTestnetChain, MNEMONIC1);
    console.log(cosm.address);
    const addr = "orai1h3aknu8val9agf7vtvllxt6dnvh6m39n2zgnnhmrap3tl0g82kcscz8rgt";
    const migrateMarket = (await cosm.migrate(message.migrateContract(addr,4375)))
        .contractAddress;

    // const recipient = "orai1y6nq9tvapk8xqmnlxf9cnjyfddrvzr6pfle9ze";
    // const amount = "10000000000000"
    // const mintUSDT = await cosm.execute(message.executeMintUSDT(recipient, amount));    
    console.log("Migrate result:", migrateMarket)
}

main();
