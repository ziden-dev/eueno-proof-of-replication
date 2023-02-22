const CONFIG = require("../../../config.json");
export const migrateContract = (contract, code_id) => {
    return {
        contractAddr: contract,
        codeId: code_id,
        migrateMsg: {},
        memo: null,
    };
};
