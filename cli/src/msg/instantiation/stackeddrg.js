const CONFIG = require("../../../config.json");
export const initStackedDrg = () => {
    return {
        input: {
            wasm: true,
            wasm_file: "porep/contracts/stacked-drg/artifacts/stacked-drg.wasm",
            memo: "Stacked Drg",
            code_id: 0,
        },
        instantiateMsg: {

        },
        label: "Stacked Drg",
        options: {
            memo: null,
            funds: [],
            admin: CONFIG.admin,
        },
    };
};
