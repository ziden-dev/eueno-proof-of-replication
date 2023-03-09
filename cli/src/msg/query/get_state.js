const TOKEN_ADDRESS = process.env.TOKEN;
export const queryState = (state, id) => {
    return {
        contractAddr: state,
        queryMsg: {
            get_state: {
                id: id,
            },
        },
    };
};