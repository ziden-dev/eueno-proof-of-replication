import path from "path";
import { Chain } from "./cosm-lib";
import { GasPrice } from "@cosmjs/stargate";
import { makeCosmoshubPath } from "@cosmjs/proto-signing";

export const malagaChain: Chain = {
    httpUrl: "https://rpc.malaga-420.cosmwasm.com",
    networkId: "malaga-420",
    bech32prefix: "wasm",
    feeToken: "umlg",
    faucetUrl: "https://faucet.malaga-420.cosmwasm.com/credit",
    hdPath: makeCosmoshubPath(0),
    defaultKeyFile: path.join(__dirname, ".malaga.key"),
    fees: {
        upload: 2500000,
        init: 1000000,
        exec: 500000,
    },
    gasPrice: GasPrice.fromString("0.25umlg"),
};

export const uniChain: Chain = {
    httpUrl: "https://rpc.uni.juno.deuslabs.fi",
    networkId: "uni",
    bech32prefix: "juno",
    feeToken: "ujunox",
    faucetUrl: "https://faucet.uni.juno.deuslabs.fi/credit",
    hdPath: makeCosmoshubPath(0),
    defaultKeyFile: path.join(__dirname, ".uni.key"),
    fees: {
        upload: 6000000,
        init: 500000,
        exec: 200000,
    },
    gasPrice: GasPrice.fromString("0.025ujunox"),
};

export const oraiTestnetChain: Chain = {
    httpUrl: "https://testnet-rpc.orai.io/",
    networkId: "Oraichain-testnet",
    bech32prefix: "orai",
    feeToken: "orai",
    faucetUrl: "",
    hdPath: makeCosmoshubPath(0),
    defaultKeyFile: path.join(__dirname, ".oraitestnet.key"),
    fees: {
        upload: 30000000,
        init: 1000000,
        exec: 10000000,
    },
    gasPrice: GasPrice.fromString("0.25orai"),
};

export const oraiMainnetChain: Chain = {
    httpUrl: "https://rpc.orai.io",
    networkId: "Oraichain",
    bech32prefix: "orai",
    feeToken: "orai",
    faucetUrl: "",
    hdPath: makeCosmoshubPath(0),
    defaultKeyFile: path.join(__dirname, ".oraimainnet.key"),
    fees: {
        upload: 2500000,
        init: 1000000,
        exec: 10000000,
    },
    gasPrice: GasPrice.fromString("0.25orai"),
};
