import axios from "axios";
import fs from "fs";
import {
    SigningCosmWasmClient,
    UploadResult,
    InstantiateResult,
    ExecuteResult,
    MigrateResult,
    JsonObject,
    InstantiateOptions,
} from "@cosmjs/cosmwasm-stargate";
import { GasPrice, calculateFee, StdFee, Coin } from "@cosmjs/stargate";
import {
    DirectSecp256k1HdWallet,
    makeCosmoshubPath,
} from "@cosmjs/proto-signing";
import { HdPath } from "@cosmjs/crypto";
import path from "path";
import { coin } from "@cosmjs/amino";

export interface Chain {
    readonly httpUrl: string;
    readonly networkId: string;
    readonly feeToken: string;
    readonly bech32prefix: string;
    readonly hdPath: HdPath;
    readonly faucetUrl?: string;
    readonly defaultKeyFile: string;
    readonly fees: {
        upload: number;
        init: number;
        exec: number;
    };
    readonly gasPrice: GasPrice;
}

export interface InstantiateObject {
    readonly input: {
        wasm: boolean;
        wasmFile: string;
        memo: string;
        codeId: number;
    };
    readonly instantiateMsg: Record<string, any>;
    readonly label: string;
    readonly options?: InstantiateOptions;
}

export interface ExecuteObject {
    readonly contractAddr: string;
    readonly executeMsg: Record<string, any>;
    readonly memo: string;
    readonly funds: Coin[];
}

export interface QueryObject {
    readonly contractAddr: string;
    readonly queryMsg: Record<string, any>;
}

export interface MigrateObject {
    readonly contractAddr: string;
    readonly codeId: number,
    readonly migrateMsg: Record<string, any>;
    readonly memo: string;
}

export class Cosm {
    address: string;
    chain: Chain;
    client: SigningCosmWasmClient;

    constructor() {}

    static init = async (chain: Chain, mnemonic: string): Promise<Cosm> => {
        let instance = new Cosm();
        const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, {
            hdPaths: [chain.hdPath],
            prefix: chain.bech32prefix,
        });
        const client = await instance.connect(wallet, chain);
        const [account] = await wallet.getAccounts();
        instance.chain = chain;
        instance.address = account.address;
        instance.client = client;
        return instance;
    };

    connect = async (
        wallet: DirectSecp256k1HdWallet,
        chain: Chain
    ): Promise<SigningCosmWasmClient> => {
        const clientOptions = {
            prefix: chain.bech32prefix,
        };
        return await SigningCosmWasmClient.connectWithSigner(
            chain.httpUrl,
            wallet,
            clientOptions
        );
    };

    hitFaucet = async (): Promise<void> => {
        let denom: string = this.chain.feeToken;
        let address: string = this.address;
        let faucetUrl: string = this.chain.faucetUrl || "";
        await axios.post(faucetUrl, { denom, address });
    };

    getBalance = async (): Promise<Coin> => {
        const tokens = await this.client.getBalance(
            this.address,
            this.chain.feeToken
        );
        return tokens;
    };

    getUploadFee = (): StdFee => {
        return calculateFee(this.chain.fees.upload, this.chain.gasPrice);
    };

    getInitFee = (): StdFee => {
        return calculateFee(this.chain.fees.init, this.chain.gasPrice);
    };

    getExecFee = (): StdFee => {
        return calculateFee(this.chain.fees.exec, this.chain.gasPrice);
    };

    upload = async (wasm: Uint8Array, memo: string, gasLimit?: number): Promise<UploadResult> => {
        let uploadFee: StdFee|"auto"|number;
        if (gasLimit != null) {
            uploadFee = calculateFee(gasLimit, this.chain.gasPrice);
        } else {
            uploadFee = this.getUploadFee();
        }
        return await this.client.upload(this.address, wasm, uploadFee, memo);
    };

    parseInstantiateObject = (jsonObject: object): InstantiateObject => {
        let rs: InstantiateObject = {
            input: {
                wasm: jsonObject["input"]["wasm"],
                wasmFile: parseString(jsonObject["input"]["wasm_file"]),
                memo: parseString(jsonObject["input"]["memo"]),
                codeId: jsonObject["input"]["code_id"],
            },
            instantiateMsg: parseMsg(jsonObject["instantiateMsg"]),
            label: parseString(jsonObject["label"]),
            options: parseInstantiateOptions(jsonObject["options"]),
        };

        return rs;
    };

    initContract = async (
        rawObject: object,
        gasLimit?: number,
        uploadGas?: number
    ): Promise<InstantiateResult> => {
        let instantiateObject: InstantiateObject =
            this.parseInstantiateObject(rawObject);
        let isWasm: boolean = instantiateObject.input.wasm;
        let wasm: Uint8Array;
        let codeId: number;
        if (isWasm) {
            wasm = fs.readFileSync(instantiateObject.input.wasmFile);
            let rs = await this.upload(wasm, instantiateObject.input.memo, uploadGas);
            codeId = rs.codeId;
        } else {
            codeId = instantiateObject.input.codeId;
        }
        if (gasLimit == null) {
            gasLimit = this.chain.fees.init;
        }

        const instantiateResponse = await this.client.instantiate(
            this.address,
            codeId,
            instantiateObject.instantiateMsg,
            instantiateObject.label,
            calculateFee(gasLimit, this.chain.gasPrice),
            instantiateObject.options
        );

        return instantiateResponse;
    };

    parseExecuteObject = (jsonObject: object): ExecuteObject => {
        let rs: ExecuteObject = {
            contractAddr: parseString(jsonObject["contractAddr"]),
            executeMsg: parseMsg(jsonObject["executeMsg"]),
            memo: parseString(jsonObject["memo"]),
            funds: parseFunds(jsonObject["funds"]),
        };
        return rs;
    };

    parseMigrateObject = (jsonObject: object): MigrateObject => {
        let rs: MigrateObject = {
            contractAddr: parseString(jsonObject["contractAddr"]),
            codeId:  jsonObject["codeId"],
            migrateMsg: parseMsg(jsonObject["migrateMsg"]),
            memo: parseString(jsonObject["memo"]),
        };
        return rs;
    };


    execute = async (
        rawObject: object,
        gasLimit?: number
    ): Promise<ExecuteResult> => {
        let executetionObject: ExecuteObject =
            this.parseExecuteObject(rawObject);
        if (gasLimit == null) {
            gasLimit = this.chain.fees.exec;
        }
        return await this.client.execute(
            this.address,
            executetionObject.contractAddr,
            executetionObject.executeMsg,
            calculateFee(gasLimit, this.chain.gasPrice),
            executetionObject.memo,
            executetionObject.funds
        );
    };

    migrate = async (
        rawObject: object,
        gasLimit?: number
    ) : Promise<MigrateResult> => {
        let executetionObject: MigrateObject =
            this.parseMigrateObject(rawObject);
        if (gasLimit == null) {
            gasLimit = this.chain.fees.exec;
        }

        return await this.client.migrate(
            this.address,
            executetionObject.contractAddr,
            executetionObject.codeId,
            executetionObject.migrateMsg,
            calculateFee(gasLimit, this.chain.gasPrice),
            executetionObject.memo

        )
    }

    parseQueryObject = (jsonObject: object): QueryObject => {
        let rs: QueryObject = {
            contractAddr: parseString(jsonObject["contractAddr"]),
            queryMsg: parseMsg(jsonObject["queryMsg"]),
        };

        return rs;
    };

    query = async (rawObject: object): Promise<JsonObject> => {
        let queryObject = this.parseQueryObject(rawObject);
        return await this.client.queryContractSmart(
            queryObject.contractAddr,
            queryObject.queryMsg
        );
    };

    getContractsByCodeId = async (
        codeId: number
    ): Promise<readonly string[]> => {
        return await this.client.getContracts(codeId);
    };
}

export function parseMsg(msg: object): object {
    for (var name in msg) {
        if (typeof msg[name] == "object") {
            msg[name] = parseObject(msg[name]);
        }
    }
    return msg;
}

function parseObject(item: object) {
    if (item != null) {
        let isBinary = item.hasOwnProperty("binary");
        for (var name in item) {
            if (typeof item[name] == "object") {
                item[name] = parseObject(item[name]);
            }
        }
        if (isBinary) {
            delete item["binary"];
            return toBase64(item);
        } else {
            return item;
        }
    } else return null;
}

function parseInstantiateOptions(options: object): InstantiateOptions {
    let rs: InstantiateOptions = {
        memo: options["memo"],
        admin: parseString(options["admin"]),
        funds:
            options["funds"] == null || options["funds"].length == 0
                ? null
                : options["funds"],
    };
    return rs;
}

function parseString(str: string): string {
    return str == null || str == "" ? null : str;
}

function parseFunds(funds: object) {
    let rs: Coin[] = new Array<Coin>();
    for (var index in funds) {
        let fund = funds[index];
        rs.push(coin(fund["amount"], fund["denom"]));
    }
    return rs;
}

export function toBase64(msg: object) {
    return Buffer.from(JSON.stringify(msg)).toString("base64");
}
