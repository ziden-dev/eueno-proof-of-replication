# Eueno-proof-of-replication

> This library is a folk of [Filecoin Proof of Replication library](https://github.com/filecoin-project/rust-fil-proofs/tree/master/storage-proofs-porep).

An module being responsible for proving and verifying the availability of some pieces of data in certain data nodes of Eueno storage system.

## Use case

The module contains to 2 main actors: Prover - Eueno's node which stores data, Verifier - Cosmwasm Smart Contract.

At a certain point of time, when being asked, the prover must create a Snark proof that convinces the verifier that the node actually holds the required piece of data.

In the following parts, we will cover all detailed steps that need to be done by provers and verifiers to implement the protocol.

**Example code:** [here](https://github.com/ziden-dev/eueno-proof-of-replication/blob/contracts-with-tests/exps/src/main.rs) 

## Setting up common parameters

There are some shared parameters that should be agreed and set up by both provers and verifiers before implementing the protocol.

* **nodes**: byte length of the data piece
* **degree**: node degree of the DRGraph, ussually being set by default value (6)
* **expansion_degree**: expansion node degree of the Stacked DRGraph, usually being set by default value (8)
* **num_layers**: the number of layers within the Stacked DRG
* **layer_challenges**: define number of challenges being generated for each layer.
* **partition_count**: used for proving and verifying a bunch of proofs simultanously, temporarily disabled at current version.
* **porep_id**: the id used in each proving time, should be unique

**Example**

```rust
let nodes = 1024;
let degree = 6;
let expansion_degree = 8;
let num_layers = 2;
let layer_challenges = LayerChallenges::new(num_layers, 1);
let partition_count = 1;
let arbitrary_porep_id = [55; 32];
```

### SetupParams
All of these above parameters are used to construct **SetupParams** in both Prover and Verifier

**Prover side**

```rust
    let setup_params = compound_proof::SetupParams {
        vanilla_params: SetupParams {
            nodes,
            degree,
            expansion_degree,
            porep_id: arbitrary_porep_id,
            layer_challenges,
            api_version: ApiVersion::V1_1_0, // inherit from filecoin, should be removed later
        },
        partitions: Some(partition_count),
        priority: false,
    };
```

**Verifier side**

```rust
    let verifier_setup_params = VerifierSetupParams {
        nodes: nodes as u64,
        degree: degree as u64,
        expansion_degree: expansion_degree as u64,
        porep_id: arbitrary_porep_id,
        layer_challenges: verifier_layer_challenge,
        api_version: VerifierApiVersion::V1_1_0,
    };
```

### PublicParams

**PublicParams** are constructed from **SetupParams** in both side

**Prover side**

```rust
    let public_params =
        StackedCompound::<Tree, Sha256Hasher>::setup(&setup_params).expect("setup failed");
```

**Verifier side**

```rust
    // Contract owner calls the set function on smart contract, passes the setup_params as a parameter
    pub fn set_setup_params(
        deps: DepsMut,
        info: MessageInfo,
        setup_params: VerifierSetupParams,
    ) -> Result<Response, ContractError>
```

**Groth16 Trusted setup**

Set up some necessary parameters of Groth16 algorithm, including verifier key, which is stored on the smart contract
```rust
let blank_groth_params = <StackedCompound<Tree, Sha256Hasher> as CompoundProof<
        StackedDrg<'_, Tree, Sha256Hasher>,
        _,
    >>::groth_params(Some(&mut rng), &public_params.vanilla_params)
    .expect("failed to generate groth params");
```

Extract verifier key from groth params and store it on the smart contract
```rust
let mut vk_out = Vec::new();
    blank_groth_params
        .vk
        .write(&mut vk_out)
        .expect("failed to export verifying key");

// Call this function on the smart contract with vk_out as vk_raw parameter
pub fn set_vk_raw(
        deps: DepsMut,
        info: MessageInfo,
        vk_raw: Vec<u8>,
    ) -> Result<Response, ContractError>
```

## Prover

### Data

The proved data has the form of the vertor of bytes

#### An example of sampling an arbitrary piece of data from ramdom source

```rust
let data: Vec<u8> = (0..nodes)
        .flat_map(|_| fr_into_bytes(&Fr::random(&mut rng)))
        .collect();
```

***Warning:*** In case when we want to create data from files, there need to be a method to guarantee those pieces of data can be converted validily into the vector of BLS12-381 scalar field numbers.

### Create replications of that data
```rust
// MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempdir().unwrap();
    let config = StoreConfig::new(
        cache_dir.path(),
        CacheKey::CommDTree.to_string(),
        default_rows_to_discard(nodes, BINARY_ARITY),
    );

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    // Replicate data
    let (tau, (p_aux, t_aux)) = StackedDrg::<Tree, Sha256Hasher>::replicate(
        &public_params.vanilla_params,
        &replica_id.into(),
        (mmapped_data.as_mut()).into(),
        None,
        config,
        replica_path.clone(),
    )
    .expect("replication failed");
```

### Construct Snark Proof and Public Inputs affirming that these replications are valid

```rust
    // Calculate Public inputs
    let seed = rng.gen();
    let public_inputs =
        PublicInputs::<<Tree::Hasher as Hasher>::Domain, <Sha256Hasher as Hasher>::Domain> {
            replica_id: replica_id.into(),
            seed,
            tau: Some(tau),
            k: None,
        };

    // Calculate Private Inputs
    // Store a copy of the t_aux for later resource deletion.
    let t_aux_orig = t_aux.clone();

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux = TemporaryAuxCache::<Tree, _>::new(&t_aux, replica_path)
        .expect("failed to restore contents of t_aux");

    let private_inputs = PrivateInputs::<Tree, Sha256Hasher> { p_aux, t_aux };

    //Calculate Proof
    let proof = StackedCompound::prove(
        &public_params,
        &public_inputs,
        &private_inputs,
        &blank_groth_params,
    )
    .expect("failed while proving");

    // Transform proof to contract calldata so we can pass them as a parameter into the verifying function
    let proof_call_data = proof.to_vec();
```

## Verifier

Call the verifying function to validate public inputs and proof which have been calculated by prover previously

```rust
pub fn verify_proof(
        deps: Deps,
        proof_raw: Vec<u8>,
        public_inputs: PublicInputs<PoseidonDomain, Sha256Domain>,
    ) -> StdResult<bool>
```

## Some limits of current version

* Hasn't supported aggregating Groth16 proofs (Multiproof) yet
* Hasn't supported transfer outer files into standard form of data

