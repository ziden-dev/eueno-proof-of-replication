use std::{io::Cursor, time::SystemTime};

use bellperson::groth16::VerifyingKey;
use blstrs::{Bls12, Scalar as Fr};
use converter::{groth16::convert_fr, serializer::{serialize_verifying_key, serialize_proof}};
use ff::Field;
use fr32::fr_into_bytes;
use generic_array::typenum::{U2, U4, U8};
use hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, Hasher};
use merkletree::store::StoreConfig;
use proofs_core::{
    api_version::ApiVersion,
    cache_key::CacheKey,
    compound_proof::{self, CompoundProof},
    drgraph::BASE_DEGREE,
    merkle::{get_base_tree_count, DiskTree, MerkleTreeTrait},
    test_helper::setup_replica,
    util::default_rows_to_discard,
    TEST_SEED,
};
use proofs_porep::{
    stacked::{
        ChallengeRequirements, LayerChallenges, PrivateInputs, PublicInputs, SetupParams,
        StackedCompound, StackedDrg, TemporaryAux, TemporaryAuxCache, BINARY_ARITY, EXP_DEGREE,
    },
    PoRep,
};

use contract_auxiliaries::{
    domain::{poseidon::PoseidonDomain, sha256::Sha256Domain},
    drg::stacked::{
        challenges::LayerChallenges as VerifierLayerChallenges, VerifierSetupParams,
        VerifierStackedDrg,
    },
    utils::ApiVersion as VerifierApiVersion, deserializer::{deserialize_verifying_key, deserialize_proof},
};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use tempfile::tempdir;

fn test_gen_pubins_top_8_4_2() {
    test_generate_public_inputs::<DiskTree<PoseidonHasher, U8, U4, U2>>();
}

fn test_generate_public_inputs<Tree: 'static + MerkleTreeTrait>() {
    let nodes = 8 * get_base_tree_count::<Tree>();

    let degree = BASE_DEGREE;
    let expansion_degree = EXP_DEGREE;
    let num_layers = 2;
    let layer_challenges = LayerChallenges::new(num_layers, 1);
    let partition_count = 1;

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    println!("Start replicating data");
    let start = SystemTime::now();

    let replica_id: Fr = Fr::random(&mut rng);
    let data: Vec<u8> = (0..nodes)
        .flat_map(|_| fr_into_bytes(&Fr::random(&mut rng)))
        .collect();

    let arbitrary_porep_id = [55; 32];
    let setup_params = compound_proof::SetupParams {
        vanilla_params: SetupParams {
            nodes,
            degree,
            expansion_degree,
            porep_id: arbitrary_porep_id,
            layer_challenges,
            api_version: ApiVersion::V1_1_0,
        },
        partitions: Some(partition_count),
        priority: false,
    };

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

    let public_params =
        StackedCompound::<Tree, Sha256Hasher>::setup(&setup_params).expect("setup failed");
    let (tau, (p_aux, t_aux)) = StackedDrg::<Tree, Sha256Hasher>::replicate(
        &public_params.vanilla_params,
        &replica_id.into(),
        (mmapped_data.as_mut()).into(),
        None,
        config,
        replica_path.clone(),
    )
    .expect("replication failed");

    let rep_time = SystemTime::now()
        .duration_since(start)
        .expect("Time went backwards")
        .as_millis();
    println!("replicating time: {:?}", rep_time);

    let mut copied = vec![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne!(data, copied, "replication did not change data");

    let seed = rng.gen();
    let public_inputs =
        PublicInputs::<<Tree::Hasher as Hasher>::Domain, <Sha256Hasher as Hasher>::Domain> {
            replica_id: replica_id.into(),
            seed,
            tau: Some(tau),
            k: None,
        };

    let public_inputs_json =
        serde_json::to_string(&public_inputs).expect("failed to serialize public inputs");
    println!("public input json: {:?}", public_inputs_json);

    let new_public_inputs =
        serde_json::from_str(&public_inputs_json).expect("failed to deserialize public inputs");
    assert!(public_inputs.eq(&new_public_inputs));

    let expected_pubins = StackedCompound::<Tree, Sha256Hasher>::generate_public_inputs_for_test(
        &public_inputs,
        &public_params.vanilla_params,
        Some(0),
    )
    .expect("failed to gen public inputs for test");

    let verifier_layer_challenge = VerifierLayerChallenges::new(num_layers, 1);
    let verifier_setup_params = VerifierSetupParams {
        nodes: nodes as u64,
        degree: degree as u64,
        expansion_degree: expansion_degree as u64,
        porep_id: arbitrary_porep_id,
        layer_challenges: verifier_layer_challenge,
        api_version: VerifierApiVersion::V1_1_0,
    };

    let verifier_public_params =
        VerifierStackedDrg::<PoseidonDomain, Sha256Domain>::setup(&verifier_setup_params)
            .expect("failed to setup verifier public params");

    let public_inputs_json =
        serde_json::to_string(&public_inputs).expect("failed to serialize public inputs");

    let verifier_public_input =
        serde_json::from_str(&public_inputs_json).expect("failed to deserialize public inputs");
    let actual_pubins = VerifierStackedDrg::<PoseidonDomain, Sha256Domain>::generate_public_inputs(
        &verifier_public_input,
        &verifier_public_params,
        Some(0),
    )
    .expect("failed to gen verifier public inputs");

    assert_eq!(actual_pubins.len(), expected_pubins.len());
    actual_pubins
        .into_iter()
        .zip(expected_pubins.into_iter())
        .for_each(|(a, b)| {
            let converted_b = convert_fr(b);
            assert!(a.eq(&converted_b));
        });

    // Store a copy of the t_aux for later resource deletion.
    let t_aux_orig = t_aux.clone();

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux = TemporaryAuxCache::<Tree, _>::new(&t_aux, replica_path)
        .expect("failed to restore contents of t_aux");

    let private_inputs = PrivateInputs::<Tree, Sha256Hasher> { p_aux, t_aux };

    println!("Start setting up groth parameters");
    let start = SystemTime::now();
    let blank_groth_params = <StackedCompound<Tree, Sha256Hasher> as CompoundProof<
        StackedDrg<'_, Tree, Sha256Hasher>,
        _,
    >>::groth_params(Some(&mut rng), &public_params.vanilla_params)
    .expect("failed to generate groth params");

    let mut vk_out = Vec::new();
    blank_groth_params
        .vk
        .write(&mut vk_out)
        .expect("failed to export verifying key");
    println!("Verifying key: {:?}", vk_out);

    let vk =
        VerifyingKey::<Bls12>::read(Cursor::new(vk_out)).expect("failed to recover verifying key");
    assert!(vk.eq(&blank_groth_params.vk));

    let vk_le = serialize_verifying_key(&vk);

    let ark_vk = deserialize_verifying_key(&vk_le).expect("failed to convert verifying key");

    let setup_time = SystemTime::now()
        .duration_since(start)
        .expect("Time went backwards")
        .as_millis();
    println!("setting up time: {:?}", setup_time);

    // Discard cached MTs that are no longer needed.
    TemporaryAux::<Tree, Sha256Hasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

    println!("Start proving");
    let start = SystemTime::now();
    let proof = StackedCompound::prove(
        &public_params,
        &public_inputs,
        &private_inputs,
        &blank_groth_params,
    )
    .expect("failed while proving");
    let proving_time = SystemTime::now()
        .duration_since(start)
        .expect("Time went backwards")
        .as_secs();
    println!("proving time: {:?}", proving_time);

    let proof_call_data = proof.to_vec();
    println!("Proof call data: {:?}", proof_call_data);

    let verified = StackedCompound::verify(
        &public_params,
        &public_inputs,
        &proof,
        &ChallengeRequirements {
            minimum_challenges: 1,
        },
    )
    .expect("failed while verifying");

    assert!(verified);

    let proof_le = serialize_proof(&proof.circuit_proofs[0]);

    let ark_proof = deserialize_proof(&proof_le).expect("failed to convert proof");
    let ark_verifier = VerifierStackedDrg::<PoseidonDomain, Sha256Domain>::new(&ark_vk);
    let ark_verified = ark_verifier.verify(
        &verifier_public_params,
        &verifier_public_input,
        &ark_proof,
        &contract_auxiliaries::drg::stacked::challenges::ChallengeRequirements {
            minimum_challenges: 1,
        },
    ).expect("failed while verifying ark");
    assert!(ark_verified);

    cache_dir.close().expect("Failed to remove cache dir");
}
fn main() {
    test_gen_pubins_top_8_4_2();
}
