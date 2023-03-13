use crate::{domain::Domain, drg::drgraph::Graph};

use super::{
    verifier_graph::VerifierStackedBucketGraph,
    verifier_params::{PublicParams, SetupParams},
    challenges::ChallengeRequirements, verifier_params::PublicInputs,
};
use anyhow::{ensure, Result};
use ark_groth16::{Proof, PreparedVerifyingKey, VerifyingKey, prepare_verifying_key, verify_proof};
use std::marker::PhantomData;
use ark_bls12_381::{Fr, Bls12_381};

/// The inputs that are necessary for the verifier to verify the proof.
#[derive(Clone)]
pub struct MerkleTreePublicInputs {
    /// The challenge, which leaf to prove.
    pub challenge: usize,
}

/// The parameters shared between the prover and verifier.
#[derive(Clone)]
pub struct MerkleTreePublicParams {
    /// How many leaves the underlying merkle tree has.
    pub leaves: usize,
}

fn generate_merkletree_public_inputs(
    pub_inputs: &MerkleTreePublicInputs,
    pub_params: &MerkleTreePublicParams,
    _k: Option<usize>,
) -> Result<Vec<Fr>> {
    ensure!(
        pub_inputs.challenge < pub_params.leaves,
        "Challenge out of range"
    );
    let mut inputs = Vec::new();

    // Inputs are (currently, inefficiently) packed with one `Fr` per challenge.
    // Boolean/bit auth paths trivially correspond to the challenged node's index within a sector.
    // Defensively convert the challenge with `try_from` as a reminder that we must not truncate.
    let input_fr = Fr::from(u64::try_from(pub_inputs.challenge).expect("challenge type too wide"));
    inputs.push(input_fr);

    Ok(inputs)
}

/// Helper to generate public inputs for inclusion proofs.
fn generate_inclusion_inputs(
    por_params: &MerkleTreePublicParams,
    challenge: usize,
    k: Option<usize>,
) -> Result<Vec<Fr>> {
    let pub_inputs = MerkleTreePublicInputs { challenge };

    generate_merkletree_public_inputs(&pub_inputs, por_params, k)
}

pub struct VerifierStackedDrg<H: Domain, G: Domain> {
    _h: PhantomData<H>,
    _g: PhantomData<G>,
    pvk: PreparedVerifyingKey<Bls12_381>
}

impl<H: Domain, G: Domain> VerifierStackedDrg<H, G> {
    pub fn new(vk: &VerifyingKey<Bls12_381>) -> Self{
        let pvk = prepare_verifying_key(vk);
        Self {
            pvk,
            _h: Default::default(),
            _g: Default::default()
        }
    }

    pub fn setup(sp: &SetupParams) -> Result<PublicParams<H>> {
        let graph = VerifierStackedBucketGraph::<H>::new_stacked(
            sp.nodes as usize,
            sp.degree as usize,
            sp.expansion_degree as usize,
            sp.porep_id,
            sp.api_version,
        )?;

        Ok(PublicParams::new(graph, sp.layer_challenges.clone()))
    }

    pub fn satisfies_requirements(
        public_params: &PublicParams<H>,
        requirements: &ChallengeRequirements,
        partitions: usize,
    ) -> bool {
        let partition_challenges = public_params.layer_challenges.challenges_count_all();

        assert_eq!(
            partition_challenges.checked_mul(partitions),
            Some(partition_challenges * partitions)
        );
        partition_challenges * partitions >= requirements.minimum_challenges
    }

    pub fn generate_public_inputs(
        pub_in: &PublicInputs<H, G>,
        pub_params: &PublicParams<H>,
        k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let graph = &pub_params.graph;

        let mut inputs = Vec::new();

        let replica_id = pub_in.replica_id;
        inputs.push(replica_id.into());

        let comm_d = pub_in.tau.as_ref().expect("missing tau").comm_d;
        inputs.push(comm_d.into());

        let comm_r = pub_in.tau.as_ref().expect("missing tau").comm_r;
        inputs.push(comm_r.into());

        let por_params = MerkleTreePublicParams {
            leaves: graph.size(),
        };
        let por_params_d = MerkleTreePublicParams {
            leaves: graph.size(),
        };

        let all_challenges = pub_in.challenges(&pub_params.layer_challenges, graph.size(), k);

        for challenge in all_challenges.into_iter() {
            // comm_d inclusion proof for the data leaf
            inputs.extend(generate_inclusion_inputs(
                &por_params_d,
                challenge,
                k,
            )?);

            // drg parents
            let mut drg_parents = vec![0; graph.base_graph().degree()];
            graph.base_graph().parents(challenge, &mut drg_parents)?;

            // Inclusion Proofs: drg parent node in comm_c
            for parent in drg_parents.into_iter() {
                inputs.extend(generate_inclusion_inputs(
                    &por_params,
                    parent as usize,
                    k,
                )?);
            }

            // exp parents
            let mut exp_parents = vec![0; graph.expansion_degree()];
            graph.expanded_parents(challenge, &mut exp_parents)?;

            // Inclusion Proofs: expander parent node in comm_c
            for parent in exp_parents.into_iter() {
                inputs.extend(generate_inclusion_inputs(
                    &por_params,
                    parent as usize,
                    k,
                )?);
            }

            inputs.push(Fr::from(challenge as u64));

            // Inclusion Proof: encoded node in comm_r_last
            inputs.extend(generate_inclusion_inputs(&por_params, challenge, k)?);

            // Inclusion Proof: column hash of the challenged node in comm_c
            inputs.extend(generate_inclusion_inputs(&por_params, challenge, k)?);
        }

        Ok(inputs)
    }

    // verify is equivalent to ProofScheme::verify.
    pub fn verify(
        &self,
        public_params: &PublicParams<H>,
        public_inputs: &PublicInputs<H, G>,
        proof: &Proof<Bls12_381>,
        requirements: &ChallengeRequirements,
    ) -> Result<bool> {

        if !Self::satisfies_requirements(
            &public_params,
            requirements,
            1,
        ) {
            return Ok(false);
        }

        let inputs: Vec<_> = Self::generate_public_inputs(public_inputs, public_params, Some(0))?;

        let res = verify_proof(&self.pvk,  proof, &inputs).unwrap();
        Ok(res)
    }
}
