use std::marker::PhantomData;

use anyhow::{ensure, Context};
use bellperson::Circuit;
use blstrs::Scalar as Fr;
use hashers::Hasher;
use generic_array::typenum;
use proofs_core::{
    compound_proof::{CircuitComponent, CompoundProof},
    drgraph::Graph,
    error::Result,
    gadgets::por::PoRCompound,
    gadgets::variables::Root,
    merkle::{BinaryMerkleTree, MerkleProofTrait},
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    por,
    proof::ProofScheme,
};
use typenum::U2;

use crate::drg::{DrgPoRep, DrgPoRepCircuit};

/// DRG based Proof of Replication.
///
/// # Fields
///
/// * `params` - parameters for the curve
///
/// ----> Private `replica_node` - The replica node being proven.
///
/// * `replica_node` - The replica node being proven.
/// * `replica_node_path` - The path of the replica node being proven.
/// * `replica_root` - The merkle root of the replica.
///
/// * `replica_parents` - A list of all parents in the replica, with their value.
/// * `replica_parents_paths` - A list of all parents paths in the replica.
///
/// ----> Private `data_node` - The data node being proven.
///
/// * `data_node_path` - The path of the data node being proven.
/// * `data_root` - The merkle root of the data.
/// * `replica_id` - The id of the replica.
///

pub struct DrgPoRepCompound<H, G>
where
    H: Hasher,
    G::Key: AsRef<H::Domain>,
    G: Graph<H>,
{
    // Sad phantom is sad
    _h: PhantomData<H>,
    _g: PhantomData<G>,
}

impl<C: Circuit<Fr>, H: Hasher, G: Graph<H>, P: ParameterSetMetadata> CacheableParameters<C, P>
    for DrgPoRepCompound<H, G>
where
    G::Key: AsRef<H::Domain>,
{
    fn cache_prefix() -> String {
        format!("drg-proof-of-replication-{}", H::name())
    }
}

impl<'a, H, G> CompoundProof<'a, DrgPoRep<'a, H, G>, DrgPoRepCircuit<'a, H>>
    for DrgPoRepCompound<H, G>
where
    H: 'static + Hasher,
    G::Key: AsRef<<H as Hasher>::Domain>,
    G: 'a + Graph<H> + ParameterSetMetadata + Sync + Send,
{
    fn generate_public_inputs(
        pub_in: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicParams,
        // We can ignore k because challenges are generated by caller and included
        // in PublicInputs.
        _k: Option<usize>,
    ) -> Result<Vec<Fr>> {
        let replica_id = pub_in.replica_id.context("missing replica id")?;
        let challenges = &pub_in.challenges;

        ensure!(
            pub_in.tau.is_none() == pub_params.private,
            "Public input parameter tau must be unset"
        );

        let (comm_r, comm_d) = match pub_in.tau {
            None => (None, None),
            Some(tau) => (Some(tau.comm_r), Some(tau.comm_d)),
        };

        let leaves = pub_params.graph.size();

        let por_pub_params = por::PublicParams {
            leaves,
            private: pub_params.private,
        };

        let mut input: Vec<Fr> = vec![replica_id.into()];

        let mut parents = vec![0; pub_params.graph.degree()];
        for challenge in challenges {
            let mut por_nodes = vec![*challenge as u32];
            pub_params.graph.parents(*challenge, &mut parents)?;
            por_nodes.extend_from_slice(&parents);

            for node in por_nodes {
                let por_pub_inputs = por::PublicInputs {
                    commitment: comm_r,
                    challenge: node as usize,
                };
                let por_inputs = PoRCompound::<BinaryMerkleTree<H>>::generate_public_inputs(
                    &por_pub_inputs,
                    &por_pub_params,
                    None,
                )?;

                input.extend(por_inputs);
            }

            let por_pub_inputs = por::PublicInputs {
                commitment: comm_d,
                challenge: *challenge,
            };

            let por_inputs = PoRCompound::<BinaryMerkleTree<H>>::generate_public_inputs(
                &por_pub_inputs,
                &por_pub_params,
                None,
            )?;
            input.extend(por_inputs);
        }
        Ok(input)
    }

    fn circuit(
        public_inputs: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicInputs,
        component_private_inputs: <DrgPoRepCircuit<'_, H> as CircuitComponent>::ComponentPrivateInputs,
        proof: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::Proof,
        public_params: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicParams,
        _partition_k: Option<usize>,
    ) -> Result<DrgPoRepCircuit<'a, H>> {
        let challenges = public_params.challenges_count;
        let len = proof.nodes.len();

        ensure!(len <= challenges, "too many challenges");
        ensure!(
            proof.replica_parents.len() == len,
            "Number of replica parents must match"
        );
        ensure!(
            proof.replica_nodes.len() == len,
            "Number of replica nodes must match"
        );

        let replica_nodes = proof
            .replica_nodes
            .iter()
            .map(|node| Some(node.data.into()))
            .collect();

        let replica_nodes_paths = proof
            .replica_nodes
            .iter()
            .map(|node| node.proof.as_options())
            .collect();

        let is_private = public_params.private;

        let (data_root, replica_root) = if is_private {
            (
                component_private_inputs.comm_d.context("is_private")?,
                component_private_inputs.comm_r.context("is_private")?,
            )
        } else {
            (
                Root::Val(Some(proof.data_root.into())),
                Root::Val(Some(proof.replica_root.into())),
            )
        };

        let replica_id = public_inputs.replica_id;

        let replica_parents = proof
            .replica_parents
            .iter()
            .map(|parents| {
                parents
                    .iter()
                    .map(|(_, parent)| Some(parent.data.into()))
                    .collect()
            })
            .collect();

        let replica_parents_paths = proof
            .replica_parents
            .iter()
            .map(|parents| {
                let p = parents
                    .iter()
                    .map(|(_, parent)| parent.proof.as_options())
                    .collect();
                p
            })
            .collect();

        let data_nodes = proof
            .nodes
            .iter()
            .map(|node| Some(node.data.into()))
            .collect();

        let data_nodes_paths = proof
            .nodes
            .iter()
            .map(|node| node.proof.as_options())
            .collect();

        ensure!(
            public_inputs.tau.is_none() == public_params.private,
            "inconsistent private state"
        );

        Ok(DrgPoRepCircuit {
            replica_nodes,
            replica_nodes_paths,
            replica_root,
            replica_parents,
            replica_parents_paths,
            data_nodes,
            data_nodes_paths,
            data_root,
            replica_id: replica_id.map(Into::into),
            private: public_params.private,
            _h: Default::default(),
        })
    }

    fn blank_circuit(
        public_params: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicParams,
    ) -> DrgPoRepCircuit<'a, H> {
        let depth = public_params.graph.merkle_tree_depth::<U2>() as usize;
        let degree = public_params.graph.degree();
        let arity = 2;

        let challenges_count = public_params.challenges_count;

        let replica_nodes = vec![None; challenges_count];
        let replica_nodes_paths =
            vec![vec![(vec![None; arity - 1], None); depth - 1]; challenges_count];

        let replica_root = Root::Val(None);
        let replica_parents = vec![vec![None; degree]; challenges_count];
        let replica_parents_paths =
            vec![vec![vec![(vec![None; arity - 1], None); depth - 1]; degree]; challenges_count];
        let data_nodes = vec![None; challenges_count];
        let data_nodes_paths =
            vec![vec![(vec![None; arity - 1], None); depth - 1]; challenges_count];
        let data_root = Root::Val(None);

        DrgPoRepCircuit {
            replica_nodes,
            replica_nodes_paths,
            replica_root,
            replica_parents,
            replica_parents_paths,
            data_nodes,
            data_nodes_paths,
            data_root,
            replica_id: None,
            private: public_params.private,
            _h: Default::default(),
        }
    }
}
