use blstrs::Bls12;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{SETUP_PARAMS, OWNER};
use pairing::{Engine, MillerLoopResult, MultiMillerLoop};
use ff::{PrimeField, Field};
use group::{prime::PrimeCurveAffine, Curve, Group, UncompressedEncoding, GroupEncoding};
use std::fmt::{self, Debug, Error, Formatter};
use std::mem::size_of;
use ec_gpu_gen::EcError;
use std::ops::{AddAssign, Mul};
use blstrs::Scalar as Fr;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::marker::PhantomData;
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use generic_array::typenum::Unsigned;
use sha2::{Digest, Sha256};
use rand::{Rng, SeedableRng, RngCore};
use rand_chacha::ChaCha8Rng;
use std::cmp::{max, min, Ordering};
use std::io::{self, Read, Write, Cursor};
use byteorder::{BigEndian, ReadBytesExt};
use std::panic::panic_any;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use blake2b_simd::blake2b;

// version info for migration info
const CONTRACT_NAME: &str = "stacked-drg";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION"); 

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    OWNER.save(deps.storage, &info.sender)?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::SetSetupParams {setup_params_json} => execute::set_setup_params(deps, info, setup_params_json)
    }
}

pub mod execute {

    use super::*;
    pub fn set_setup_params(deps: DepsMut, info: MessageInfo, setup_params_json: String) -> Result<Response, ContractError>{
        if info.sender == OWNER.load(deps.storage).unwrap() {
            SETUP_PARAMS.save(deps.storage, &setup_params_json)?;
            Ok(Response::default())
        }
        else {
            Err(ContractError::Unauthorized{})
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::VerifyProofJson {vk_raw, proof_raw, public_inputs_json} => to_binary(&query::verify_proof_json(deps, vk_raw, proof_raw, public_inputs_json)?)
    }
}

pub mod query { 

    use super::*;
    pub fn verify_proof_json(
        deps: Deps, 
        vk_raw: Vec<u8>,
        proof_raw: Vec<u8>,
        public_inputs_json: String,
    ) -> StdResult<bool>
    {
        let vk = VerifyingKey::<Bls12>::read(Cursor::new(vk_raw)).unwrap();
        let proof = Proof::<Bls12>::read(Cursor::new(proof_raw)).unwrap();
        let public_inputs: PublicInputs<PoseidonDomain, Sha256Domain> = serde_json::from_str(&public_inputs_json).unwrap();
        let pvk = prepare_single_verifying_key(&vk);
        let setup_params_json = SETUP_PARAMS.load(deps.storage).unwrap();
        let setup_params: VanillaParams = serde_json::from_str(&setup_params_json).unwrap();
        let public_params = VerifierStackedDrg::<PoseidonDomain, Sha256Domain>::setup(&setup_params).unwrap();
        let inputs = VerifierStackedDrg::<PoseidonDomain, Sha256Domain>::generate_public_inputs(&public_inputs, &public_params, Some(0)).unwrap();
        verify_proof(&pvk, &proof, &inputs)
    }

    // pub fn verify_batch<E>(
    //     vk_raw: Vec<u8>,
    //     proofs_raw: Vec<Vec<u8>>,
    //     public_inputs_json: String,
    // ) -> Result<bool, SynthesisError> 
    // where
    //     E: MultiMillerLoop,
    //     <<E as Engine>::Fr as PrimeField>::Repr: Sync,
    // {
    //     let pvk: &SinglePreparedVerifyingKey<E> = serde_json::from_str(&pvk_json).unwrap();
    //     let proofs: &[&Proof<E>] = serde_json::from_str(&proofs_json).unwrap();
    //     let public_inputs: &[Vec<E::Fr>] = serde_json::from_str(&public_inputs_json).unwrap();
    //     assert_eq!(proofs.len(), public_inputs.len(), "Inconsistent inputs");
    //     let mut res = true;
    //     for i in 0..proofs.len() {
    //         if !verify_proof(pvk, proofs[i], &public_inputs[i]) {
    //             res = false;
    //             break;
    //         }
    //     }
    //     Ok(res)
    // }
}

pub fn multiscalar_naive<G: PrimeCurveAffine>(
    points: &[G::Curve],
    scalars: &[G::Scalar],
) -> G::Curve
{
    let mut acc = G::Curve::identity();
    for (scalar, point) in scalars.iter().zip(points.iter()) {
        acc.add_assign(&point.mul(scalar));
    }
    acc
}

pub fn verify_proof<E>(
    pvk: &SinglePreparedVerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::Fr],
) -> StdResult<bool>
where
    E: MultiMillerLoop,
    <<E as Engine>::Fr as PrimeField>::Repr: Sync,
{
    assert_eq!((public_inputs.len() + 1), pvk.ic.len(), "Inconsistent inputs");
    // The original verification equation is:
    // A * B = alpha * beta + inputs * gamma + C * delta
    // ... however, we rearrange it so that it is:
    // A * B - inputs * gamma - C * delta = alpha * beta
    // or equivalently:
    // A * B + inputs * (-gamma) + C * (-delta) = alpha * beta
    // which allows us to do a single final exponentiation.

    // - Calculate ML alpha * beta
    let ml_a_b = E::multi_miller_loop(&[(&proof.a, &proof.b.into())]);

    // - Calculate ML C * (-delta)
    let mut ml_all = E::multi_miller_loop(&[(&proof.c, &pvk.neg_delta_g2)]);

    // - Accumulate inputs (on the current thread)

    let mut acc = multiscalar_naive::<E::G1Affine>(&pvk.ic_projective[1..], &public_inputs);

    acc.add_assign(&pvk.ic_projective[0]);

    // Calculate ML inputs * (-gamma)
    let acc_aff = acc.to_affine();
    let ml_acc = E::multi_miller_loop(&[(&acc_aff, &pvk.neg_gamma_g2)]);
    // Wait for the threaded miller loops to finish

    // Combine the results.
    ml_all += ml_a_b;
    ml_all += ml_acc;

    // Calculate the final exponentiation
    let actual = ml_all.final_exponentiation();

    Ok(actual == pvk.alpha_g1_beta_g2)
}

/// Generate a prepared verifying key, required to verify a proofs.
pub fn prepare_single_verifying_key<E: Engine + MultiMillerLoop>(
    vk: &VerifyingKey<E>,
) -> SinglePreparedVerifyingKey<E>
where
    E: MultiMillerLoop,
{
    let neg_gamma = -vk.gamma_g2;
    let neg_delta = -vk.delta_g2;


    SinglePreparedVerifyingKey {
        alpha_g1_beta_g2: E::pairing(&vk.alpha_g1, &vk.beta_g2),
        neg_gamma_g2: neg_gamma.into(),
        neg_delta_g2: neg_delta.into(),
        ic: vk.ic.clone(),
        ic_projective: vk.ic.iter().map(|i| i.to_curve()).collect(),
    }
}

#[derive(Clone, Debug)]
pub struct Proof<E: Engine> {
    pub a: E::G1Affine,
    pub b: E::G2Affine,
    pub c: E::G1Affine,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(thiserror::Error, Debug)]
pub enum SynthesisError {
    /// During synthesis, we lacked knowledge of a variable assignment.
    #[error("an assignment for a variable could not be computed")]
    AssignmentMissing,
    /// During synthesis, we divided by zero.
    #[error("division by zero")]
    DivisionByZero,
    /// During synthesis, we constructed an unsatisfiable constraint system.
    #[error("unsatisfiable constraint system")]
    Unsatisfiable,
    /// During synthesis, our polynomials ended up being too high of degree
    #[error("polynomial degree is too large")]
    PolynomialDegreeTooLarge,
    /// During proof generation, we encountered an identity in the CRS
    #[error("encountered an identity element in the CRS")]
    UnexpectedIdentity,
    /// During proof generation, we encountered an I/O error with the CRS
    #[error("encountered an I/O error: {0}")]
    IoError(#[from] io::Error),
    /// During verification, our verifying key was malformed.
    #[error("malformed verifying key")]
    MalformedVerifyingKey,
    /// During CRS generation, we observed an unconstrained auxiliary variable
    #[error("auxiliary variable was unconstrained")]
    UnconstrainedVariable,
    /// During GPU multiexp/fft, some GPU related error happened
    #[error("encountered a GPU error: {0}")]
    GpuError(#[from] GpuError),
    #[error("attempted to aggregate malformed proofs: {0}")]
    MalformedProofs(String),
    #[error("malformed SRS")]
    MalformedSrs,
    #[error("non power of two proofs given for aggregation")]
    NonPowerOfTwo,
    #[error("incompatible vector length: {0}")]
    IncompatibleLengthVector(String),
    #[error("invalid pairing")]
    InvalidPairing,
}

pub struct SinglePreparedVerifyingKey<E>
where
E: MultiMillerLoop{
    /// Pairing result of alpha*beta
    pub(crate) alpha_g1_beta_g2: <E as Engine>::Gt,
    /// -gamma in G2 (used for single)
    pub(crate) neg_gamma_g2: <E as MultiMillerLoop>::G2Prepared,
    /// -delta in G2 (used for single)
    pub(crate) neg_delta_g2: <E as MultiMillerLoop>::G2Prepared,
    /// Copy of IC from `VerifiyingKey`.
    pub(crate) ic: Vec<E::G1Affine>,

    // Aggregation specific prep
    pub(crate) ic_projective: Vec<E::G1>,
}

#[derive(Debug, Clone)]
pub struct VerifyingKey<E: Engine + MultiMillerLoop> {
    // alpha in g1 for verifying and for creating A/C elements of
    // proof. Never the point at infinity.
    pub alpha_g1: E::G1Affine,

    // beta in g1 and g2 for verifying and for creating B/C elements
    // of proof. Never the point at infinity.
    pub beta_g1: E::G1Affine,
    pub beta_g2: E::G2Affine,

    // gamma in g2 for verifying. Never the point at infinity.
    pub gamma_g2: E::G2Affine,

    // delta in g1/g2 for verifying and proving, essentially the magic
    // trapdoor that forces the prover to evaluate the C element of the
    // proof with only components from the CRS. Never the point at
    // infinity.
    pub delta_g1: E::G1Affine,
    pub delta_g2: E::G2Affine,

    // Elements of the form (beta * u_i(tau) + alpha v_i(tau) + w_i(tau)) / gamma
    // for all public inputs. Because all public inputs have a dummy constraint,
    // this is the same size as the number of inputs, and never contains points
    // at infinity.
    pub ic: Vec<E::G1Affine>,
}

#[derive(thiserror::Error, Debug)]
pub enum GpuError {
    #[error("GPUError: {0}")]
    Simple(&'static str),
    #[cfg(any(feature = "cuda", feature = "opencl"))]
    #[error("No kernel is initialized!")]
    KernelUninitialized,
    #[error("EC GPU error: {0}")]
    EcGpu(#[from] EcError),
    #[error("GPU accelerator is disabled!")]
    GpuDisabled,
}

#[derive(Debug)]
pub struct PublicParams<D>
where
    D: 'static + Domain,
{
    pub graph: VerifierStackedBucketGraph<D>,
    pub layer_challenges: LayerChallenges,
    _d: PhantomData<D>,
}

pub trait Domain:
    Ord
    + Copy
    + Clone
    + AsRef<[u8]>
    + Default
    + Debug
    + Eq
    + Send
    + Sync
    + From<Fr>
    + From<<Fr as PrimeField>::Repr>
    + Into<Fr>
    + Serialize
    + DeserializeOwned
    + Element
    + StdHash
{
    #[allow(clippy::wrong_self_convention)]
    fn into_bytes(&self) -> Vec<u8>;
    fn try_from_bytes(raw: &[u8]) -> anyhow::Result<Self>;
    /// Write itself into the given slice, LittleEndian bytes.
    fn write_bytes(&self, _: &mut [u8]) -> anyhow::Result<()>;

    fn random<R: RngCore>(rng: &mut R) -> Self;
}

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct BucketGraph<D: Domain> {
    nodes: usize,
    base_degree: usize,
    seed: [u8; 28],
    api_version: ApiVersion,
    _d: PhantomData<D>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerChallenges {
    /// How many layers we are generating challenges for.
    layers: usize,
    /// The maximum count of challenges
    max_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicInputs<T: Domain, S: Domain> {
    #[serde(bound = "")]
    pub replica_id: T,
    pub seed: [u8; 32],
    #[serde(bound = "")]
    pub tau: Option<Tau<T, S>>,
    /// Partition index
    pub k: Option<usize>,
}

pub type VerifierStackedBucketGraph<D> = StackedGraph<D, BucketGraph<D>>;

pub trait Element: Ord + Clone + AsRef<[u8]> + Sync + Send + Default + std::fmt::Debug {
    /// Returns the length of an element when serialized as a byte slice.
    fn byte_len() -> usize;

    /// Creates the element from its byte form. Panics if the slice is not appropriately sized.
    fn from_slice(bytes: &[u8]) -> Self;

    fn copy_to_slice(&self, bytes: &mut [u8]);
}

pub const NODE_SIZE: usize = 32;


pub trait Graph<D: Domain>: Debug + Clone + PartialEq + Eq {
    type Key: Debug;

    /// Returns the expected size of all nodes in the graph.
    fn expected_size(&self) -> usize {
        self.size() * NODE_SIZE
    }

    /// Returns a sorted list of all parents of this node. The parents may be repeated.
    ///
    /// If a node doesn't have any parents, then this vector needs to return a vector where
    /// the first element is the requested node. This will be used as indicator for nodes
    /// without parents.
    ///
    /// The `parents` parameter is used to store the result. This is done fore performance
    /// reasons, so that the vector can be allocated outside this call.
    fn parents(&self, node: usize, parents: &mut [u32]) -> Result<(), ()>;

    /// Returns the size of the graph (number of nodes).
    fn size(&self) -> usize;

    /// Returns the number of parents of each node in the graph.
    fn degree(&self) -> usize;

    fn new(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: PoRepID,
        api_version: ApiVersion,
    ) -> Result<Self, SynthesisError>;
    fn seed(&self) -> [u8; 28];

    /// Creates the encoding key.
    /// The algorithm for that is `Sha256(id | encodedParentNode1 | encodedParentNode1 | ...)`.
    fn create_key(
        &self,
        id: &D,
        node: usize,
        parents: &[u32],
        parents_data: &[u8],
        exp_parents_data: Option<&[u8]>,
    ) -> Result<Self::Key, SynthesisError>;
}

#[derive(Clone, Debug)]
pub struct StackedGraph<D, G>
where
    D: Domain,
    G: Graph<D> + 'static,
{
    expansion_degree: usize,
    base_graph: G,
    pub(crate) feistel_keys: [Index; 4],
    feistel_precomputed: FeistelPrecomputed,
    api_version: ApiVersion,
    id: String,
    _d: PhantomData<D>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum ApiVersion {
    V1_0_0,
    V1_1_0,
}

/// The inputs that are necessary for the verifier to verify the proof.
#[derive(Debug, Clone)]
pub struct MerkleTreePublicInputs {
    /// The challenge, which leaf to prove.
    pub challenge: usize,
}

/// The parameters shared between the prover and verifier.
#[derive(Clone, Debug)]
pub struct MerkleTreePublicParams {
    /// How many leaves the underlying merkle tree has.
    pub leaves: usize,
}

fn generate_merkletree_public_inputs(
    pub_inputs: &MerkleTreePublicInputs,
    pub_params: &MerkleTreePublicParams,
    _k: Option<usize>,
) -> Result<Vec<Fr>, Error> {
    assert!(
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
) -> Result<Vec<Fr>, Error> {
    let pub_inputs = MerkleTreePublicInputs { challenge };

    generate_merkletree_public_inputs(&pub_inputs, por_params, k)
}

#[derive(Debug)]
pub struct VerifierStackedDrg<H: Domain, G: Domain> {
    _h: PhantomData<H>,
    _g: PhantomData<G>,
}

impl<H: Domain, G: Domain> VerifierStackedDrg<H, G> {
    pub fn setup(sp: &VanillaParams) -> Result<PublicParams<H>, SynthesisError> {
        let graph = VerifierStackedBucketGraph::<H>::new_stacked(
            sp.nodes,
            sp.degree,
            sp.expansion_degree,
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
    ) -> Result<Vec<Fr>, Error> {
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
            graph.base_graph().parents(challenge, &mut drg_parents).unwrap();

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
            graph.expanded_parents(challenge, &mut exp_parents).unwrap();

            // Inclusion Proofs: expander parent node in comm_c
            for parent in exp_parents.into_iter() {
                inputs.extend(generate_inclusion_inputs(
                    &por_params,
                    parent as usize,
                    k,
                )?);
            }

            inputs.push(u64_into_fr(challenge as u64));

            // Inclusion Proof: encoded node in comm_r_last
            inputs.extend(generate_inclusion_inputs(&por_params, challenge, k)?);

            // Inclusion Proof: column hash of the challenged node in comm_c
            inputs.extend(generate_inclusion_inputs(&por_params, challenge, k)?);
        }

        Ok(inputs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tau<D: Domain, E: Domain> {
    #[serde(bound = "")]
    pub comm_d: E,
    #[serde(bound = "")]
    pub comm_r: D,
}

pub fn graph_height<U: Unsigned>(number_of_leafs: usize) -> usize {
    get_merkle_tree_row_count(number_of_leafs, U::to_usize())
}

pub fn get_merkle_tree_row_count(leafs: usize, branches: usize) -> usize {
    // Optimization
    if branches == 2 {
        (leafs * branches).trailing_zeros() as usize
    } else {
        (branches as f64 * leafs as f64).log(branches as f64) as usize
    }
}

pub type PoRepID = [u8; 32];
pub type Index = u64;
pub type FeistelPrecomputed = (Index, Index, Index);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VanillaParams {
    // Number of nodes
    pub nodes: usize,

    // Base degree of DRG
    pub degree: usize,

    pub expansion_degree: usize,

    pub porep_id: [u8; 32],
    pub layer_challenges: LayerChallenges,
    pub api_version: ApiVersion,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SetupParams {
    pub vanilla_params: VanillaParams,
    pub partitions: Option<usize>,
    pub priority: bool,
}

#[derive(Debug, Default)]
pub struct ChallengeRequirements {
    pub minimum_challenges: usize,
}

#[inline]
pub fn u64_into_fr(n: u64) -> Fr {
    Fr::from(n)
}

impl<D: Domain> Graph<D> for BucketGraph<D> {
    type Key = D;

    fn create_key(
        &self,
        id: &D,
        node: usize,
        parents: &[u32],
        base_parents_data: &[u8],
        _exp_parents_data: Option<&[u8]>,
    ) -> Result<Self::Key, SynthesisError> {
        let mut hasher = Sha256::new();
        hasher.update(AsRef::<[u8]>::as_ref(id));

        // The hash is about the parents, hence skip if a node doesn't have any parents
        if node != parents[0] as usize {
            for parent in parents.iter() {
                let offset = data_at_node_offset(*parent as usize);
                hasher.update(&base_parents_data[offset..offset + NODE_SIZE]);
            }
        }

        let hash = hasher.finalize();
        Ok(bytes_into_fr_repr_safe(hash.as_ref()).into())
    }

    #[inline]
    fn parents(&self, node: usize, parents: &mut [u32]) -> Result<(), ()> {
        let m = self.degree();

        match node {
            // There are special cases for the first and second node: the first node self
            // references, the second node only references the first node.
            0 | 1 => {
                // Use the degree of the current graph (`m`) as `parents.len()` might be bigger than
                // that (that's the case for Stacked Graph).
                for parent in parents.iter_mut().take(m) {
                    *parent = 0;
                }
                Ok(())
            }
            _ => {
                // DRG node indexes are guaranteed to fit within a `u32`.
                let node = node as u32;

                let mut seed = [0u8; 32];
                seed[..28].copy_from_slice(&self.seed);
                seed[28..].copy_from_slice(&node.to_le_bytes());
                let mut rng = ChaCha8Rng::from_seed(seed);
                
                let m_prime = m - 1;
                // Large sector sizes require that metagraph node indexes are `u64`.
                let metagraph_node = node as u64 * m_prime as u64;
                let n_buckets = (metagraph_node as f64).log2().ceil() as u64;

                let (predecessor_index, other_drg_parents) = match self.api_version {
                    ApiVersion::V1_0_0 => (m_prime, &mut parents[..]),
                    ApiVersion::V1_1_0 => (0, &mut parents[1..]),
                };

                for parent in other_drg_parents.iter_mut().take(m_prime) {
                    let bucket_index = (rng.gen::<u64>() % n_buckets) + 1;
                    let largest_distance_in_bucket = min(metagraph_node, 1 << bucket_index);
                    let smallest_distance_in_bucket = max(2, largest_distance_in_bucket >> 1);

                    // Add 1 becuase the number of distances in the bucket is inclusive.
                    let n_distances_in_bucket =
                        largest_distance_in_bucket - smallest_distance_in_bucket + 1;

                    let distance =
                        smallest_distance_in_bucket + (rng.gen::<u64>() % n_distances_in_bucket);

                    let metagraph_parent = metagraph_node - distance;

                    // Any metagraph node mapped onto the DRG can be safely cast back to `u32`.
                    let mapped_parent = (metagraph_parent / m_prime as u64) as u32;

                    *parent = if mapped_parent == node {
                        node - 1
                    } else {
                        mapped_parent
                    };
                }

                // Immediate predecessor must be the first parent, so hashing cannot begin early.
                parents[predecessor_index] = node - 1;
                Ok(())
            }
        }
    }

    #[inline]
    fn size(&self) -> usize {
        self.nodes
    }

    /// Returns the degree of the graph.
    #[inline]
    fn degree(&self) -> usize {
        self.base_degree
    }

    fn seed(&self) -> [u8; 28] {
        self.seed
    }

    fn new(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: PoRepID,
        api_version: ApiVersion,
    ) -> Result<Self, SynthesisError> {
        assert_eq!(expansion_degree, 0, "Expension degree must be zero.");

        // The number of metagraph nodes must be less than `2u64^54` as to not incur rounding errors
        // when casting metagraph node indexes from `u64` to `f64` during parent generation.
        let m_prime = base_degree - 1;
        let n_metagraph_nodes = nodes as u64 * m_prime as u64;
        assert!(
            n_metagraph_nodes <= 1u64 << 54,
            "The number of metagraph nodes must be precisely castable to `f64`"
        );

        let drg_seed = derive_drg_seed(porep_id);

        Ok(BucketGraph {
            nodes,
            base_degree,
            seed: drg_seed,
            api_version,
            _d: PhantomData,
        })
    }
}

pub fn data_at_node_offset(v: usize) -> usize {
    v * NODE_SIZE
}

#[inline]
pub fn bytes_into_fr_repr_safe(le_bytes: &[u8]) -> <Fr as PrimeField>::Repr {
    debug_assert!(le_bytes.len() == 32);
    let mut repr = [0u8; 32];
    repr.copy_from_slice(le_bytes);
    repr[31] &= 0b0011_1111;
    repr
}

impl<E: Engine + MultiMillerLoop> VerifyingKey<E> {

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut g1_repr = <E::G1Affine as UncompressedEncoding>::Uncompressed::default();
        let mut g2_repr = <E::G2Affine as UncompressedEncoding>::Uncompressed::default();

        reader.read_exact(g1_repr.as_mut())?;
        let alpha_g1 = read_uncompressed_point(&g1_repr)?;

        reader.read_exact(g1_repr.as_mut())?;
        let beta_g1 = read_uncompressed_point(&g1_repr)?;

        reader.read_exact(g2_repr.as_mut())?;
        let beta_g2 = read_uncompressed_point(&g2_repr)?;

        reader.read_exact(g2_repr.as_mut())?;
        let gamma_g2 = read_uncompressed_point(&g2_repr)?;

        reader.read_exact(g1_repr.as_mut())?;
        let delta_g1 = read_uncompressed_point(&g1_repr)?;

        reader.read_exact(g2_repr.as_mut())?;
        let delta_g2 = read_uncompressed_point(&g2_repr)?;

        let ic_len = reader.read_u32::<BigEndian>()? as usize;

        let mut ic = vec![];

        for _ in 0..ic_len {
            reader.read_exact(g1_repr.as_mut())?;
            let g1: E::G1Affine = read_uncompressed_point(&g1_repr)?;
            if g1.is_identity().into() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "point at infinity",
                ));
            }
            ic.push(g1);
        }

        Ok(VerifyingKey {
            alpha_g1,
            beta_g1,
            beta_g2,
            gamma_g2,
            delta_g1,
            delta_g2,
            ic,
        })
    }
}

pub fn derive_drg_seed(porep_id: PoRepID) -> [u8; 28] {
    let mut drg_seed = [0; 28];
    let raw_seed = derive_porep_domain_seed(DRSAMPLE_DST, porep_id);
    drg_seed.copy_from_slice(&raw_seed[..28]);
    drg_seed
}

impl<E: Engine> Proof<E> {
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.a.to_bytes().as_ref())?;
        writer.write_all(self.b.to_bytes().as_ref())?;
        writer.write_all(self.c.to_bytes().as_ref())?;

        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = vec![0u8; Self::size()];
        reader.read_exact(&mut bytes)?;
        let proof = Self::read_many(&bytes, 1)?.pop().unwrap();

        Ok(proof)
    }

    pub fn size() -> usize {
        let g1_compressed_size = <E::G1Affine as GroupEncoding>::Repr::default()
            .as_ref()
            .len();
        let g2_compressed_size = <E::G2Affine as GroupEncoding>::Repr::default()
            .as_ref()
            .len();
        2 * g1_compressed_size + g2_compressed_size
    }

    pub fn read_many(proof_bytes: &[u8], num_proofs: usize) -> io::Result<Vec<Self>> {
        debug_assert_eq!(proof_bytes.len(), num_proofs * Self::size());

        // Decompress and group check in parallel
        #[derive(Clone, Copy)]
        enum ProofPart<E: Engine> {
            A(E::G1Affine),
            B(E::G2Affine),
            C(E::G1Affine),
        }
        let g1_len = <E::G1Affine as GroupEncoding>::Repr::default()
            .as_ref()
            .len();
        let g2_len = <E::G2Affine as GroupEncoding>::Repr::default()
            .as_ref()
            .len();

        let parts = (0..num_proofs * 3)
            .into_iter()
            .map(|i| -> io::Result<_> {
                // Work on all G2 points first since they are more expensive. Avoid
                // having a long pole due to g2 starting late.
                let c = i / num_proofs;
                let p = i % num_proofs;
                let offset = Self::size() * p;
                match c {
                    0 => {
                        let mut g2_repr = <E::G2Affine as GroupEncoding>::Repr::default();
                        let start = offset + g1_len;
                        let end = start + g2_len;
                        g2_repr.as_mut().copy_from_slice(&proof_bytes[start..end]);

                        let b: E::G2Affine = {
                            let opt = E::G2Affine::from_bytes(&g2_repr);
                            Option::from(opt).ok_or_else(|| {
                                io::Error::new(io::ErrorKind::InvalidData, "not on curve")
                            })
                        }?;
                        if b.is_identity().into() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "point at infinity",
                            ));
                        }
                        Ok(ProofPart::<E>::B(b))
                    }
                    1 => {
                        let mut g1_repr = <E::G1Affine as GroupEncoding>::Repr::default();
                        let start = offset;
                        let end = start + g1_len;
                        g1_repr.as_mut().copy_from_slice(&proof_bytes[start..end]);
                        let a: E::G1Affine = {
                            let opt = E::G1Affine::from_bytes(&g1_repr);
                            Option::from(opt).ok_or_else(|| {
                                io::Error::new(io::ErrorKind::InvalidData, "not on curve")
                            })
                        }?;

                        if a.is_identity().into() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "point at infinity",
                            ));
                        }
                        Ok(ProofPart::<E>::A(a))
                    }
                    2 => {
                        let mut g1_repr = <E::G1Affine as GroupEncoding>::Repr::default();
                        let start = offset + g1_len + g2_len;
                        let end = start + g1_len;

                        g1_repr.as_mut().copy_from_slice(&proof_bytes[start..end]);
                        let c: E::G1Affine = {
                            let opt = E::G1Affine::from_bytes(&g1_repr);
                            Option::from(opt).ok_or_else(|| {
                                io::Error::new(io::ErrorKind::InvalidData, "not on curve")
                            })
                        }?;

                        if c.is_identity().into() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "point at infinity",
                            ));
                        }

                        Ok(ProofPart::<E>::C(c))
                    }
                    _ => unreachable!("invalid math {}", c),
                }
            })
            .collect::<io::Result<Vec<_>>>()?;

        let mut proofs = vec![
            Proof::<E> {
                a: <E::G1Affine>::identity(),
                b: <E::G2Affine>::identity(),
                c: <E::G1Affine>::identity(),
            };
            num_proofs
        ];

        for (i, part) in parts.into_iter().enumerate() {
            let c = i / num_proofs;
            let p = i % num_proofs;
            let proof = &mut proofs[p];
            match c {
                0 => {
                    if let ProofPart::B(b) = part {
                        proof.b = b;
                    } else {
                        unreachable!("invalid construction");
                    };
                }
                1 => {
                    if let ProofPart::A(a) = part {
                        proof.a = a;
                    } else {
                        unreachable!("invalid construction");
                    };
                }
                2 => {
                    if let ProofPart::C(c) = part {
                        proof.c = c;
                    } else {
                        unreachable!("invalid construction");
                    };
                }
                _ => unreachable!("invalid math {}", c),
            }
        }

        Ok(proofs)
    }
}

#[derive(Default, Copy, Clone, Debug, Serialize, Deserialize)]
pub struct PoseidonDomain(pub <Fr as PrimeField>::Repr);

impl Domain for PoseidonDomain {
    fn into_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn try_from_bytes(raw: &[u8]) -> anyhow::Result<Self> {
        assert_eq!(
            raw.len(), PoseidonDomain::byte_len(),
            "invalid amount of bytes"
        );
        let mut repr = <Fr as PrimeField>::Repr::default();
        repr.copy_from_slice(raw);
        Ok(PoseidonDomain(repr))
    }

    fn write_bytes(&self, dest: &mut [u8]) -> anyhow::Result<()> {
        assert_eq!(
            dest.len(), PoseidonDomain::byte_len(),
            "invalid amount of bytes"
        );
        dest.copy_from_slice(&self.0);
        Ok(())
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        // generating an Fr and converting it, to ensure we stay in the field
        Fr::random(rng).into()
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize, Hash)]
pub struct Sha256Domain(pub [u8; 32]);

fn read_uncompressed_point<C: UncompressedEncoding>(repr: &C::Uncompressed) -> io::Result<C> {
    let opt = C::from_uncompressed(repr);
    Option::from(opt).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not on curve"))
}

pub fn derive_porep_domain_seed(
    domain_separation_tag: DomainSeparationTag,
    porep_id: [u8; 32],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain_separation_tag.0)
        .chain_update(porep_id)
        .finalize()
        .into()
}

pub struct DomainSeparationTag(&'static str);

pub const DRSAMPLE_DST: DomainSeparationTag = DomainSeparationTag("DRSample");
pub const FEISTEL_DST: DomainSeparationTag = DomainSeparationTag("Feistel");

impl AsRef<PoseidonDomain> for PoseidonDomain {
    fn as_ref(&self) -> &PoseidonDomain {
        self
    }
}

impl StdHash for PoseidonDomain {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        StdHash::hash(&self.0, state);
    }
}

impl PartialEq for PoseidonDomain {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Element for PoseidonDomain {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        match PoseidonDomain::try_from_bytes(bytes) {
            Ok(res) => res,
            Err(err) => panic_any(err),
        }
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.0);
    }
}

impl AsRef<[u8]> for PoseidonDomain {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Fr> for PoseidonDomain {
    #[inline]
    fn from(val: Fr) -> Self {
        PoseidonDomain(val.to_repr())
    }
}

impl From<[u8; 32]> for PoseidonDomain {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        PoseidonDomain(val)
    }
}

impl Ord for PoseidonDomain {
    #[inline(always)]
    fn cmp(&self, other: &PoseidonDomain) -> Ordering {
        (self.0).cmp(&other.0)
    }
}

impl Eq for PoseidonDomain {}

impl PartialOrd for PoseidonDomain {
    #[inline(always)]
    fn partial_cmp(&self, other: &PoseidonDomain) -> Option<Ordering> {
        Some((self.0).cmp(&other.0))
    }
}

impl From<PoseidonDomain> for Fr {
    #[inline]
    fn from(val: PoseidonDomain) -> Self {
        Fr::from_repr_vartime(val.0).expect("from_repr failure")
    }
}

impl Debug for Sha256Domain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Domain({})", hex::encode(&self.0))
    }
}

impl AsRef<Sha256Domain> for Sha256Domain {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Sha256Domain {
    // fn trim_to_fr32(&mut self) {
    //     // strip last two bits, to ensure result is in Fr.
    //     self.0[31] &= 0b0011_1111;
    // }
}

impl AsRef<[u8]> for Sha256Domain {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl From<Sha256Domain> for Fr {
    fn from(val: Sha256Domain) -> Self {
        Fr::from_repr_vartime(val.0).expect("from_repr failure")
    }
}

impl Domain for Sha256Domain {
    fn into_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn try_from_bytes(raw: &[u8]) -> anyhow::Result<Self> {
        assert_eq!(
            raw.len(), Sha256Domain::byte_len(),
            "invalid number of bytes"
        );

        let mut res = Sha256Domain::default();
        res.0.copy_from_slice(&raw[0..Sha256Domain::byte_len()]);
        Ok(res)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> anyhow::Result<()> {
        assert!(
            dest.len() >= Sha256Domain::byte_len(),
            "invalid number of bytes"
        );

        dest[0..Sha256Domain::byte_len()].copy_from_slice(&self.0[..]);
        Ok(())
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        // generating an Fr and converting it, to ensure we stay in the field
        Fr::random(rng).into()
    }
}

impl Element for Sha256Domain {
    fn byte_len() -> usize {
        32
    }

    fn from_slice(bytes: &[u8]) -> Self {
        match Sha256Domain::try_from_bytes(bytes) {
            Ok(res) => res,
            Err(err) => panic_any(err),
        }
    }

    fn copy_to_slice(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.0);
    }
}

impl From<Fr> for Sha256Domain {
    fn from(val: Fr) -> Self {
        Sha256Domain(val.to_repr())
    }
}

impl From<[u8; 32]> for Sha256Domain {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        Sha256Domain(val)
    }
}

pub const BASE_DEGREE: usize = 6;
pub const EXP_DEGREE: usize = 8;

impl<D, G> StackedGraph<D, G>
where
    D: Domain,
    G: Graph<D> + ParameterSetMetadata + Sync + Send,
{
    pub fn new(
        base_graph: Option<G>,
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: PoRepID,
        api_version: ApiVersion,
    ) -> Result<Self, SynthesisError> {
        assert_eq!(base_degree, BASE_DEGREE);
        assert_eq!(expansion_degree, EXP_DEGREE);
        assert!(nodes <= u32::MAX as usize, "too many nodes");

        let base_graph = match base_graph {
            Some(graph) => graph,
            None => G::new(nodes, base_degree, 0, porep_id, api_version)?,
        };

        let bg_id = base_graph.identifier();

        let feistel_keys = derive_feistel_keys(porep_id);

        let res = StackedGraph {
            base_graph,
            id: format!(
                "stacked_graph::StackedGraph{{expansion_degree: {} base_graph: {} }}",
                expansion_degree, bg_id,
            ),
            expansion_degree,
            feistel_keys,
            feistel_precomputed: precompute((expansion_degree * nodes) as Index),
            api_version,
            _d: PhantomData,
        };

        Ok(res)
    }
    /// Assign one parent to `node` using a Chung's construction with a reversible
    /// permutation function from a Feistel cipher (controlled by `invert_permutation`).
    fn correspondent(&self, node: usize, i: usize) -> u32 {
        // We can't just generate random values between `[0, size())`, we need to
        // expand the search space (domain) to accommodate every unique parent assignment
        // generated here. This can be visualized more clearly as a matrix where the each
        // new parent of each new node is assigned a unique `index`:
        //
        //
        //          | Parent 1 | Parent 2 | Parent 3 |
        //
        // | Node 1 |     0    |     1    |     2    |
        //
        // | Node 2 |     3    |     4    |     5    |
        //
        // | Node 3 |     6    |     7    |     8    |
        //
        // | Node 4 |     9    |     A    |     B    |
        //
        // This starting `index` will be shuffled to another position to generate a
        // parent-child relationship, e.g., if generating the parents for the second node,
        // `permute` would be called with values `[3; 4; 5]` that would be mapped to other
        // indexes in the search space of `[0, B]`, say, values `[A; 0; 4]`, that would
        // correspond to nodes numbered `[4; 1, 2]` which will become the parents of the
        // second node. In a later pass invalid parents like 2, self-referencing, and parents
        // with indexes bigger than 2 (if in the `forward` direction, smaller than 2 if the
        // inverse), will be removed.
        let a = (node * self.expansion_degree) as Index + i as Index;

        let transformed = permute(
            self.size() as Index * self.expansion_degree as Index,
            a,
            &self.feistel_keys,
            self.feistel_precomputed,
        );

        match self.api_version {
            ApiVersion::V1_0_0 => transformed as u32 / self.expansion_degree as u32,
            ApiVersion::V1_1_0 => u32::try_from(transformed as u64 / self.expansion_degree as u64)
                .expect("invalid transformation"),
        }

        // Collapse the output in the matrix search space to the row of the corresponding
        // node (losing the column information, that will be regenerated later when calling
        // back this function in the `reversed` direction).
    }

    pub fn generate_expanded_parents(&self, node: usize, expanded_parents: &mut [u32]) {
        debug_assert_eq!(expanded_parents.len(), self.expansion_degree);
        for (i, el) in expanded_parents.iter_mut().enumerate() {
            *el = self.correspondent(node, i);
        }
    }

    pub fn new_stacked(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: PoRepID,
        api_version: ApiVersion,
    ) -> Result<Self, SynthesisError> {
        Self::new(
            None,
            nodes,
            base_degree,
            expansion_degree,
            porep_id,
            api_version,
        )
    }

    pub fn base_graph(&self) -> &G {
        &self.base_graph
    }

    pub fn expansion_degree(&self) -> usize {
        self.expansion_degree
    }

    pub fn base_parents(&self, node: usize, parents: &mut [u32]) -> Result<(), ()> {
        // No cache usage, generate on demand.
        self.base_graph().parents(node, parents)
    }

    /// Assign `self.expansion_degree` parents to `node` using an invertible permutation
    /// that is applied one way for the forward layers and one way for the reversed
    /// ones.
    #[inline]
    pub fn expanded_parents(&self, node: usize, parents: &mut [u32]) -> Result<(), ()> {
        // No cache usage, generate on demand.
        self.generate_expanded_parents(node, parents);
        Ok(())
    }
}

impl<D, G> PartialEq for StackedGraph<D, G>
where
    D: Domain,
    G: Graph<D>,
{
    fn eq(&self, other: &StackedGraph<D, G>) -> bool {
        self.base_graph == other.base_graph && self.expansion_degree == other.expansion_degree
    }
}

impl<D, G> Eq for StackedGraph<D, G>
where
    D: Domain,
    G: Graph<D>,
{
}

pub trait ParameterSetMetadata {
    fn identifier(&self) -> String;
    fn sector_size(&self) -> u64;
}

pub fn permute(
    num_elements: Index,
    index: Index,
    keys: &[Index],
    precomputed: FeistelPrecomputed,
) -> Index {
    let mut u = encode(index, keys, precomputed);

    while u >= num_elements {
        u = encode(u, keys, precomputed)
    }
    // Since we are representing `num_elements` using an even number of bits,
    // that can encode many values above it, so keep repeating the operation
    // until we land in the permitted range.

    u
}

impl<D: Domain> ParameterSetMetadata for BucketGraph<D> {
    fn identifier(&self) -> String {
        // NOTE: Seed is not included because it does not influence parameter generation.
        format!(
            "verifier_drgraph::BucketGraph{{size: {}; degree: {}}}",
            self.nodes,
            self.degree()
        )
    }

    fn sector_size(&self) -> u64 {
        (self.nodes * NODE_SIZE) as u64
    }
}

impl<D: Domain> Clone for PublicParams<D>
{
    fn clone(&self) -> Self {
        Self {
            graph: self.graph.clone(),
            layer_challenges: self.layer_challenges.clone(),
            _d: Default::default(),
        }
    }
}

impl<D: Domain> PublicParams<D>
{
    pub fn new(graph: VerifierStackedBucketGraph<D>, layer_challenges: LayerChallenges) -> Self {
        PublicParams {
            graph,
            layer_challenges,
            _d: PhantomData,
        }
    }
}

impl<D: Domain> ParameterSetMetadata for PublicParams<D>
{
    fn identifier(&self) -> String {
        format!(
            "verifier_layered_drgporep::PublicParams{{ graph: {}, challenges: {:?} }}",
            self.graph.identifier(),
            self.layer_challenges
        )
    }

    fn sector_size(&self) -> u64 {
        self.graph.sector_size()
    }
}

impl<'a, D: Domain> From<&'a PublicParams<D>> for PublicParams<D>
{
    fn from(other: &PublicParams<D>) -> PublicParams<D> {
        PublicParams::new(other.graph.clone(), other.layer_challenges.clone())
    }
}

impl LayerChallenges {
    pub const fn new(layers: usize, max_count: usize) -> Self {
        LayerChallenges { layers, max_count }
    }

    pub fn layers(&self) -> usize {
        self.layers
    }

    pub fn challenges_count_all(&self) -> usize {
        self.max_count
    }

    /// Derive all challenges.
    pub fn derive<D: Domain>(
        &self,
        leaves: usize,
        replica_id: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        self.derive_internal(self.challenges_count_all(), leaves, replica_id, seed, k)
    }
    pub fn derive_internal<D: Domain>(
        &self,
        challenges_count: usize,
        leaves: usize,
        replica_id: &D,
        seed: &[u8; 32],
        k: u8,
    ) -> Vec<usize> {
        assert!(leaves > 2, "Too few leaves: {}", leaves);

        (0..challenges_count)
            .map(|i| {
                let j: u32 = ((challenges_count * k as usize) + i) as u32;

                let hash = Sha256::new()
                    .chain_update(replica_id.into_bytes())
                    .chain_update(seed)
                    .chain_update(&j.to_le_bytes())
                    .finalize();

                let big_challenge = BigUint::from_bytes_le(hash.as_ref());

                // We cannot try to prove the first node, so make sure the challenge
                // can never be 0.
                let big_mod_challenge = big_challenge % (leaves - 1);
                let big_mod_challenge = big_mod_challenge
                    .to_usize()
                    .expect("`big_mod_challenge` exceeds size of `usize`");
                big_mod_challenge + 1
            })
            .collect()
    }
}

impl<D, G> Graph<D> for StackedGraph<D, G>
where
    D: Domain,
    G: Graph<D> + ParameterSetMetadata + Sync + Send,
{
    type Key = Vec<u8>;

    fn size(&self) -> usize {
        self.base_graph().size()
    }

    fn degree(&self) -> usize {
        self.base_graph.degree() + self.expansion_degree
    }

    #[inline]
    fn parents(&self, node: usize, parents: &mut [u32]) -> Result<(), ()> {
        self.base_parents(node, &mut parents[..self.base_graph().degree()])?;

        // expanded_parents takes raw_node
        self.expanded_parents(
            node,
            &mut parents
                [self.base_graph().degree()..self.base_graph().degree() + self.expansion_degree()],
        )?;

        Ok(())
    }

    fn seed(&self) -> [u8; 28] {
        self.base_graph().seed()
    }

    fn new(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: PoRepID,
        api_version: ApiVersion,
    ) -> Result<Self, SynthesisError> {
        Self::new_stacked(nodes, base_degree, expansion_degree, porep_id, api_version)
    }

    fn create_key(
        &self,
        _id: &D,
        _node: usize,
        _parents: &[u32],
        _base_parents_data: &[u8],
        _exp_parents_data: Option<&[u8]>,
    ) -> Result<Self::Key, SynthesisError> {
        unimplemented!("not used");
    }
}

fn encode(index: Index, keys: &[Index], precomputed: FeistelPrecomputed) -> Index {
    let (mut left, mut right, right_mask, half_bits) = common_setup(index, precomputed);

    for key in keys.iter().take(FEISTEL_ROUNDS) {
        let (l, r) = (right, left ^ feistel(right, *key, right_mask));
        left = l;
        right = r;
    }

    (left << half_bits) | right
}

fn common_setup(index: Index, precomputed: FeistelPrecomputed) -> (Index, Index, Index, Index) {
    let (left_mask, right_mask, half_bits) = precomputed;

    let left = (index & left_mask) >> half_bits;
    let right = index & right_mask;

    (left, right, right_mask, half_bits)
}

pub const FEISTEL_ROUNDS: usize = 3;

impl<T: Domain, S: Domain> PublicInputs<T, S> {
    pub fn challenges(
        &self,
        layer_challenges: &LayerChallenges,
        leaves: usize,
        partition_k: Option<usize>,
    ) -> Vec<usize> {
        let k = partition_k.unwrap_or(0);

        layer_challenges.derive::<T>(leaves, &self.replica_id, &self.seed, k as u8)
    }
}

pub fn derive_feistel_keys(porep_id: PoRepID) -> [u64; 4] {
    let mut feistel_keys = [0u64; 4];
    let raw_seed = derive_porep_domain_seed(FEISTEL_DST, porep_id);
    feistel_keys[0] = u64::from_le_bytes(raw_seed[0..8].try_into().expect("from_le_bytes failure"));
    feistel_keys[1] =
        u64::from_le_bytes(raw_seed[8..16].try_into().expect("from_le_bytes failure"));
    feistel_keys[2] =
        u64::from_le_bytes(raw_seed[16..24].try_into().expect("from_le_bytes failure"));
    feistel_keys[3] =
        u64::from_le_bytes(raw_seed[24..32].try_into().expect("from_le_bytes failure"));
    feistel_keys
}

pub fn precompute(num_elements: Index) -> FeistelPrecomputed {
    let mut next_pow4: Index = 4;
    let mut log4 = 1;
    while next_pow4 < num_elements {
        next_pow4 *= 4;
        log4 += 1;
    }

    let left_mask = ((1 << log4) - 1) << log4;
    let right_mask = (1 << log4) - 1;
    let half_bits = log4;

    (left_mask, right_mask, half_bits)
}

impl<D, G> ParameterSetMetadata for StackedGraph<D, G>
where
    D: Domain,
    G: Graph<D> + ParameterSetMetadata,
{
    fn identifier(&self) -> String {
        self.id.clone()
    }

    fn sector_size(&self) -> u64 {
        self.base_graph.sector_size()
    }
}

const HALF_FEISTEL_BYTES: usize = size_of::<Index>();
const FEISTEL_BYTES: usize = 2 * HALF_FEISTEL_BYTES;

fn feistel(right: Index, key: Index, right_mask: Index) -> Index {
    let mut data: [u8; FEISTEL_BYTES] = [0; FEISTEL_BYTES];

    // So ugly, but the price of (relative) speed.
    let r = if FEISTEL_BYTES <= 8 {
        data[0] = (right >> 24) as u8;
        data[1] = (right >> 16) as u8;
        data[2] = (right >> 8) as u8;
        data[3] = right as u8;

        data[4] = (key >> 24) as u8;
        data[5] = (key >> 16) as u8;
        data[6] = (key >> 8) as u8;
        data[7] = key as u8;

        let raw = blake2b(&data);
        let hash = raw.as_bytes();

        Index::from(hash[0]) << 24
            | Index::from(hash[1]) << 16
            | Index::from(hash[2]) << 8
            | Index::from(hash[3])
    } else {
        data[0] = (right >> 56) as u8;
        data[1] = (right >> 48) as u8;
        data[2] = (right >> 40) as u8;
        data[3] = (right >> 32) as u8;
        data[4] = (right >> 24) as u8;
        data[5] = (right >> 16) as u8;
        data[6] = (right >> 8) as u8;
        data[7] = right as u8;

        data[8] = (key >> 56) as u8;
        data[9] = (key >> 48) as u8;
        data[10] = (key >> 40) as u8;
        data[11] = (key >> 32) as u8;
        data[12] = (key >> 24) as u8;
        data[13] = (key >> 16) as u8;
        data[14] = (key >> 8) as u8;
        data[15] = key as u8;

        let raw = blake2b(&data);
        let hash = raw.as_bytes();

        Index::from(hash[0]) << 56
            | Index::from(hash[1]) << 48
            | Index::from(hash[2]) << 40
            | Index::from(hash[3]) << 32
            | Index::from(hash[4]) << 24
            | Index::from(hash[5]) << 16
            | Index::from(hash[6]) << 8
            | Index::from(hash[7])
    };

    r & right_mask
}