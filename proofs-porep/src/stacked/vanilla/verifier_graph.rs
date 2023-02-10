use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

use anyhow::ensure;
use hashers::Domain;
use proofs_core::{
    api_version::ApiVersion,
    crypto::{
        derive_porep_domain_seed,
        feistel::{self, FeistelPrecomputed},
        FEISTEL_DST,
    },
    verifier_drgraph::{BucketGraph, Graph, BASE_DEGREE},
    error::Result,
    parameter_cache::ParameterSetMetadata,
    PoRepID,
};

/// The expansion degree used for Stacked Graphs.
pub const EXP_DEGREE: usize = 8;

#[derive(Clone)]
pub struct StackedGraph<D, G>
where
    D: Domain,
    G: Graph<D> + 'static,
{
    expansion_degree: usize,
    base_graph: G,
    pub(crate) feistel_keys: [feistel::Index; 4],
    feistel_precomputed: FeistelPrecomputed,
    api_version: ApiVersion,
    id: String,
    _d: PhantomData<D>,
}

impl<D, G> Debug for StackedGraph<D, G>
where
    D: Domain,
    G: Graph<D> + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StackedGraph")
            .field("expansion_degree", &self.expansion_degree)
            .field("base_graph", &self.base_graph)
            .field("feistel_precomputed", &self.feistel_precomputed)
            .field("id", &self.id)
            .finish()
    }
}

pub type VerifierStackedBucketGraph<D> = StackedGraph<D, BucketGraph<D>>;

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
    ) -> Result<Self> {
        assert_eq!(base_degree, BASE_DEGREE);
        assert_eq!(expansion_degree, EXP_DEGREE);
        ensure!(nodes <= u32::MAX as usize, "too many nodes");

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
            feistel_precomputed: feistel::precompute((expansion_degree * nodes) as feistel::Index),
            api_version,
            _d: PhantomData,
        };

        Ok(res)
    }
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
    fn parents(&self, node: usize, parents: &mut [u32]) -> Result<()> {
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
    ) -> Result<Self> {
        Self::new_stacked(nodes, base_degree, expansion_degree, porep_id, api_version)
    }

    fn create_key(
        &self,
        _id: &D,
        _node: usize,
        _parents: &[u32],
        _base_parents_data: &[u8],
        _exp_parents_data: Option<&[u8]>,
    ) -> Result<Self::Key> {
        unimplemented!("not used");
    }
}

impl<D, G> StackedGraph<D, G>
where
    D: Domain,
    G: Graph<D> + ParameterSetMetadata + Sync + Send,
{
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
        let a = (node * self.expansion_degree) as feistel::Index + i as feistel::Index;

        let transformed = feistel::permute(
            self.size() as feistel::Index * self.expansion_degree as feistel::Index,
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
    ) -> Result<Self> {
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

    pub fn base_parents(&self, node: usize, parents: &mut [u32]) -> Result<()> {
        // No cache usage, generate on demand.
        self.base_graph().parents(node, parents)
    }

    /// Assign `self.expansion_degree` parents to `node` using an invertible permutation
    /// that is applied one way for the forward layers and one way for the reversed
    /// ones.
    #[inline]
    pub fn expanded_parents(&self, node: usize, parents: &mut [u32]) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    use hashers::poseidon::PoseidonDomain;

    // Test that 3 (or more) rounds of the Feistel cipher can be used
    // as a pseudorandom permutation, that is, each input will be mapped
    // to a unique output (and though not test here, since the cipher
    // is symmetric, the decryption rounds also work as the inverse
    // permutation), for more details see:
    // https://en.wikipedia.org/wiki/Feistel_cipher#Theoretical_work.
    #[test]
    fn test_shuffle() {
        let n = 2_u64.pow(10);
        let d = EXP_DEGREE as u64;
        // Use a relatively small value of `n` as Feistel is expensive (but big
        // enough that `n >> d`).

        let mut shuffled: HashSet<u64> = HashSet::with_capacity((n * d) as usize);

        let feistel_keys = &[1, 2, 3, 4];
        let feistel_precomputed = feistel::precompute((n * d) as feistel::Index);

        for i in 0..n {
            for k in 0..d {
                let permuted =
                    feistel::permute(n * d, i * d + k, feistel_keys, feistel_precomputed);

                // Since the permutation implies a one-to-one correspondence,
                // traversing the entire input space should generate the entire
                // output space (in `shuffled`) without repetitions (since a duplicate
                // output would imply there is another output that wasn't generated
                // and the permutation would be incomplete).
                assert!(shuffled.insert(permuted));
            }
        }

        // Actually implied by the previous `assert!` this is left in place as an
        // extra safety check that indeed the permutation preserved all the output
        // space (of `n * d` nodes) without repetitions (which the `HashSet` would
        // have skipped as duplicates).
        assert_eq!(shuffled.len(), (n * d) as usize);
    }

    #[test]
    /// The initial implementation had a bug which prevented parents from ever falling in the later half of a sector.
    /// In fact, it is even worse than that, in the case of 64GiB sectors.
    /// This test demonstrates conclusively that non-legacy graphs do not suffer from this pathology.
    /// It also suggests, inconclusively, that legacy graphds do suffer from it (which we already know).
    fn test_graph_distribution_pathology() {
        let sector32_nodes: u32 = 1 << 30;
        let sector64_nodes: u32 = 1 << 31;

        let porep_id = |id: u8| {
            let mut porep_id = [0u8; 32];
            porep_id[0] = id;

            porep_id
        };

        test_pathology_aux(porep_id(3), sector32_nodes, ApiVersion::V1_0_0);
        test_pathology_aux(porep_id(4), sector64_nodes, ApiVersion::V1_0_0);

        test_pathology_aux(porep_id(8), sector32_nodes, ApiVersion::V1_1_0);
        test_pathology_aux(porep_id(9), sector64_nodes, ApiVersion::V1_1_0);
    }

    fn test_pathology_aux(porep_id: PoRepID, nodes: u32, api_version: ApiVersion) {
        // In point of fact, the concrete graphs expected to be non-pathological
        // appear to demonstrate this immediately (i.e. in the first node). We
        // test more than that just to make the tentative diagnosis of pathology
        // more convincing in the cases where we expect it. In the interest of
        // keeping the tests brief, we keep this fairly small, though, since we
        // already know the previous porep_ids exhibit the problem. The main
        // reason to test those cases at all is to convince ourselves the test
        // is sound.
        let test_n = 1_000;

        let expect_pathological = match api_version {
            ApiVersion::V1_0_0 => true,
            ApiVersion::V1_1_0 => false,
        };

        let graph = VerifierStackedBucketGraph::<PoseidonDomain>::new_stacked(
            nodes as usize,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
            api_version,
        )
        .expect("stacked bucket graph new_stacked failed");

        // If a parent index is not less than half the total node count, then
        // the parent falls in the second half of the previous layer. By the
        // definition of 'pathology' used here, that means the graph producing
        // this parent is not pathological.
        let demonstrably_large_enough = |p: &u32| *p >= (nodes / 2);

        dbg!(&porep_id, &nodes, &expect_pathological);
        for i in 0..test_n {
            let mut expanded_parents = [0u32; EXP_DEGREE];
            graph
                .expanded_parents(i, &mut expanded_parents)
                .expect("expanded_parents");

            if expect_pathological {
                // If we ever see a large-enough parent, then this graph is not
                // pathological, so the test fails.
                assert!(
                    !expanded_parents.iter().any(demonstrably_large_enough),
                    "Expected pathological graph but found large-enough parent."
                );
            } else if expanded_parents.iter().any(demonstrably_large_enough) {
                // If we ever see a large-enough parent, then this graph is
                // not pathological, and the test succeeds. This is the only
                // way for a test expecting a non-pathological graph to
                // succeed, so there is no risk of false negatives (i.e.
                // failure to identify pathological graphs when unexpected).
                return;
            }
        }

        // If we get here, we did not observe a parent large enough to conclude
        // that the graph is not pathological. In that case, the test fails if we
        // expected a non-pathological graph and succeeds otherwise. NOTE: this
        // could lead us to conclude that an actually non-pathological graph is
        // pathological, if `test_n` is set too low. Since the primary purpose
        // of this test is to assure us that newer graphs are not pathological,
        // it suffices to set `test_n` high enough to detect that.
        assert!(expect_pathological, "Did not expect pathological graph, but did not see large-enough parent to prove otherwise.");
    }

    // Tests that the set of expander edges has not been truncated.
    #[test]
    fn test_high_parent_bits() {
        // 64GiB sectors have 2^31 nodes.
        const N_NODES: usize = 1 << 31;

        // `u32` truncation would reduce the expander edge bit-length from 34 bits to 32 bits, thus
        // the first parent truncated would be the node at index `2^32 / EXP_DEGREE = 2^29`.
        const FIRST_TRUNCATED_PARENT: u32 = 1 << 29;

        // The number of child nodes to test before failing. This value was chosen arbitrarily and
        // can be changed.
        const N_CHILDREN_SAMPLED: usize = 3;

        // Non-legacy porep-id.
        let mut porep_id = [0u8; 32];
        porep_id[..8].copy_from_slice(&5u64.to_le_bytes());

        let graph = VerifierStackedBucketGraph::<PoseidonDomain>::new_stacked(
            N_NODES,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
            ApiVersion::V1_1_0,
        )
        .expect("stacked bucket graph new_stacked");

        let mut exp_parents = [0u32; EXP_DEGREE];
        for v in 0..N_CHILDREN_SAMPLED {
            graph
                .expanded_parents(v, &mut exp_parents[..])
                .expect("expanded_parents");
            if exp_parents.iter().any(|u| *u >= FIRST_TRUNCATED_PARENT) {
                return;
            }
        }
        panic!();
    }

    // Checks that the distribution of parent node indexes within a sector is within a set bound.
    #[test]
    fn test_exp_parent_histogram() {
        // 64GiB sectors have 2^31 nodes.
        const N_NODES: usize = 1 << 31;

        // The number of children used to construct the histogram. This value is chosen
        // arbitrarily and can be changed.
        const N_CHILDREN_SAMPLED: usize = 10000;

        // The number of bins used to partition the set of sector nodes. This value was chosen
        // arbitrarily and can be changed to any integer that is a multiple of `EXP_DEGREE` and
        // evenly divides `N_NODES`.
        const N_BINS: usize = 32;
        const N_NODES_PER_BIN: u32 = (N_NODES / N_BINS) as u32;
        const PARENT_COUNT_PER_BIN_UNIFORM: usize = N_CHILDREN_SAMPLED * EXP_DEGREE / N_BINS;

        // This test will pass if every bin's parent count is within the bounds:
        // `(1 +/- FAILURE_THRESHOLD) * PARENT_COUNT_PER_BIN_UNIFORM`.
        const FAILURE_THRESHOLD: f32 = 0.4;
        const MAX_PARENT_COUNT_ALLOWED: usize =
            ((1.0 + FAILURE_THRESHOLD) * PARENT_COUNT_PER_BIN_UNIFORM as f32) as usize - 1;
        const MIN_PARENT_COUNT_ALLOWED: usize =
            ((1.0 - FAILURE_THRESHOLD) * PARENT_COUNT_PER_BIN_UNIFORM as f32) as usize + 1;

        // Non-legacy porep-id.
        let mut porep_id = [0u8; 32];
        porep_id[..8].copy_from_slice(&5u64.to_le_bytes());

        let graph = VerifierStackedBucketGraph::<PoseidonDomain>::new_stacked(
            N_NODES,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
            ApiVersion::V1_1_0,
        )
        .expect("stacked bucket graph new_stacked failed");

        // Count the number of parents in each bin.
        let mut hist = [0usize; N_BINS];
        let mut exp_parents = [0u32; EXP_DEGREE];
        for sample_index in 0..N_CHILDREN_SAMPLED {
            let v = sample_index * N_NODES / N_CHILDREN_SAMPLED;
            graph
                .expanded_parents(v, &mut exp_parents[..])
                .expect("expanded_parents failed");
            for u in exp_parents.iter() {
                let bin_index = (u / N_NODES_PER_BIN) as usize;
                hist[bin_index] += 1;
            }
        }

        let success = hist.iter().all(|&n_parents| {
            (MIN_PARENT_COUNT_ALLOWED..=MAX_PARENT_COUNT_ALLOWED).contains(&n_parents)
        });

        assert!(success);
    }
}
