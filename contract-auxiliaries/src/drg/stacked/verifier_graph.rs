use std::convert::{TryFrom, TryInto};
use std::marker::PhantomData;

use anyhow::{ensure, Result};
use crate::{
    domain::Domain,
    utils::ApiVersion,
    crypto::{
        derive_porep_domain_seed,
        feistel::{self, FeistelPrecomputed},
        FEISTEL_DST,
    },
    drg::drgraph::{BucketGraph, Graph, BASE_DEGREE},
    PoRepID
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
    _d: PhantomData<D>,
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
    G: Graph<D> + Sync + Send,
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

        let feistel_keys = derive_feistel_keys(porep_id);

        let res = StackedGraph {
            base_graph,
            expansion_degree,
            feistel_keys,
            feistel_precomputed: feistel::precompute((expansion_degree * nodes) as feistel::Index),
            api_version,
            _d: PhantomData,
        };

        Ok(res)
    }
}

impl<D, G> Graph<D> for StackedGraph<D, G>
where
    D: Domain,
    G: Graph<D> + Sync + Send,
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
    G: Graph<D> + Sync + Send,
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