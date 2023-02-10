use std::marker::PhantomData;
use hashers::Domain;
use proofs_core::{
    api_version::ApiVersion,
    parameter_cache::ParameterSetMetadata
};

use crate::stacked::vanilla::LayerChallenges;

use super::verifier_graph::VerifierStackedBucketGraph;

#[derive(Debug, Clone)]
pub struct SetupParams {
    // Number of nodes
    pub nodes: usize,

    // Base degree of DRG
    pub degree: usize,

    pub expansion_degree: usize,

    pub porep_id: [u8; 32],
    pub layer_challenges: LayerChallenges,
    pub api_version: ApiVersion,
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