use std::marker::PhantomData;
use crate::{
    utils::ApiVersion,
    domain::Domain
};
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

use super::challenges::LayerChallenges;

use super::verifier_graph::VerifierStackedBucketGraph;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, JsonSchema)]
pub struct SetupParams {
    // Number of nodes
    pub nodes: u64,

    // Base degree of DRG
    pub degree: u64,

    pub expansion_degree: u64,

    pub porep_id: [u8; 32],
    pub layer_challenges: LayerChallenges,
    pub api_version: ApiVersion,
}

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

impl<'a, D: Domain> From<&'a PublicParams<D>> for PublicParams<D>
{
    fn from(other: &PublicParams<D>) -> PublicParams<D> {
        PublicParams::new(other.graph.clone(), other.layer_challenges.clone())
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema, Debug)]
pub struct PublicInputs<T: Domain, S: Domain> {
    #[serde(bound = "")]
    pub replica_id: T,
    pub seed: [u8; 32],
    #[serde(bound = "")]
    pub tau: Option<Tau<T, S>>,
    /// Partition index
    pub k: Option<u64>,
}

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

/// Tau for a single parition.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Debug)]
pub struct Tau<D: Domain, E: Domain> {
    #[serde(bound = "")]
    pub comm_d: E,
    #[serde(bound = "")]
    pub comm_r: D,
}