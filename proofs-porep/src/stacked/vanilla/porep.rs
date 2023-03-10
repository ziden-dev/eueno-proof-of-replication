use std::path::PathBuf;

use hashers::Hasher;
use merkletree::store::StoreConfig;
use proofs_core::{
    error::Result,
    merkle::{BinaryMerkleTree, MerkleTreeTrait},
    Data,
};

use crate::{
    stacked::vanilla::{
        params::{PersistentAux, PublicParams, Tau, TemporaryAux},
        proof::StackedDrg,
    },
    PoRep,
};

impl<'a, Tree: 'static + MerkleTreeTrait, G: 'static + Hasher> PoRep<'a, Tree::Hasher, G>
    for StackedDrg<'a, Tree, G>
{
    type Tau = Tau<<Tree::Hasher as Hasher>::Domain, <G as Hasher>::Domain>;
    type ProverAux = (
        PersistentAux<<Tree::Hasher as Hasher>::Domain>,
        TemporaryAux<Tree, G>,
    );

    fn replicate(
        pp: &'a PublicParams<Tree>,
        replica_id: &<Tree::Hasher as Hasher>::Domain,
        data: Data<'a>,
        data_tree: Option<BinaryMerkleTree<G>>,
        config: StoreConfig,
        replica_path: PathBuf,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let (tau, p_aux, t_aux) = Self::transform_and_replicate_layers(
            &pp.graph,
            &pp.layer_challenges,
            replica_id,
            data,
            data_tree,
            config,
            replica_path,
        )?;

        Ok((tau, (p_aux, t_aux)))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams<Tree>,
        replica_id: &'b <Tree::Hasher as Hasher>::Domain,
        data: &'b mut [u8],
        config: Option<StoreConfig>,
    ) -> Result<()> {
        Self::extract_and_invert_transform_layers(
            &pp.graph,
            &pp.layer_challenges,
            replica_id,
            data,
            config.expect("Missing store config"),
        )?;

        Ok(())
    }

    fn extract(
        _pp: &PublicParams<Tree>,
        _replica_id: &<Tree::Hasher as Hasher>::Domain,
        _data: &mut [u8],
        _node: usize,
        _config: Option<StoreConfig>,
    ) -> Result<()> {
        unimplemented!();
    }
}
