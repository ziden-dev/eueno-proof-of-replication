
use std::fmt::Debug;

use ark_bls12_381::Fr;
use serde::{Serialize, de::DeserializeOwned};
pub mod sha256;
pub mod poseidon;

pub trait Element: Ord + Clone + AsRef<[u8]> + Sync + Send + Default {
    /// Returns the length of an element when serialized as a byte slice.
    fn byte_len() -> usize;

    /// Creates the element from its byte form. Panics if the slice is not appropriately sized.
    fn from_slice(bytes: &[u8]) -> Self;

    fn copy_to_slice(&self, bytes: &mut [u8]);
}

pub trait Domain:
    Ord
    + Copy
    + Clone
    + AsRef<[u8]>
    + Default
    + Eq
    + Send
    + Sync
    + From<Fr>
    + Into<Fr>
    + Serialize
    + DeserializeOwned
    + Element
    + Debug
{
    #[allow(clippy::wrong_self_convention)]
    fn into_bytes(&self) -> Vec<u8>;
    fn try_from_bytes(raw: &[u8]) -> anyhow::Result<Self>;
    /// Write itself into the given slice, LittleEndian bytes.
    fn write_bytes(&self, _: &mut [u8]) -> anyhow::Result<()>;
}