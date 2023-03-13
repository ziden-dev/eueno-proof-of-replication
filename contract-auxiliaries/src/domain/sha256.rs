use std::panic::panic_any;

use anyhow::ensure;
use ark_bls12_381::Fr;
use ark_ff::{PrimeField, BigInteger};
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

use super::{Domain, Element};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize, JsonSchema, Debug)]
pub struct Sha256Domain(pub [u8; 32]);

impl AsRef<Sha256Domain> for Sha256Domain {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<[u8]> for Sha256Domain {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl From<Fr> for Sha256Domain {
    fn from(val: Fr) -> Self {
        let le: [u8; 32] = val.into_repr().to_bytes_le().as_slice().try_into().unwrap();
        Sha256Domain(le)
    }
}

impl From<Sha256Domain> for Fr {
    fn from(val: Sha256Domain) -> Self {
        Fr::from_le_bytes_mod_order(&val.0)
    }
}


impl Domain for Sha256Domain {
    fn into_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn try_from_bytes(raw: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            raw.len() == Sha256Domain::byte_len(),
            "invalid number of bytes"
        );

        let mut res = Sha256Domain::default();
        res.0.copy_from_slice(&raw[0..Sha256Domain::byte_len()]);
        Ok(res)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> anyhow::Result<()> {
        ensure!(
            dest.len() >= Sha256Domain::byte_len(),
            "invalid number of bytes"
        );

        dest[0..Sha256Domain::byte_len()].copy_from_slice(&self.0[..]);
        Ok(())
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

impl From<[u8; 32]> for Sha256Domain {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        Sha256Domain(val)
    }
}

impl From<Sha256Domain> for [u8; 32] {
    #[inline]
    fn from(val: Sha256Domain) -> Self {
        val.0
    }
}
