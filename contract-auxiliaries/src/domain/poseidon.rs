use std::{panic::panic_any, cmp::Ordering};

use anyhow::ensure;
use ark_bls12_381::Fr;
use ark_ff::{PrimeField, BigInteger};
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

use super::{Domain, Element};


#[derive(Default, Copy, Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PoseidonDomain(pub [u8; 32]);

impl AsRef<PoseidonDomain> for PoseidonDomain {
    fn as_ref(&self) -> &PoseidonDomain {
        self
    }
}

impl PartialEq for PoseidonDomain {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for PoseidonDomain {}

impl Ord for PoseidonDomain {
    #[inline(always)]
    fn cmp(&self, other: &PoseidonDomain) -> Ordering {
        (self.0).cmp(&other.0)
    }
}

impl PartialOrd for PoseidonDomain {
    #[inline(always)]
    fn partial_cmp(&self, other: &PoseidonDomain) -> Option<Ordering> {
        Some((self.0).cmp(&other.0))
    }
}

impl AsRef<[u8]> for PoseidonDomain {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Domain for PoseidonDomain {
    fn into_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn try_from_bytes(raw: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            raw.len() == PoseidonDomain::byte_len(),
            "invalid number of bytes"
        );

        let mut res = PoseidonDomain::default();
        res.0.copy_from_slice(&raw[0..PoseidonDomain::byte_len()]);
        Ok(res)
    }

    fn write_bytes(&self, dest: &mut [u8]) -> anyhow::Result<()> {
        ensure!(
            dest.len() >= PoseidonDomain::byte_len(),
            "invalid number of bytes"
        );

        dest[0..PoseidonDomain::byte_len()].copy_from_slice(&self.0[..]);
        Ok(())
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

impl From<Fr> for PoseidonDomain {
    #[inline]
    fn from(val: Fr) -> Self {
        let le: [u8; 32] = val.into_repr().to_bytes_le().as_slice().try_into().unwrap();
        PoseidonDomain(le)
    }
}

impl From<[u8; 32]> for PoseidonDomain {
    #[inline]
    fn from(val: [u8; 32]) -> Self {
        PoseidonDomain(val)
    }
}

impl From<PoseidonDomain> for Fr {
    #[inline]
    fn from(val: PoseidonDomain) -> Self {
        Fr::from_le_bytes_mod_order(&val.0)
    }
}
