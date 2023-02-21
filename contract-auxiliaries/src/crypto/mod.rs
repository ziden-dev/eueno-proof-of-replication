use sha2::{Digest, Sha256};

pub mod feistel;

pub struct DomainSeparationTag(&'static str);

pub const DRSAMPLE_DST: DomainSeparationTag = DomainSeparationTag("DRSample");
pub const FEISTEL_DST: DomainSeparationTag = DomainSeparationTag("Feistel");

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
