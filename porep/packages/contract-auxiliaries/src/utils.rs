use serde::Deserialize;

#[derive(Copy, Clone, Eq, PartialEq, Deserialize)]
pub enum ApiVersion {
    V1_0_0,
    V1_1_0,
}

pub const NODE_SIZE: usize = 32;

/// Returns the start position of the data, 0-indexed.
pub fn data_at_node_offset(v: usize) -> usize {
    v * NODE_SIZE
}