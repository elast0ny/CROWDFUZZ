use crate::*;

use ::rand::rngs::SmallRng;
use ::rand::Rng;

pub struct HavocState {
    /// fast/non-crypto grade random
    rng: SmallRng,
}
impl HavocState {
    pub fn from_rng(rng: SmallRng) -> Self {
        Self { rng }
    }
}

pub fn havoc(bytes: &mut [u8], s: &mut HavocState) -> (bool, bool) {
    (true, true)
}
