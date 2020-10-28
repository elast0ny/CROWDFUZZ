use crate::*;

use ::rand::rngs::SmallRng;
use ::rand::Rng;

pub struct HavocState {
    weight: usize,
    num_iterations: usize,
    /// fast/non-crypto grade random
    rng: SmallRng,
}
impl HavocState {
    pub fn new(rng: SmallRng) -> Self {
        let mut r = Self {
            weight: 1,
            num_iterations: 0,
            rng,
        };
        r.reset();
        r
    }

    pub fn desc(&self, dst: &mut String) {
        use std::fmt::Write;
        dst.push_str("havoc ");
        let _ = write!(dst, "{}", self.num_iterations);
    }

    pub fn reset(&mut self) {
        // Recalculate number of iterations based on weight
        self.num_iterations = self.weight
            * self.rng.gen_range(
                1,
                if self.num_iterations == 0 {
                    HAVOC_CYCLES_INIT
                } else {
                    HAVOC_CYCLES
                } as usize,
            );
    }
}

pub fn havoc(_bytes: &mut [u8], _s: &mut HavocState) -> StageResult {
    StageResult::CantRestoreInput
}
