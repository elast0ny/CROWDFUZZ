use crate::*;

pub enum InnerStage<T> {
    Updated,
    Next(T),
    Done,
}

pub enum StageResult {
    /// Mutated input and will restore on next iteration
    WillRestoreInput,
    /// Mutated input and will not restore on next iteration
    CantRestoreInput,
    /// Current stage updated itself and has not mutated the input
    Update,
    /// Stage is done and has not mutated the input
    Done,
}

#[derive(Debug)]
pub enum MutatorStage {
    /// Flips groups of bits [1,2,4,8,16,32]
    BitFlip(BitFlipState),
    /// Perform arithmetic operations [8,16,32]
    Arithmetic(ArithState),
    /// Insert interesting values [8,16,32]
    Interesting(InterestState),
    /*
    /// Use user provided values
    UserExtra,
    /// Automaticaly found values
    AutoExtra,
    */
    /// Do anything
    Havoc(HavocState),
}
impl Default for MutatorStage {
    fn default() -> Self {
        // Just pick a random state
        Self::BitFlip(BitFlipState::new(&CfInput::default()))
    }
}
impl MutatorStage {
    pub fn sync_to_input(
        &mut self,
        q: &mut AflQueueEntry,
        afl: &AflGlobals,
        input: &mut CfInput,
    ) -> &mut Self {
        if afl.skip_deterministic || q.passed_det {
            if let Self::Havoc(ref mut s) = self {
                s.reset(q, afl);
            } else {
                *self = Self::Havoc(HavocState::new(q, afl));
            }
        } else {
            // Input is not done deterministic, start from beginning
            *self = Self::BitFlip(BitFlipState::new(input));
        }
        self
    }
    
    /// Progress to the next mutator
    pub fn next(&mut self, q: &mut AflQueueEntry, afl: &AflGlobals, input: &[u8]) -> bool {
        match self {
            Self::Havoc(_) => false,
            Self::BitFlip(_) => {
                *self = Self::Arithmetic(ArithState::new(input));
                true
            }
            Self::Arithmetic(_) => {
                *self = Self::Interesting(InterestState::new(input));
                true
            }
            Self::Interesting(_) => {
                *self = Self::Havoc(HavocState::new(q, afl));
                true
            }
        }
    }

    pub fn mutate(&mut self, input: &mut CfInput) -> StageResult {
        match self {
            Self::Havoc(s) => s.mutate(input),
            Self::BitFlip(s) => s.mutate(input),
            Self::Arithmetic(s) => s.mutate(input),
            Self::Interesting(s) => s.mutate(input),
        }
    }

    pub fn update_state(&self, input: &[u8], name: Option<&mut String>, total_cycles: Option<&mut u64>) {
        match self {
            Self::Havoc(s) => {
                if let Some(n) = name {
                    s.desc(n);
                }
                if let Some(c) = total_cycles {
                    *c = s.total_cycles() as _;
                }
            },
            Self::BitFlip(s) => {
                if let Some(n) = name {
                    s.desc(n);
                }
                if let Some(c) = total_cycles {
                    *c = s.total_cycles(input) as _;
                }
            },
            Self::Arithmetic(s) => {
                if let Some(n) = name {
                    s.desc(n);
                }
                if let Some(c) = total_cycles {
                    *c = s.total_cycles(input) as _;
                }
            },
            Self::Interesting(s) => {
                if let Some(n) = name {
                    s.desc(n);
                }
                if let Some(c) = total_cycles {
                    *c = s.total_cycles(input) as _;
                }
            },
        }
    }
}

/* Common helper functions for mutators */

pub fn swap_16(v: u16) -> u16 {
    (v << 8) | (v >> 8)
}

pub fn swap_32(v: u32) -> u32 {
    (v << 24) | (v >> 24) | ((v << 8) & 0x00FF0000) | ((v >> 8) & 0x0000FF00)
}
