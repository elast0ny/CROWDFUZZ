use crate::*;

fn max_idx(width: u8, input_len: usize) -> usize {
    if input_len == 0 {
        return 0;
    }

    if width < 8 {
        (input_len * 8) - ((width) - 1) as usize
    } else {
        let delta = ((width / 8) - 1) as usize;
        if delta > input_len {
            0
        } else {
            input_len - delta
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BitFlipState {
    idx: usize,
    restore_val: bool,
    width: u8,
}
impl BitFlipState {
    pub fn new(input: &[u8]) -> Self {
        Self {
            idx: max_idx(1, input.len()),
            restore_val: false,
            width: 1,
        }
    }
    pub fn desc(&self, dst: &mut String) {
        dst.push_str("bitflip ");
        dst.push_str(match self.width {
            1 => "1/1",
            2 => "2/1",
            4 => "4/1",
            8 => "8/8",
            16 => "16/8",
            _ => "32/2",
        });
    }
    pub fn total_cycles(&self, input: &[u8]) -> usize {
        let mut total = 0;
        let mut i = 1;
        loop {
            total += max_idx(i, input.len());
            i *= 2;
            if i > 32 {
                break;
            }
        }
        total
    }

    /// Flips bits in the input starting from the end
    pub fn mutate(&mut self, mut input: &mut [u8]) -> StageResult {
        // Restore the orig input
        if self.restore_val {
            self.restore_val = false;
            unsafe {
                match self.width {
                    1 => {
                        input.flip_bit(self.idx);
                    }
                    2 => {
                        input.flip_bit(self.idx);
                        input.flip_bit(self.idx + 1);
                    }
                    4 => {
                        input.flip_bit(self.idx);
                        input.flip_bit(self.idx + 1);
                        input.flip_bit(self.idx + 2);
                        input.flip_bit(self.idx + 3);
                    }
                    8 => {
                        input.flip_byte(self.idx);
                    }
                    16 => {
                        input.flip_word(self.idx);
                    }
                    _ => {
                        input.flip_dword(self.idx);
                    }
                }
            }
        }

        if self.idx == 0 {
            if self.width >= 32 {
                return StageResult::Done;
            }
            
            self.width *= 2;
            self.idx = max_idx(self.width, input.len());
            return StageResult::Update;
        };

        self.idx -= 1;
        let num_bits = self.width as u8;
        self.restore_val = true;
        unsafe {
            if num_bits < 8 {
                if num_bits >= 1 {
                    input.flip_bit(self.idx);
                }
                if num_bits >= 2 {
                    input.flip_bit(self.idx + 1);
                }
                if num_bits >= 4 {
                    input.flip_bit(self.idx + 2);
                    input.flip_bit(self.idx + 3);
                }
            } else if num_bits == 8 {
                input.flip_byte(self.idx);
            } else if num_bits == 16 {
                input.flip_word(self.idx);
            } else {
                input.flip_dword(self.idx);
            }
        }

        StageResult::WillRestoreInput
    }
}

/** Helper function to see if a particular change (xor_val = old ^ new) could
be a product of deterministic bit flips with the lengths and stepovers
attempted by afl-fuzz. This is used to avoid dupes in some of the
deterministic fuzzing operations that follow bit flips. We also
return 1 if xor_val is zero, which implies that the old and attempted new
values are identical and the exec would be a waste of time. */
pub fn could_be_bitflip(mut xor_val: u32) -> bool {
    let mut sh: u8 = 0;

    if xor_val == 0 {
        return true;
    }
    /* Shift left until first bit set. */
    while (xor_val & 1) == 0 {
        sh += 1;
        xor_val >>= 1;
    }
    /* 1-, 2-, and 4-bit patterns are OK anywhere. */
    if xor_val == 1 || xor_val == 3 || xor_val == 15 {
        return true;
    }
    /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
    divisible by 8, since that's the stepover for these ops. */
    if sh & 7 != 0 {
        return false;
    }
    if xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff {
        return true;
    }

    false
}
