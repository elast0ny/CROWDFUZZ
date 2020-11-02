use crate::*;

#[derive(Copy, Clone, Debug)]
pub struct InterestState {
    idx: usize,
    prev_val: Option<(usize, u32)>,
    width: u8,
    val_idx: usize,
}
impl InterestState {
    pub fn new(input: &[u8]) -> Self {
        Self {
            idx: input.len(),
            prev_val: None,
            width: 1,
            val_idx: INTERESTING_8.len() - 1,
        }
    }

    pub fn desc(&self, dst: &mut String) {
        dst.push_str("interest ");
        dst.push_str(match self.width {
            1 => "8/8",
            2 => "16/8",
            _ => "32/8",
        });
    }

    pub fn total_cycles(&self, input: &[u8]) -> usize {
        let mut total = 0;
        let mut i = 1;
        loop {
            let max_idx = input.len() - (i - 1) as usize;

            total += max_idx * if i == 1 {
                INTERESTING_8.len()
            } else if i == 2 {
                INTERESTING_16.len()
            } else {
                INTERESTING_32.len()
            };

            i *= 2;
            if i > 4 {
                break;
            }
        }
        total
    }

    pub fn mutate(&mut self, mut input: &mut [u8]) -> StageResult {
        // Restore the orig input
        if let Some((idx, orig_val)) = self.prev_val.take() {
            unsafe {
                match self.width {
                    1 => {
                        input.set_byte(idx, orig_val as _);
                    }
                    2 => {
                        input.set_word(idx, orig_val as _);
                    }
                    _ => {
                        input.set_dword(idx, orig_val);
                    }
                };
            }
        }

        loop {
            // If we have reached the end of the buffer
            if self.idx == 0 {
                // If done all interesting values
                if self.val_idx == 0 {
                    if self.width == 4 {
                        // Last stage is Interest(u32)
                        return StageResult::Done;
                    } else {
                        // Move to next width
                        self.width *= 2;
                    }
                    // Reset intersting value index
                    self.val_idx = if self.width == 2 {
                        INTERESTING_16.len() - 1
                    } else {
                        INTERESTING_32.len() - 1
                    };
                    self.idx = input.len() - (self.width - 1) as usize;
                    return StageResult::Update;
                }
                
                self.idx = input.len() - (self.width - 1) as usize;
                self.val_idx -= 1;
                continue;
            }

            self.idx -= 1;

            let orig = unsafe {
                match self.width {
                    1 => input.set_byte(self.idx, *INTERESTING_8.get_unchecked(self.val_idx)) as _,
                    2 => input.set_word(self.idx, *INTERESTING_16.get_unchecked(self.val_idx)) as _,
                    _ => input.set_dword(self.idx, *INTERESTING_32.get_unchecked(self.val_idx)),
                }
            };

            self.prev_val = Some((self.idx, orig));

            break;
        }

        
        

        StageResult::WillRestoreInput
    }
}

/* Last but not least, a similar helper to see if insertion of an
interesting integer is redundant given the insertions done for
shorter blen. The last param (check_le) is set if the caller
already executed LE insertion for current blen and wants to see
if BE variant passed in new_val is unique. */

pub fn could_be_interest(old_val: u32, new_val: u32, blen: u8, check_le: bool) -> bool {
    if old_val == new_val {
        return true;
    }
    /* See if one-byte insertions from interesting_8 over old_val could
    produce new_val. */
    for i in 0..blen {
        for j in 0..INTERESTING_8.len() {
            let tval = unsafe {
                (old_val & !(0xff << (i * 8)))
                    | ((*INTERESTING_8.get_unchecked(j) as u32) << (i * 8))
            };

            if new_val == tval {
                return true;
            }
        }
    }
    /* Bail out unless we're also asked to examine two-byte LE insertions
    as a preparation for BE attempts. */
    if blen == 2 && !check_le {
        return false;
    }
    /* See if two-byte insertions over old_val could give us new_val. */

    for i in 0..blen - 1 {
        for j in 0..INTERESTING_16.len() {
            let mut tval = unsafe {
                (old_val & !(0xFFFF << (i * 8)))
                    | ((*INTERESTING_16.get_unchecked(j) as u32) << (i * 8))
            };
            if new_val == tval {
                return true;
            }
            /* Continue here only if blen > 2. */
            if blen > 2 {
                tval = unsafe {
                    (old_val & !(0xffff << (i * 8)))
                        | ((swap_16(*INTERESTING_16.get_unchecked(j) as u16) as u32) << (i * 8))
                };
                if new_val == tval {
                    return true;
                }
            }
        }
    }
    if blen == 4 && check_le {
        /* See if four-byte insertions could produce the same result
        (LE only). */

        for j in 0..INTERESTING_32.len() {
            if new_val == unsafe { *INTERESTING_32.get_unchecked(j) } as u32 {
                return true;
            }
        }
    }
    false
}

pub const INTERESTING_8: &[u8] = &[
    0,   /*                                         */
    1,   /*                                         */
    16,  /* One-off with common buffer size         */
    32,  /* One-off with common buffer size         */
    64,  /* One-off with common buffer size         */
    100, /* One-off with common buffer size         */
    127, /*                                         */
    128, /* Overflow signed 8-bit when decremented  */
    255, /* u8::MAX                                 */
];
pub const INTERESTING_16: &[u16] = &[
    0, 1, 16, 32, 64, 100, 127, 128, 128, 255,   /* Overflow signed 8-bit                   */
    256,   /* Overflow unsig 8-bit                    */
    512,   /* One-off with common buffer size         */
    1000,  /* One-off with common buffer size         */
    1024,  /* One-off with common buffer size         */
    4096,  /* One-off with common buffer size         */
    32767, /* Overflow signed 16-bit when incremented */
    32768, /* Overflow signed 16-bit when decremented */
    65407, /* Overflow signed 8-bit                   */
    65535, /* u16::MAX                                */
];
pub const INTERESTING_32: &[u32] = &[
    0, 1, 16, 32, 64, 100, 127, 128, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65407,
    65535, 65536,      /* Overflow unsig 16 bit                   */
    100663045,  /* Large positive number (endian-agnostic) */
    2147483647, /* Overflow signed 32-bit when incremented */
    2147483648, /* Overflow signed 32-bit when decremented */
    4194304250, /* Large negative number (endian-agnostic) */
    4294934527, /* Overflow signed 16-bit                  */
    4294967295, /* u32::MAX                                */
];
