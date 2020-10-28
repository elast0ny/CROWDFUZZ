use crate::*;

#[derive(Clone, Copy, Debug)]
enum InterestStage {
    Width8(i8, usize),
    Width16(i16, usize),
    Width32(i32, usize),
}
impl Default for InterestStage {
    fn default() -> Self {
        Self::Width8(INTERESTING_8[0], 0)
    }
}
impl InterestStage {
    pub fn max_idx(&self, input_len: usize) -> usize {
        match self {
            Self::Width8(_, _) => input_len,
            Self::Width16(_, _) => input_len - 1,
            Self::Width32(_, _) => input_len - 3,
        }
    }

    pub fn next(&mut self) -> GenericStage<Self> {
        unsafe {
            match self {
                Self::Width8(ref mut val, ref mut idx) => {
                    if *idx + 1 == INTERESTING_8.len() {
                        GenericStage::Next(Self::Width16(INTERESTING_16[0], 0))
                    } else {
                        *idx += 1;
                        *val = *INTERESTING_8.get_unchecked(*idx);
                        GenericStage::Updated
                    }
                }
                Self::Width16(ref mut val, ref mut idx) => {
                    if *idx + 1 == INTERESTING_16.len() {
                        GenericStage::Next(Self::Width32(INTERESTING_32[0], 0))
                    } else {
                        *idx += 1;
                        *val = *INTERESTING_16.get_unchecked(*idx);
                        GenericStage::Updated
                    }
                }
                Self::Width32(ref mut val, ref mut idx) => {
                    if *idx + 1 == INTERESTING_32.len() {
                        GenericStage::Done
                    } else {
                        *idx += 1;
                        *val = *INTERESTING_32.get_unchecked(*idx);
                        GenericStage::Updated
                    }
                }
            }
        }
    }
}

pub struct InterestState {
    idx: usize,
    stage: InterestStage,
}
impl InterestState {
    pub fn new(input_len: usize) -> Self {
        Self {
            idx: input_len,
            stage: InterestStage::default(),
        }
    }
}

pub fn interesting(bytes: &mut [u8], s: &mut InterestState) -> (bool, bool) {
    loop {
        if s.idx == 0 {
            match s.stage.next() {
                GenericStage::Updated => {}
                GenericStage::Next(v) => {
                    s.idx = v.max_idx(bytes.len());
                    s.stage = v;
                }
                GenericStage::Done => return (true, false),
            };
        }

        s.idx -= 1;

        unsafe {
            let dst = bytes.as_mut_ptr().add(s.idx);
            let orig: u32;

            match s.stage {
                InterestStage::Width8(j, _) => {
                    orig = *dst as u32;
                    if could_be_bitflip(orig ^ j as u32) || could_be_arith(orig, j as u32, 1) {
                        continue;
                    }
                    *(dst as *mut i8) = j;
                }
                InterestStage::Width16(j, _) => {
                    orig = *(dst as *mut u16) as u32;
                    if could_be_bitflip(orig ^ j as u32)
                        || could_be_arith(orig, j as u32, 2)
                        || could_be_interest(orig, j as _, 2, false)
                    {
                        continue;
                    }
                    *(dst as *mut i16) = j;
                }
                InterestStage::Width32(j, _) => {
                    orig = *(dst as *mut u32);
                    if could_be_bitflip(orig ^ j as u32)
                        || could_be_arith(orig, j as u32, 4)
                        || could_be_interest(orig, j as _, 4, false)
                    {
                        continue;
                    }
                    *(dst as *mut i32) = j;
                }
            };
        }

        break;
    }
    (false, true)
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

pub const INTERESTING_8: &[i8] = &[
    -128, /* Overflow signed 8-bit when decremented  */
    -1,   /*                                         */
    0,    /*                                         */
    1,    /*                                         */
    16,   /* One-off with common buffer size         */
    32,   /* One-off with common buffer size         */
    64,   /* One-off with common buffer size         */
    100,  /* One-off with common buffer size         */
    127,
];
pub const INTERESTING_16: &[i16] = &[
    -128, -1, 0, 1, 16, 32, 64, 100, 127,
    -32768, /* Overflow signed 16-bit when decremented */
    -129,   /* Overflow signed 8-bit                   */
    128,    /* Overflow signed 8-bit                   */
    255,    /* Overflow unsig 8-bit when incremented   */
    256,    /* Overflow unsig 8-bit                    */
    512,    /* One-off with common buffer size         */
    1000,   /* One-off with common buffer size         */
    1024,   /* One-off with common buffer size         */
    4096,   /* One-off with common buffer size         */
    32767,  /* Overflow signed 16-bit when incremented */
];
pub const INTERESTING_32: &[i32] = &[
    -128,
    -1,
    0,
    1,
    16,
    32,
    64,
    100,
    127,
    -32768,
    -129,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767,
    -2147483648, /* Overflow signed 32-bit when decremented */
    -100663046,  /* Large negative number (endian-agnostic) */
    -32769,      /* Overflow signed 16-bit                  */
    32768,       /* Overflow signed 16-bit                  */
    65535,       /* Overflow unsig 16-bit when incremented  */
    65536,       /* Overflow unsig 16 bit                   */
    100663045,   /* Large positive number (endian-agnostic) */
    2147483647,  /* Overflow signed 32-bit when incremented */
];
