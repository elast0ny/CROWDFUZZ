use crate::*;

#[derive(Clone, Copy, Debug)]
enum BitWidth {
    Bit1 = 1,
    Bit2 = 2,
    Bit4 = 4,
    Byte1 = 8,
    Byte2 = 16,
    Byte4 = 32,
}
impl Default for BitWidth {
    fn default() -> Self {
        Self::Bit1
    }
}
impl BitWidth {
    pub fn max_idx_for_input(&self, bytes: &[u8]) -> usize {
        if (*self as u8) < 8 {
            (bytes.len() * 8) - ((*self as u8) - 1) as usize
        } else {
            bytes.len() - (((*self as u8) / 8) - 1) as usize
        }
    }

    pub fn next(self) -> Option<Self> {
        match self {
            Self::Bit1 => Some(Self::Bit2),
            Self::Bit2 => Some(Self::Bit4),
            Self::Bit4 => Some(Self::Byte1),
            Self::Byte1 => Some(Self::Byte2),
            Self::Byte2 => Some(Self::Byte4),
            Self::Byte4 => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BitFlipState {
    idx: usize,
    width: BitWidth,
}
impl BitFlipState {
    pub fn from_input(bytes: &[u8]) -> Self {
        let width = BitWidth::default();
        Self {
            idx: width.max_idx_for_input(bytes),
            width,
        }
    }
}

/// Flips bits in the input starting from the end
/// # Safety
/// <why unsafe ?>
pub fn bit_flip(bytes: &mut [u8], s: &mut BitFlipState) -> (bool, bool) {
    if s.idx == 0 {
        // Go to the next width
        s.width = match s.width.next() {
            Some(w) => {
                s.idx = w.max_idx_for_input(bytes);
                w
            }
            None => return (true, false),
        }
    };

    s.idx -= 1;
    let num_bits = s.width as u8;

    unsafe {
        if num_bits < 8 {
            if num_bits >= 1 {
                flip_bit(bytes, s.idx);
            }
            if num_bits >= 2 {
                flip_bit(bytes, s.idx + 1);
            }
            if num_bits >= 4 {
                flip_bit(bytes, s.idx + 2);
                flip_bit(bytes, s.idx + 3);
            }
        } else if num_bits == 8 {
            *bytes.get_unchecked_mut(s.idx) ^= 0xFF;
        } else if num_bits == 16 {
            *((bytes.as_mut_ptr().add(s.idx)) as *mut u16) ^= 0xFFFF;
        } else {
            *((bytes.as_mut_ptr().add(s.idx)) as *mut u32) ^= 0xFFFFFFFF;
        }
    }
    s.idx -= 1;

    (false, true)
}

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
